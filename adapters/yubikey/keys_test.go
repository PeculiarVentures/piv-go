package yubikey

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"math/big"
	"strings"
	"testing"

	"github.com/PeculiarVentures/piv-go/adapters"
	"github.com/PeculiarVentures/piv-go/adapters/admin"
	internalutil "github.com/PeculiarVentures/piv-go/internal"
	"github.com/PeculiarVentures/piv-go/internal/testtrace"
	"github.com/PeculiarVentures/piv-go/iso7816"
	"github.com/PeculiarVentures/piv-go/piv"

	"github.com/PeculiarVentures/piv-go/emulator"
)

var yubiKeyTestChallenge = []byte{0x10, 0x32, 0x54, 0x76, 0x98, 0xBA, 0xDC, 0xFE}

func newYubiKeyPolicySession(mock *emulator.Card) *adapters.Session {
	return &adapters.Session{
		Client:              piv.NewClient(mock),
		ReaderName:          "Yubico YubiKey OTP+FIDO+CCID",
		ManagementAlgorithm: piv.Alg3DES,
		ManagementKey:       append([]byte(nil), defaultManagementKey...),
	}
}

func enqueueManagementAuth(mock *emulator.Card) {
	challengeResp := iso7816.EncodeTLV(0x7C, iso7816.EncodeTLV(0x81, yubiKeyTestChallenge))
	mock.EnqueueResponse(0x87, challengeResp, uint16(iso7816.SwSuccess))
	mock.EnqueueResponse(0x87, nil, uint16(iso7816.SwSuccess))
}

func yubiKeyTestPoint(t *testing.T) []byte {
	t.Helper()
	return internalutil.MustEncodeUncompressedPoint(elliptic.P256(), elliptic.P256().Params().Gx, elliptic.P256().Params().Gy)
}

func findCommand(mock *emulator.Card, ins byte) []byte {
	for _, command := range mock.TransmittedCommands {
		if len(command) > 1 && command[1] == ins {
			return command
		}
	}
	return nil
}

func TestYubiKeyAdapterGenerateKeyWithPolicies(t *testing.T) {
	tests := []struct {
		name        string
		pinPolicy   byte
		touchPolicy byte
		wantAA      bool
		wantAB      bool
	}{
		{name: "default policies omit tags", pinPolicy: 0x00, touchPolicy: 0x00},
		{name: "pin once", pinPolicy: 0x02, touchPolicy: 0x00, wantAA: true},
		{name: "touch cached", pinPolicy: 0x00, touchPolicy: 0x03, wantAB: true},
		{name: "pin always touch always", pinPolicy: 0x03, touchPolicy: 0x02, wantAA: true, wantAB: true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			point := yubiKeyTestPoint(t)
			mock := emulator.NewCard()
			enqueueManagementAuth(mock)
			mock.SetSuccessResponse(0x47, iso7816.EncodeTLV(0x7F49, iso7816.EncodeTLV(0x86, point)))
			mock.SetSuccessResponse(0xDB, nil)

			publicKey, err := NewAdapter().GenerateKey(newYubiKeyPolicySession(mock), piv.SlotSignature, piv.AlgECCP256, test.pinPolicy, test.touchPolicy)
			if err != nil {
				t.Fatalf("GenerateKey() error = %v", err)
			}
			if _, ok := publicKey.(*ecdsa.PublicKey); !ok {
				t.Fatalf("expected ECDSA public key, got %T", publicKey)
			}

			generateCmd := findCommand(mock, 0x47)
			if generateCmd == nil {
				t.Fatal("expected GENERATE ASYMMETRIC KEY PAIR command")
			}
			parsed, err := iso7816.ParseCommand(generateCmd)
			if err != nil {
				t.Fatalf("parse generate command: %v", err)
			}
			if parsed.P1 != 0x00 || parsed.P2 != byte(piv.SlotSignature) {
				t.Fatalf("unexpected generate header: %X", generateCmd[:4])
			}
			outer, err := iso7816.ParseAllTLV(parsed.Data)
			if err != nil {
				t.Fatalf("parse outer template: %v", err)
			}
			ac := iso7816.FindTag(outer, 0xAC)
			if ac == nil {
				t.Fatalf("control reference 0xAC not found in %X", parsed.Data)
			}
			inner, err := iso7816.ParseAllTLV(ac.Value)
			if err != nil {
				t.Fatalf("parse control reference: %v", err)
			}
			algorithm := iso7816.FindTag(inner, 0x80)
			if algorithm == nil || !bytes.Equal(algorithm.Value, []byte{piv.AlgECCP256}) {
				t.Fatalf("algorithm tag 0x80 missing or wrong in %X", ac.Value)
			}
			pin := iso7816.FindTag(inner, TagPinPolicy)
			if test.wantAA && (pin == nil || len(pin.Value) != 1 || pin.Value[0] != test.pinPolicy) {
				t.Fatalf("PIN policy tag 0xAA missing or wrong in %X", ac.Value)
			}
			if !test.wantAA && pin != nil {
				t.Fatalf("PIN policy tag 0xAA must be omitted, got %X", ac.Value)
			}
			touch := iso7816.FindTag(inner, TagTouchPolicy)
			if test.wantAB && (touch == nil || len(touch.Value) != 1 || touch.Value[0] != test.touchPolicy) {
				t.Fatalf("touch policy tag 0xAB missing or wrong in %X", ac.Value)
			}
			if !test.wantAB && touch != nil {
				t.Fatalf("touch policy tag 0xAB must be omitted, got %X", ac.Value)
			}

			if findCommand(mock, 0xDB) == nil {
				t.Fatal("expected PUT DATA storing the generated public key")
			}
		})
	}
}

func TestYubiKeyAdapterGenerateKeyMatchesTrace(t *testing.T) {
	point := yubiKeyTestPoint(t)
	mock := emulator.NewCard()
	enqueueManagementAuth(mock)
	mock.SetSuccessResponse(0x47, iso7816.EncodeTLV(0x7F49, iso7816.EncodeTLV(0x86, point)))
	mock.SetSuccessResponse(0xDB, nil)

	if _, err := NewAdapter().GenerateKey(newYubiKeyPolicySession(mock), piv.SlotSignature, piv.AlgECCP256, 0x02, 0x03); err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}
	testtrace.RequireMatchFile(t, "testdata/generate_with_policies_apdu_trace.txt", mock.APDULog())
}

func TestYubiKeyAdapterGenerateKeyRejectsUnsupportedPolicies(t *testing.T) {
	mock := emulator.NewCard()
	if _, err := NewAdapter().GenerateKey(newYubiKeyPolicySession(mock), piv.SlotSignature, piv.AlgECCP256, 0x04, 0x00); err == nil {
		t.Fatal("expected unsupported PIN policy error")
	}
}

func fixedScalarP256Key() *ecdsa.PrivateKey {
	curve := elliptic.P256()
	x, y := curve.ScalarBaseMult(big.NewInt(1).Bytes())
	return &ecdsa.PrivateKey{D: big.NewInt(1), PublicKey: ecdsa.PublicKey{Curve: curve, X: x, Y: y}}
}

func TestYubiKeyAdapterImportKeyMatchesTrace(t *testing.T) {
	mock := emulator.NewCard()
	enqueueManagementAuth(mock)
	mock.SetSuccessResponse(InsImportKey, nil)

	if err := NewAdapter().ImportKey(newYubiKeyPolicySession(mock), piv.SlotSignature, piv.AlgECCP256, fixedScalarP256Key(), 0x01, 0x02); err != nil {
		t.Fatalf("ImportKey() error = %v", err)
	}

	importCmd := findCommand(mock, InsImportKey)
	if importCmd == nil {
		t.Fatal("expected IMPORT KEY command")
	}
	if importCmd[2] != piv.AlgECCP256 || importCmd[3] != byte(piv.SlotSignature) {
		t.Fatalf("unexpected IMPORT KEY header: %X", importCmd[:4])
	}
	testtrace.RequireMatchFile(t, "testdata/import_key_apdu_trace.txt", mock.APDULog())
}

func TestYubiKeyAdapterImportKeyRejectsUnsupportedKey(t *testing.T) {
	mock := emulator.NewCard()
	enqueueManagementAuth(mock)
	err := NewAdapter().ImportKey(newYubiKeyPolicySession(mock), piv.SlotSignature, piv.AlgECCP256, "not-a-key", 0x00, 0x00)
	if err == nil || !strings.Contains(err.Error(), "unsupported") {
		t.Fatalf("expected unsupported key error, got %v", err)
	}
	if findCommand(mock, InsImportKey) != nil {
		t.Fatal("no IMPORT KEY APDU must be sent on validation failure")
	}
}

func TestYubiKeyAdapterVersionMatchesTrace(t *testing.T) {
	mock := emulator.NewCard()
	mock.SetSuccessResponse(0xFD, []byte{0x05, 0x07, 0x00})

	session := &adapters.Session{Client: piv.NewClient(mock), ReaderName: "Yubico YubiKey OTP+FIDO+CCID"}
	version, err := NewAdapter().Version(session)
	if err != nil {
		t.Fatalf("Version() error = %v", err)
	}
	if version != "5.7.0" {
		t.Fatalf("unexpected version: %q", version)
	}
	testtrace.RequireMatchFile(t, "testdata/version_apdu_trace.txt", mock.APDULog())
}

func TestYubiKeyAdapterChangeManagementKeyWithTouch(t *testing.T) {
	newKey := []byte{0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38}

	mock := emulator.NewCard()
	enqueueManagementAuth(mock)
	mock.SetSuccessResponse(0xFF, nil)
	enqueueManagementAuth(mock)

	session := newYubiKeyPolicySession(mock)
	if err := NewAdapter().ChangeManagementKeyWithTouch(session, piv.Alg3DES, newKey, true); err != nil {
		t.Fatalf("ChangeManagementKeyWithTouch() error = %v", err)
	}
	setKeyCmd := findCommand(mock, 0xFF)
	if setKeyCmd == nil {
		t.Fatal("expected SET MANAGEMENT KEY command")
	}
	if setKeyCmd[2] != 0xFF || setKeyCmd[3] != 0xFE {
		t.Fatalf("touch rotation must use P2 0xFE, got %X", setKeyCmd[:4])
	}
	testtrace.RequireMatchFile(t, "testdata/set_mgm_touch_apdu_trace.txt", mock.APDULog())
}

func TestYubiKeyAdapterChangeManagementKeyDelegatesWithoutTouch(t *testing.T) {
	newKey := []byte{0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38}

	mock := emulator.NewCard()
	enqueueManagementAuth(mock)
	mock.SetSuccessResponse(0xFF, nil)
	enqueueManagementAuth(mock)

	session := newYubiKeyPolicySession(mock)
	if err := NewAdapter().ChangeManagementKey(session, piv.Alg3DES, newKey); err != nil {
		t.Fatalf("ChangeManagementKey() error = %v", err)
	}
	setKeyCmd := findCommand(mock, 0xFF)
	if setKeyCmd == nil {
		t.Fatal("expected SET MANAGEMENT KEY command")
	}
	if setKeyCmd[2] != 0xFF || setKeyCmd[3] != 0xFF {
		t.Fatalf("default rotation must use P2 0xFF, got %X", setKeyCmd[:4])
	}
}

func TestChangeManagementKeyWithTouchFallsBackWithoutTouch(t *testing.T) {
	mock := emulator.NewCard()
	enqueueManagementAuth(mock)
	mock.SetSuccessResponse(0xFF, nil)
	enqueueManagementAuth(mock)

	session := newYubiKeyPolicySession(mock)
	runtime := adapters.NewRuntime(session, NewAdapter())
	newKey := bytes.Repeat([]byte{0x07}, 24)
	if err := admin.ChangeManagementKeyWithTouch(runtime, piv.Alg3DES, newKey, false); err != nil {
		t.Fatalf("ChangeManagementKeyWithTouch() error = %v", err)
	}
	if setKeyCmd := findCommand(mock, 0xFF); setKeyCmd == nil || setKeyCmd[3] != 0xFF {
		t.Fatalf("fallback rotation must use P2 0xFF, got %X", setKeyCmd)
	}
}
