package yubikey

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"testing"

	"github.com/PeculiarVentures/piv-go/emulator"
	"github.com/PeculiarVentures/piv-go/iso7816"
	"github.com/PeculiarVentures/piv-go/piv"
)

func assertOTPSelectAndPIVRestore(t *testing.T, card *emulator.Card) {
	t.Helper()
	var selections [][]byte
	for _, raw := range card.TransmittedCommands {
		if len(raw) > 1 && raw[1] == 0xA4 {
			selections = append(selections, raw)
		}
	}
	if len(selections) < 2 {
		t.Fatalf("expected OTP SELECT and PIV restoration, got %d selects", len(selections))
	}
	otp, err := iso7816.ParseCommand(selections[len(selections)-2])
	if err != nil {
		t.Fatal(err)
	}
	pivSelect, err := iso7816.ParseCommand(selections[len(selections)-1])
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(otp.Data, otpAID) || bytes.Equal(pivSelect.Data, otpAID) {
		t.Fatalf("wrong SELECT order: OTP %X, PIV %X", otp.Data, pivSelect.Data)
	}
}

func TestP384NEORejectsBeforeManagementAndMutation(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name string
		call func(*Adapter, *emulator.Card) error
	}{
		{"generate", func(adapter *Adapter, card *emulator.Card) error {
			_, err := adapter.GenerateKey(newYubiKeyPolicySession(card), piv.SlotSignature, piv.AlgECCP384, 0, 0)
			return err
		}},
		{"import", func(adapter *Adapter, card *emulator.Card) error {
			return adapter.ImportKey(newYubiKeyPolicySession(card), piv.SlotSignature, piv.AlgECCP384, key, 0, 0)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			card := emulator.NewCard()
			card.SetSuccessResponse(0xA4, nil)
			card.SetSuccessResponse(0x03, []byte{3, 4, 1, 0, 0, 0})
			err := tc.call(NewAdapter(), card)
			if !errors.Is(err, ErrP384Unsupported) {
				t.Fatalf("expected typed NEO P-384 refusal, got %v", err)
			}
			assertOTPSelectAndPIVRestore(t, card)
			for _, raw := range card.TransmittedCommands {
				if len(raw) < 2 || raw[1] != 0xA4 && raw[1] != 0x03 {
					t.Fatalf("preflight sent authentication or mutation APDU: %X", raw)
				}
			}
		})
	}
}

func TestSupportsP384VersionClasses(t *testing.T) {
	for _, tc := range []struct {
		name string
		data []byte
		want bool
	}{
		{"NEO", []byte{3, 4, 1, 0, 0, 0}, false},
		{"preview", []byte{0, 0, 1, 0, 0, 0}, true},
		{"YubiKey4", []byte{4, 2, 8, 0, 0, 0}, true},
		{"YubiKey5", []byte{5, 7, 0, 0, 0, 0}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			card := emulator.NewCard()
			card.SetSuccessResponse(0xA4, nil)
			card.SetSuccessResponse(0x03, tc.data)
			got, err := NewAdapter().SupportsP384(newYubiKeyPolicySession(card))
			if err != nil || got != tc.want {
				t.Fatalf("P-384 support = %v, %v; want %v", got, err, tc.want)
			}
		})
	}
}

func TestSupportsP384UnknownOldGenerationIsIndeterminate(t *testing.T) {
	card := emulator.NewCard()
	card.SetSuccessResponse(0xA4, nil)
	card.SetSuccessResponse(0x03, []byte{2, 1, 0, 0, 0, 0})
	_, err := NewAdapter().SupportsP384(newYubiKeyPolicySession(card))
	if err == nil {
		t.Fatal("unknown old generation must not be labelled NEO")
	}
}

func TestP384FallsBackToCardWhenOTPStatusUnavailable(t *testing.T) {
	card := emulator.NewCard()
	card.SetSuccessResponse(0xA4, nil)
	card.SetResponse(0x03, nil, uint16(iso7816.SwInsNotSupported))
	enqueueManagementAuth(card)
	card.SetResponse(0x47, nil, uint16(iso7816.SwWrongData))
	_, err := NewAdapter().GenerateKey(newYubiKeyPolicySession(card), piv.SlotSignature, piv.AlgECCP384, 0, 0)
	if !iso7816.IsStatus(err, iso7816.SwWrongData) || findCommand(card, 0x47) == nil {
		t.Fatalf("unavailable OTP status must let GENERATE decide, got %v", err)
	}
}

func TestP384PreviewContinuesToCard(t *testing.T) {
	card := emulator.NewCard()
	card.SetSuccessResponse(0xA4, nil)
	card.SetSuccessResponse(0x03, []byte{0, 0, 1, 0, 0, 0})
	enqueueManagementAuth(card)
	card.SetResponse(0x47, nil, uint16(iso7816.SwWrongData))
	_, err := NewAdapter().GenerateKey(newYubiKeyPolicySession(card), piv.SlotSignature, piv.AlgECCP384, 0, 0)
	if !iso7816.IsStatus(err, iso7816.SwWrongData) || findCommand(card, 0x47) == nil {
		t.Fatalf("preview status must let GENERATE decide, got %v", err)
	}
}

func TestP384StopsOnPIVRestoreFailure(t *testing.T) {
	card := emulator.NewCard()
	card.EnqueueResponse(0xA4, nil, uint16(iso7816.SwSuccess))
	card.EnqueueResponse(0xA4, nil, uint16(iso7816.SwFileNotFound))
	card.SetSuccessResponse(0x03, []byte{5, 7, 0, 0, 0, 0})
	_, err := NewAdapter().GenerateKey(newYubiKeyPolicySession(card), piv.SlotSignature, piv.AlgECCP384, 0, 0)
	if !errors.Is(err, ErrPIVRestore) {
		t.Fatalf("expected PIV restore error, got %v", err)
	}
	for _, raw := range card.TransmittedCommands {
		if len(raw) > 1 && (raw[1] == 0x87 || raw[1] == 0x47) {
			t.Fatalf("must not authenticate or mutate with unknown applet: %X", raw)
		}
	}
}

func TestSerialNumberFallsBackToOTPAndRestoresPIV(t *testing.T) {
	card := emulator.NewCard()
	card.SetSuccessResponse(0xA4, nil)
	card.SetResponse(0xF8, nil, uint16(iso7816.SwInsNotSupported))
	card.SetSuccessResponse(0x01, []byte{0x00, 0x4f, 0xf7, 0x60})
	serial, err := NewAdapter().SerialNumber(newYubiKeyPolicySession(card))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(serial, []byte{0x00, 0x4f, 0xf7, 0x60}) {
		t.Fatalf("serial = %X", serial)
	}
	assertOTPSelectAndPIVRestore(t, card)
}

func TestSerialNumberReportsTypedOTPFailureAndRestoresPIV(t *testing.T) {
	card := emulator.NewCard()
	card.SetSuccessResponse(0xA4, nil)
	card.SetResponse(0xF8, nil, uint16(iso7816.SwInsNotSupported))
	card.SetResponse(0x01, nil, uint16(iso7816.SwInsNotSupported))
	_, err := NewAdapter().SerialNumber(newYubiKeyPolicySession(card))
	if !errors.Is(err, ErrSerialNumberUnavailable) || !errors.Is(err, ErrOTPApplet) {
		t.Fatalf("expected typed serial and OTP failures, got %v", err)
	}
	var otpErr *OTPAppletError
	if !errors.As(err, &otpErr) || otpErr.Step != "read serial" {
		t.Fatalf("expected OTP read failure, got %v", err)
	}
	assertOTPSelectAndPIVRestore(t, card)
}

func TestSerialNumberMalformedPIVValueFallsBackToOTP(t *testing.T) {
	card := emulator.NewCard()
	card.SetSuccessResponse(0xA4, nil)
	card.SetSuccessResponse(0xF8, []byte{0x01, 0x02})
	card.SetSuccessResponse(0x01, []byte{0x00, 0x4f, 0xf7, 0x60})
	serial, err := NewAdapter().SerialNumber(newYubiKeyPolicySession(card))
	if err != nil || !bytes.Equal(serial, []byte{0x00, 0x4f, 0xf7, 0x60}) {
		t.Fatalf("OTP serial fallback = %X, %v", serial, err)
	}
	assertOTPSelectAndPIVRestore(t, card)
}

func TestOTPStatusVersionRestoresPIVAndGatesDeleteKey(t *testing.T) {
	card := emulator.NewCard()
	card.SetSuccessResponse(0xA4, nil)
	card.SetSuccessResponse(0x03, []byte{3, 4, 1, 0, 0, 0})
	session := newYubiKeyPolicySession(card)
	version, err := NewAdapter().OTPStatusVersion(session)
	if err != nil || version != "3.4.1" {
		t.Fatalf("OTP status = %q, %v", version, err)
	}
	assertOTPSelectAndPIVRestore(t, card)
	if supported, err := NewAdapter().SupportsDeleteKey(session); err != nil || supported {
		t.Fatalf("NEO delete support = %v, %v", supported, err)
	}
	err = NewAdapter().DeleteKey(session, piv.SlotSignature)
	if !errors.Is(err, ErrKeyDeletionUnsupported) {
		t.Fatalf("expected unsupported delete, got %v", err)
	}
	for _, raw := range card.TransmittedCommands {
		if len(raw) > 1 && (raw[1] == 0xF6 || raw[1] == 0x87) {
			t.Fatalf("old token must reject before management auth or MOVE KEY: %X", raw)
		}
	}
}

func TestOTPStatusVersionRestoreFailureDiscardsData(t *testing.T) {
	card := emulator.NewCard()
	card.EnqueueResponse(0xA4, nil, uint16(iso7816.SwSuccess))
	card.EnqueueResponse(0xA4, nil, uint16(iso7816.SwFileNotFound))
	card.SetSuccessResponse(0x03, []byte{3, 4, 1, 0, 0, 0})
	version, err := NewAdapter().OTPStatusVersion(newYubiKeyPolicySession(card))
	if version != "" || !errors.Is(err, ErrOTPApplet) || !errors.Is(err, ErrPIVRestore) || !iso7816.IsStatus(err, iso7816.SwFileNotFound) {
		t.Fatalf("restore failure must discard version and preserve status, got %q, %v", version, err)
	}
}

func TestDeleteKeyStopsWhenPIVRestoreFails(t *testing.T) {
	card := emulator.NewCard()
	card.EnqueueResponse(0xA4, nil, uint16(iso7816.SwSuccess))
	card.EnqueueResponse(0xA4, nil, uint16(iso7816.SwFileNotFound))
	card.SetSuccessResponse(0x03, []byte{5, 7, 0, 0, 0, 0})
	err := NewAdapter().DeleteKey(newYubiKeyPolicySession(card), piv.SlotSignature)
	if !errors.Is(err, ErrPIVRestore) {
		t.Fatalf("expected PIV restore failure, got %v", err)
	}
	for _, raw := range card.TransmittedCommands {
		if len(raw) > 1 && (raw[1] == 0xF6 || raw[1] == 0x87) {
			t.Fatalf("must not authenticate or delete with unknown applet state: %X", raw)
		}
	}
}

func TestSupportsDeleteKeyAtFirmwareBoundary(t *testing.T) {
	for _, tc := range []struct {
		version string
		want    bool
	}{
		{"3.4.1", false}, {"5.6.9", false}, {"5.7.0", true}, {"6.0.0", true},
	} {
		got, err := supportsDeleteKeyVersion(tc.version)
		if err != nil || got != tc.want {
			t.Fatalf("version %s: support = %v, %v; want %v", tc.version, got, err, tc.want)
		}
	}
}
