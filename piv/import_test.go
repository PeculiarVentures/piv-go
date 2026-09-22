package piv

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"math/big"
	"strings"
	"testing"

	internalutil "github.com/PeculiarVentures/piv-go/internal"
	"github.com/PeculiarVentures/piv-go/iso7816"

	"github.com/PeculiarVentures/piv-go/emulator"
)

func TestClient_GenerateKeyPairWithPolicies_DefaultOmitsPolicyTags(t *testing.T) {
	point := internalutil.MustEncodeUncompressedPoint(elliptic.P256(), elliptic.P256().Params().Gx, elliptic.P256().Params().Gy)
	publicKeyResp := iso7816.EncodeTLV(0x7F49, iso7816.EncodeTLV(0x86, point))

	legacy := emulator.NewCard()
	legacy.SetSuccessResponse(0x47, publicKeyResp)
	if _, err := NewClient(legacy).GenerateKeyPair(SlotAuthentication, AlgECCP256); err != nil {
		t.Fatalf("GenerateKeyPair() error = %v", err)
	}

	withPolicies := emulator.NewCard()
	withPolicies.SetSuccessResponse(0x47, publicKeyResp)
	if _, err := NewClient(withPolicies).GenerateKeyPairWithPolicies(SlotAuthentication, AlgECCP256, PinPolicyDefault, TouchPolicyDefault); err != nil {
		t.Fatalf("GenerateKeyPairWithPolicies() error = %v", err)
	}

	if len(legacy.TransmittedCommands) != 1 || len(withPolicies.TransmittedCommands) != 1 {
		t.Fatalf("expected 1 command each, got %d and %d", len(legacy.TransmittedCommands), len(withPolicies.TransmittedCommands))
	}
	if !bytes.Equal(legacy.TransmittedCommands[0], withPolicies.TransmittedCommands[0]) {
		t.Fatalf("default policies must be byte-for-byte identical:\nlegacy %X\npolicies %X", legacy.TransmittedCommands[0], withPolicies.TransmittedCommands[0])
	}
}

func TestClient_GenerateKeyPairWithPolicies_EmitsPolicyTags(t *testing.T) {
	tests := []struct {
		name        string
		pinPolicy   byte
		touchPolicy byte
		wantAC      []byte
	}{
		{
			name:        "pin once",
			pinPolicy:   PinPolicyOnce,
			touchPolicy: TouchPolicyDefault,
			wantAC:      append(iso7816.EncodeTLV(0x80, []byte{AlgECCP256}), iso7816.EncodeTLV(0xAA, []byte{0x02})...),
		},
		{
			name:        "touch cached",
			pinPolicy:   PinPolicyDefault,
			touchPolicy: TouchPolicyCached,
			wantAC:      append(iso7816.EncodeTLV(0x80, []byte{AlgECCP256}), iso7816.EncodeTLV(0xAB, []byte{0x03})...),
		},
		{
			name:        "pin always touch always",
			pinPolicy:   PinPolicyAlways,
			touchPolicy: TouchPolicyAlways,
			wantAC: func() []byte {
				data := iso7816.EncodeTLV(0x80, []byte{AlgECCP256})
				data = append(data, iso7816.EncodeTLV(0xAA, []byte{0x03})...)
				return append(data, iso7816.EncodeTLV(0xAB, []byte{0x02})...)
			}(),
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			point := internalutil.MustEncodeUncompressedPoint(elliptic.P256(), elliptic.P256().Params().Gx, elliptic.P256().Params().Gy)
			mock := emulator.NewCard()
			mock.SetSuccessResponse(0x47, iso7816.EncodeTLV(0x7F49, iso7816.EncodeTLV(0x86, point)))

			if _, err := NewClient(mock).GenerateKeyPairWithPolicies(SlotSignature, AlgECCP256, test.pinPolicy, test.touchPolicy); err != nil {
				t.Fatalf("GenerateKeyPairWithPolicies() error = %v", err)
			}
			if len(mock.TransmittedCommands) != 1 {
				t.Fatalf("expected 1 command, got %d", len(mock.TransmittedCommands))
			}
			want := &iso7816.Command{Cla: 0x00, Ins: 0x47, P1: 0x00, P2: byte(SlotSignature), Data: iso7816.EncodeTLV(0xAC, test.wantAC), Le: 256}
			if !bytes.Equal(mock.TransmittedCommands[0], want.Bytes()) {
				t.Fatalf("unexpected command:\n got %X\nwant %X", mock.TransmittedCommands[0], want.Bytes())
			}
		})
	}
}

func TestClient_GenerateKeyPairWithPolicies_RejectsUnsupportedPolicies(t *testing.T) {
	for _, value := range []byte{0x04, 0x05, 0xFF} {
		mock := emulator.NewCard()
		if _, err := NewClient(mock).GenerateKeyPairWithPolicies(SlotAuthentication, AlgECCP256, value, TouchPolicyDefault); err == nil || !strings.Contains(err.Error(), "unsupported") {
			t.Fatalf("pin policy 0x%02X: expected unsupported error, got %v", value, err)
		}
		if _, err := NewClient(mock).GenerateKeyPairWithPolicies(SlotAuthentication, AlgECCP256, PinPolicyDefault, value); err == nil || !strings.Contains(err.Error(), "unsupported") {
			t.Fatalf("touch policy 0x%02X: expected unsupported error, got %v", value, err)
		}
		if len(mock.TransmittedCommands) != 0 {
			t.Fatalf("no APDU must be sent for unsupported policies, got %d commands", len(mock.TransmittedCommands))
		}
	}
}

func TestClient_ImportKey_ECDSAP256(t *testing.T) {
	curve := elliptic.P256()
	x, y := curve.ScalarBaseMult(big.NewInt(1).Bytes())
	privateKey := &ecdsa.PrivateKey{D: big.NewInt(1), PublicKey: ecdsa.PublicKey{Curve: curve, X: x, Y: y}}

	mock := emulator.NewCard()
	mock.SetSuccessResponse(InsImportKey, nil)
	if err := NewClient(mock).ImportKey(SlotSignature, AlgECCP256, privateKey, PinPolicyOnce, TouchPolicyAlways); err != nil {
		t.Fatalf("ImportKey() error = %v", err)
	}
	if len(mock.TransmittedCommands) != 1 {
		t.Fatalf("expected 1 command, got %d", len(mock.TransmittedCommands))
	}
	scalar := make([]byte, 32)
	scalar[31] = 0x01
	data := iso7816.EncodeTLV(0x06, scalar)
	data = append(data, iso7816.EncodeTLV(TagPinPolicy, []byte{0x02})...)
	data = append(data, iso7816.EncodeTLV(TagTouchPolicy, []byte{0x02})...)
	want := &iso7816.Command{Cla: 0x00, Ins: 0xFE, P1: AlgECCP256, P2: byte(SlotSignature), Data: data, Le: -1}
	if !bytes.Equal(mock.TransmittedCommands[0], want.Bytes()) {
		t.Fatalf("unexpected command:\n got %X\nwant %X", mock.TransmittedCommands[0], want.Bytes())
	}
}

func TestClient_ImportKey_DefaultPoliciesOmitTags(t *testing.T) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	mock := emulator.NewCard()
	mock.SetSuccessResponse(InsImportKey, nil)
	if err := NewClient(mock).ImportKey(SlotAuthentication, AlgECCP256, privateKey, PinPolicyDefault, TouchPolicyDefault); err != nil {
		t.Fatalf("ImportKey() error = %v", err)
	}
	command, err := iso7816.ParseCommand(mock.TransmittedCommands[0])
	if err != nil {
		t.Fatalf("parse command: %v", err)
	}
	tlvs, err := iso7816.ParseAllTLV(command.Data)
	if err != nil {
		t.Fatalf("parse payload: %v", err)
	}
	if iso7816.FindTag(tlvs, TagPinPolicy) != nil || iso7816.FindTag(tlvs, TagTouchPolicy) != nil {
		t.Fatalf("default policies must omit AA/AB tags, got %X", command.Data)
	}
}

func TestClient_ImportKey_RSA2048(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	mock := emulator.NewCard()
	mock.SetSuccessResponse(InsImportKey, nil)
	if err := NewClient(mock).ImportKey(SlotKeyManagement, AlgRSA2048, privateKey, PinPolicyDefault, TouchPolicyDefault); err != nil {
		t.Fatalf("ImportKey() error = %v", err)
	}
	command, err := iso7816.ParseCommand(mock.TransmittedCommands[0])
	if err != nil {
		t.Fatalf("parse command: %v", err)
	}
	if command.Ins != 0xFE || command.P1 != AlgRSA2048 || command.P2 != byte(SlotKeyManagement) {
		t.Fatalf("unexpected header: %X", mock.TransmittedCommands[0][:4])
	}
	tlvs, err := iso7816.ParseAllTLV(command.Data)
	if err != nil {
		t.Fatalf("parse payload: %v", err)
	}
	for _, tag := range []uint{0x01, 0x02, 0x03, 0x04, 0x05} {
		field := iso7816.FindTag(tlvs, tag)
		if field == nil {
			t.Fatalf("expected RSA component tag 0x%02X", tag)
		}
		if len(field.Value) != 128 {
			t.Fatalf("tag 0x%02X: expected 128 bytes, got %d", tag, len(field.Value))
		}
	}
}

func TestClient_ImportKey_Rejects(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	badExponent := &rsa.PrivateKey{PublicKey: rsa.PublicKey{N: rsaKey.N, E: 3}, D: rsaKey.D, Primes: rsaKey.Primes, Precomputed: rsaKey.Precomputed}
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	tests := []struct {
		name      string
		algorithm byte
		key       any
		pin       byte
		touch     byte
	}{
		{name: "bad exponent", algorithm: AlgRSA2048, key: badExponent},
		{name: "unsupported algorithm", algorithm: 0x05, key: rsaKey},
		{name: "rsa size mismatch", algorithm: AlgRSA1024, key: rsaKey},
		{name: "ec curve mismatch", algorithm: AlgECCP384, key: ecKey},
		{name: "unsupported key type", algorithm: AlgECCP256, key: "not-a-key"},
		{name: "unsupported pin policy", algorithm: AlgECCP256, key: ecKey, pin: 0x04},
		{name: "unsupported touch policy", algorithm: AlgECCP256, key: ecKey, touch: 0x05},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			mock := emulator.NewCard()
			var privateKey any = test.key
			err := NewClient(mock).ImportKey(SlotAuthentication, test.algorithm, privateKey, test.pin, test.touch)
			if err == nil || !strings.Contains(err.Error(), "unsupported") {
				t.Fatalf("expected unsupported error, got %v", err)
			}
			if len(mock.TransmittedCommands) != 0 {
				t.Fatalf("no APDU must be sent on validation failure, got %d commands", len(mock.TransmittedCommands))
			}
		})
	}
}

func TestEncodeImportKeyData_RejectsNonTwoPrimeRSA(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	withPrimes := func(count int) *rsa.PrivateKey {
		primes := make([]*big.Int, 0, count)
		for i := 0; i < count && i < len(rsaKey.Primes); i++ {
			primes = append(primes, rsaKey.Primes[i])
		}
		for len(primes) < count {
			primes = append(primes, big.NewInt(3))
		}
		return &rsa.PrivateKey{
			PublicKey:   rsaKey.PublicKey,
			D:           rsaKey.D,
			Primes:      primes,
			Precomputed: rsaKey.Precomputed,
		}
	}

	tests := []struct {
		name       string
		primes     int
		wantErr    bool
		errContain string
	}{
		{name: "two primes accepted", primes: 2},
		{name: "no primes rejected", primes: 0, wantErr: true, errContain: "2 primes"},
		{name: "single prime rejected", primes: 1, wantErr: true, errContain: "2 primes"},
		{name: "multi-prime rejected", primes: 3, wantErr: true, errContain: "unsupported"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			data, err := encodeImportKeyData(AlgRSA2048, withPrimes(test.primes), PinPolicyDefault, TouchPolicyDefault)
			if !test.wantErr {
				if err != nil {
					t.Fatalf("encodeImportKeyData() error = %v", err)
				}
				if len(data) == 0 {
					t.Fatal("expected non-empty import payload")
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), test.errContain) {
				t.Fatalf("expected error containing %q, got %v", test.errContain, err)
			}
		})
	}
}
