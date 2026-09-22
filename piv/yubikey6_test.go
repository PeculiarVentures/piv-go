package piv

import (
	"bytes"
	"crypto/rsa"
	"errors"
	"math/big"
	"strings"
	"testing"

	"github.com/PeculiarVentures/piv-go/emulator"
	"github.com/PeculiarVentures/piv-go/iso7816"
)

var yubiKey6Algorithms = []byte{
	AlgRSA3072, AlgRSA4096,
	AlgEd25519, AlgX25519,
	AlgMLDSA44, AlgMLDSA65, AlgMLDSA87,
	AlgMLKEM512, AlgMLKEM768, AlgMLKEM1024,
}

func TestIsYubiKey6Algorithm(t *testing.T) {
	for _, algorithm := range yubiKey6Algorithms {
		if !IsYubiKey6Algorithm(algorithm) {
			t.Fatalf("IsYubiKey6Algorithm(0x%02X) = false, want true", algorithm)
		}
	}
	for _, algorithm := range []byte{AlgRSA1024, AlgRSA2048, AlgECCP256, AlgECCP384, 0x00, 0xFF} {
		if IsYubiKey6Algorithm(algorithm) {
			t.Fatalf("IsYubiKey6Algorithm(0x%02X) = true, want false", algorithm)
		}
	}
}

func encodeStoredPublicKey(t *testing.T, inner []byte) []byte {
	t.Helper()
	return iso7816.EncodeTLV(0x53, iso7816.EncodeTLV(0x7F49, inner))
}

func TestParsePublicKeyObjectYubiKey6Opaque(t *testing.T) {
	raw32 := bytes.Repeat([]byte{0x11}, 32)
	key, err := ParsePublicKeyObject(encodeStoredPublicKey(t, iso7816.EncodeTLV(0x86, raw32)))
	if err != nil {
		t.Fatalf("ParsePublicKeyObject(0x86/32) error = %v", err)
	}
	opaque, ok := key.(*OpaquePublicKey)
	if !ok {
		t.Fatalf("expected *OpaquePublicKey, got %T", key)
	}
	if opaque.Algorithm != 0 {
		t.Fatalf("ambiguous 0x86/32 must parse with Algorithm zero, got 0x%02X", opaque.Algorithm)
	}
	if !bytes.Equal(opaque.Raw, raw32) {
		t.Fatal("opaque raw bytes must round-trip verbatim")
	}

	// Post-quantum tags infer the variant from the value length.
	mldsa := bytes.Repeat([]byte{0x22}, 1312)
	key, err = ParsePublicKeyObject(encodeStoredPublicKey(t, iso7816.EncodeTLV(0x87, mldsa)))
	if err != nil {
		t.Fatalf("ParsePublicKeyObject(0x87/1312) error = %v", err)
	}
	if opaque, ok := key.(*OpaquePublicKey); !ok || opaque.Algorithm != AlgMLDSA44 || !bytes.Equal(opaque.Raw, mldsa) {
		t.Fatalf("unexpected ML-DSA-44 parse result: %#v, %v", key, err)
	}

	mlkem := bytes.Repeat([]byte{0x33}, 800)
	key, err = ParsePublicKeyObject(encodeStoredPublicKey(t, iso7816.EncodeTLV(0x88, mlkem)))
	if err != nil {
		t.Fatalf("ParsePublicKeyObject(0x88/800) error = %v", err)
	}
	if opaque, ok := key.(*OpaquePublicKey); !ok || opaque.Algorithm != AlgMLKEM512 || !bytes.Equal(opaque.Raw, mlkem) {
		t.Fatalf("unexpected ML-KEM-512 parse result: %#v, %v", key, err)
	}
}

func TestParsePublicKeyObjectYubiKey6RejectsUnknown(t *testing.T) {
	payloads := [][]byte{
		iso7816.EncodeTLV(0x86, bytes.Repeat([]byte{0x11}, 33)),
		iso7816.EncodeTLV(0x87, bytes.Repeat([]byte{0x22}, 100)),
		iso7816.EncodeTLV(0x88, bytes.Repeat([]byte{0x33}, 100)),
		iso7816.EncodeTLV(0x99, []byte{0x00}),
	}
	for _, inner := range payloads {
		_, err := ParsePublicKeyObject(encodeStoredPublicKey(t, inner))
		if err == nil {
			t.Fatalf("payload %X: expected typed error, got nil", inner)
		}
		var unsupported *UnsupportedPublicKeyError
		if !errors.As(err, &unsupported) {
			t.Fatalf("payload %X: expected *UnsupportedPublicKeyError, got %T (%v)", inner, err, err)
		}
	}
}

func TestParseGeneratedPublicKeyYubiKey6Opaque(t *testing.T) {
	tests := []struct {
		algorithm byte
		inner     []byte
	}{
		{algorithm: AlgEd25519, inner: iso7816.EncodeTLV(0x86, bytes.Repeat([]byte{0x41}, 32))},
		{algorithm: AlgX25519, inner: iso7816.EncodeTLV(0x86, bytes.Repeat([]byte{0x42}, 32))},
		{algorithm: AlgMLDSA44, inner: iso7816.EncodeTLV(0x87, bytes.Repeat([]byte{0x43}, 1312))},
		{algorithm: AlgMLDSA65, inner: iso7816.EncodeTLV(0x87, bytes.Repeat([]byte{0x44}, 1952))},
		{algorithm: AlgMLDSA87, inner: iso7816.EncodeTLV(0x87, bytes.Repeat([]byte{0x45}, 2592))},
		{algorithm: AlgMLKEM512, inner: iso7816.EncodeTLV(0x88, bytes.Repeat([]byte{0x46}, 800))},
		{algorithm: AlgMLKEM768, inner: iso7816.EncodeTLV(0x88, bytes.Repeat([]byte{0x47}, 1184))},
		{algorithm: AlgMLKEM1024, inner: iso7816.EncodeTLV(0x88, bytes.Repeat([]byte{0x48}, 1568))},
	}
	for _, test := range tests {
		key, err := parseGeneratedPublicKey(test.algorithm, iso7816.EncodeTLV(0x7F49, test.inner))
		if err != nil {
			t.Fatalf("algorithm 0x%02X: unexpected error: %v", test.algorithm, err)
		}
		opaque, ok := key.(*OpaquePublicKey)
		if !ok {
			t.Fatalf("algorithm 0x%02X: expected *OpaquePublicKey, got %T", test.algorithm, key)
		}
		if opaque.Algorithm != test.algorithm {
			t.Fatalf("algorithm 0x%02X: opaque carries 0x%02X", test.algorithm, opaque.Algorithm)
		}
	}

	mismatches := []struct {
		algorithm byte
		inner     []byte
	}{
		{algorithm: AlgEd25519, inner: iso7816.EncodeTLV(0x87, bytes.Repeat([]byte{0x41}, 32))},
		{algorithm: AlgEd25519, inner: iso7816.EncodeTLV(0x86, bytes.Repeat([]byte{0x41}, 33))},
		{algorithm: AlgMLDSA44, inner: iso7816.EncodeTLV(0x87, bytes.Repeat([]byte{0x43}, 1952))},
		{algorithm: AlgMLKEM512, inner: iso7816.EncodeTLV(0x87, bytes.Repeat([]byte{0x46}, 800))},
	}
	for _, test := range mismatches {
		_, err := parseGeneratedPublicKey(test.algorithm, iso7816.EncodeTLV(0x7F49, test.inner))
		if err == nil {
			t.Fatalf("algorithm 0x%02X: expected typed error, got nil", test.algorithm)
		}
		var unsupported *UnsupportedPublicKeyError
		if !errors.As(err, &unsupported) {
			t.Fatalf("algorithm 0x%02X: expected *UnsupportedPublicKeyError, got %T (%v)", test.algorithm, err, err)
		}
	}
}

func TestParseGeneratedPublicKeyRSA3072(t *testing.T) {
	modulus := append([]byte{0x80}, bytes.Repeat([]byte{0x55}, 383)...)
	response := iso7816.EncodeTLV(0x7F49,
		append(iso7816.EncodeTLV(0x81, modulus), iso7816.EncodeTLV(0x82, []byte{0x01, 0x00, 0x01})...))
	key, err := parseGeneratedPublicKey(AlgRSA3072, response)
	if err != nil {
		t.Fatalf("parseGeneratedPublicKey(RSA3072) error = %v", err)
	}
	rsaKey, ok := key.(*rsa.PublicKey)
	if !ok {
		t.Fatalf("expected *rsa.PublicKey, got %T", key)
	}
	if new(big.Int).SetBytes(modulus).Cmp(rsaKey.N) != 0 || rsaKey.E != 65537 {
		t.Fatal("RSA-3072 public key fields do not round-trip")
	}
}

func TestClient_YubiKey6GapRejectedWithoutAPDU(t *testing.T) {
	// pqc-v1 matrix GAP/REJECT paths: no APDU must be sent.
	// Generate gap: ML-KEM only. Import gap: ML-DSA + ML-KEM.
	// Sign reject: X25519 (use ECDH) + ML-KEM gap. Store gap: ML-KEM only.
	for _, algorithm := range []byte{AlgMLKEM512, AlgMLKEM768, AlgMLKEM1024} {
		mock := emulator.NewCard()
		if _, err := NewClient(mock).GenerateKeyPair(SlotSignature, algorithm); err == nil || !strings.Contains(err.Error(), "not supported") {
			t.Fatalf("generate 0x%02X: expected not-supported error, got %v", algorithm, err)
		}
		if len(mock.TransmittedCommands) != 0 {
			t.Fatalf("generate 0x%02X: no APDU must be sent on rejection, got %d commands", algorithm, len(mock.TransmittedCommands))
		}
	}
	for _, algorithm := range []byte{AlgMLDSA44, AlgMLDSA65, AlgMLDSA87, AlgMLKEM512, AlgMLKEM768, AlgMLKEM1024} {
		mock := emulator.NewCard()
		if err := NewClient(mock).ImportKey(SlotSignature, algorithm, "not-a-key", PinPolicyDefault, TouchPolicyDefault); err == nil || !strings.Contains(err.Error(), "not supported") {
			t.Fatalf("import 0x%02X: expected not-supported error, got %v", algorithm, err)
		}
		if len(mock.TransmittedCommands) != 0 {
			t.Fatalf("import 0x%02X: no APDU must be sent on rejection, got %d commands", algorithm, len(mock.TransmittedCommands))
		}
	}
	{
		mock := emulator.NewCard()
		if _, err := NewClient(mock).Sign(AlgX25519, SlotSignature, []byte{0xAA}); err == nil || !strings.Contains(err.Error(), "x25519 cannot sign: use ECDH") {
			t.Fatalf("sign x25519: expected ECDH hint, got %v", err)
		}
		if _, err := NewClient(mock).Authenticate(AlgX25519, SlotSignature, []byte{0xAA}); err == nil || !strings.Contains(err.Error(), "x25519 cannot sign: use ECDH") {
			t.Fatalf("authenticate x25519: expected ECDH hint, got %v", err)
		}
		if len(mock.TransmittedCommands) != 0 {
			t.Fatalf("x25519 sign: no APDU must be sent on rejection, got %d commands", len(mock.TransmittedCommands))
		}
	}
	for _, algorithm := range []byte{AlgMLKEM512, AlgMLKEM768, AlgMLKEM1024} {
		mock := emulator.NewCard()
		if _, err := NewClient(mock).Sign(algorithm, SlotSignature, []byte{0xAA}); err == nil || !strings.Contains(err.Error(), "not supported") {
			t.Fatalf("sign 0x%02X: expected not-supported error, got %v", algorithm, err)
		}
		if _, err := NewClient(mock).Authenticate(algorithm, SlotSignature, []byte{0xAA}); err == nil || !strings.Contains(err.Error(), "not supported") {
			t.Fatalf("authenticate 0x%02X: expected not-supported error, got %v", algorithm, err)
		}
		if err := NewClient(mock).StoreGeneratedPublicKey(SlotSignature, algorithm, &OpaquePublicKey{Algorithm: algorithm}); err == nil || !strings.Contains(err.Error(), "not supported") {
			t.Fatalf("store 0x%02X: expected not-supported error, got %v", algorithm, err)
		}
		if len(mock.TransmittedCommands) != 0 {
			t.Fatalf("algorithm 0x%02X: no APDU must be sent on rejection, got %d commands", algorithm, len(mock.TransmittedCommands))
		}
	}
}
