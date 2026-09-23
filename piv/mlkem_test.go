package piv

import (
	"bytes"
	"crypto/mlkem"
	"crypto/rand"
	"strings"
	"testing"
)

// TestMLKEMEncapsulationKeyFromSeed verifies seed expansion against the
// standard library: the derived encapsulation key must encapsulate
// ciphertexts that the seed's decapsulation key recovers. ML-KEM-512 has
// no standard library implementation and must gap-reject.
func TestMLKEMEncapsulationKeyFromSeed(t *testing.T) {
	seed := make([]byte, MLKEMSeedLength)
	if _, err := rand.Read(seed); err != nil {
		t.Fatalf("rand.Read() error = %v", err)
	}
	dk768, err := mlkem.NewDecapsulationKey768(seed)
	if err != nil {
		t.Fatalf("NewDecapsulationKey768() error = %v", err)
	}
	ek768, err := MLKEMEncapsulationKeyFromSeed(AlgMLKEM768, seed)
	if err != nil {
		t.Fatalf("MLKEMEncapsulationKeyFromSeed(768) error = %v", err)
	}
	if !bytes.Equal(ek768, dk768.EncapsulationKey().Bytes()) {
		t.Fatal("ML-KEM-768 encapsulation key must match crypto/mlkem")
	}
	parsed, err := mlkem.NewEncapsulationKey768(ek768)
	if err != nil {
		t.Fatalf("NewEncapsulationKey768() error = %v", err)
	}
	shared, ciphertext := parsed.Encapsulate()
	recovered, err := dk768.Decapsulate(ciphertext)
	if err != nil {
		t.Fatalf("Decapsulate() error = %v", err)
	}
	if !bytes.Equal(shared, recovered) {
		t.Fatal("encapsulated secret must round-trip through the seed key")
	}

	dk1024, err := mlkem.NewDecapsulationKey1024(seed)
	if err != nil {
		t.Fatalf("NewDecapsulationKey1024() error = %v", err)
	}
	ek1024, err := MLKEMEncapsulationKeyFromSeed(AlgMLKEM1024, seed)
	if err != nil {
		t.Fatalf("MLKEMEncapsulationKeyFromSeed(1024) error = %v", err)
	}
	if !bytes.Equal(ek1024, dk1024.EncapsulationKey().Bytes()) {
		t.Fatal("ML-KEM-1024 encapsulation key must match crypto/mlkem")
	}
	if len(ek768) != 1184 || len(ek1024) != 1568 {
		t.Fatalf("encapsulation key lengths = %d/%d, want 1184/1568", len(ek768), len(ek1024))
	}

	// ML-KEM-512 has no standard library implementation: derivation
	// gap-rejects with a not-supported error.
	if _, err := MLKEMEncapsulationKeyFromSeed(AlgMLKEM512, seed); err == nil || !strings.Contains(err.Error(), "not supported") {
		t.Fatalf("expected not-supported error for ML-KEM-512, got %v", err)
	}

	// Frozen wire tables: seed 64 for every variant; ciphertext
	// 768/1088/1568; public key 800/1184/1568.
	if MLKEMSeedLength != 64 {
		t.Fatalf("MLKEMSeedLength = %d, want 64", MLKEMSeedLength)
	}
	for _, test := range []struct {
		algorithm byte
		ctLen     int
		ekLen     int
	}{
		{algorithm: AlgMLKEM512, ctLen: 768, ekLen: 800},
		{algorithm: AlgMLKEM768, ctLen: 1088, ekLen: 1184},
		{algorithm: AlgMLKEM1024, ctLen: 1568, ekLen: 1568},
	} {
		if got, ok := MLKEMCiphertextLength(test.algorithm); !ok || got != test.ctLen {
			t.Fatalf("MLKEMCiphertextLength(0x%02X) = %d, %v; want %d", test.algorithm, got, ok, test.ctLen)
		}
		if got, ok := yubiKey6PublicKeyLength(test.algorithm); !ok || got != test.ekLen {
			t.Fatalf("yubiKey6PublicKeyLength(0x%02X) = %d, %v; want %d", test.algorithm, got, ok, test.ekLen)
		}
	}

	// Wrong seed length and unknown algorithm reject.
	if _, err := MLKEMEncapsulationKeyFromSeed(AlgMLKEM768, bytes.Repeat([]byte{0xD5}, 32)); err == nil || !strings.Contains(err.Error(), "must be 64 bytes") {
		t.Fatalf("expected length error, got %v", err)
	}
	if _, err := MLKEMEncapsulationKeyFromSeed(AlgECCP256, bytes.Repeat([]byte{0xD5}, 64)); err == nil {
		t.Fatal("expected error for non-KEM algorithm")
	}
}
