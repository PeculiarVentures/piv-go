package app

import (
	"crypto/rsa"
	"math/big"
	"strings"
	"testing"

	"github.com/PeculiarVentures/piv-go/piv"
)

func TestAlgorithmNameYubiKey6(t *testing.T) {
	tests := []struct {
		algorithm byte
		want      string
	}{
		{algorithm: piv.AlgRSA3072, want: "rsa3072"},
		{algorithm: piv.AlgRSA4096, want: "rsa4096"},
		{algorithm: piv.AlgEd25519, want: "ed25519"},
		{algorithm: piv.AlgX25519, want: "x25519"},
		{algorithm: piv.AlgMLDSA44, want: "mldsa44"},
		{algorithm: piv.AlgMLDSA65, want: "mldsa65"},
		{algorithm: piv.AlgMLDSA87, want: "mldsa87"},
		{algorithm: piv.AlgMLKEM512, want: "mlkem512"},
		{algorithm: piv.AlgMLKEM768, want: "mlkem768"},
		{algorithm: piv.AlgMLKEM1024, want: "mlkem1024"},
	}
	for _, test := range tests {
		if got := AlgorithmName(test.algorithm); got != test.want {
			t.Fatalf("AlgorithmName(0x%02X) = %q, want %q", test.algorithm, got, test.want)
		}
	}
}

func TestParseKeyAlgorithmPQC(t *testing.T) {
	tests := []struct {
		name      string
		algorithm byte
		canonical string
	}{
		{name: "rsa3072", algorithm: piv.AlgRSA3072, canonical: "rsa3072"},
		{name: "RSA4096", algorithm: piv.AlgRSA4096, canonical: "rsa4096"},
		{name: "ed25519", algorithm: piv.AlgEd25519, canonical: "ed25519"},
		{name: "X25519", algorithm: piv.AlgX25519, canonical: "x25519"},
		{name: "mldsa44", algorithm: piv.AlgMLDSA44, canonical: "mldsa44"},
		{name: "MLDSA65", algorithm: piv.AlgMLDSA65, canonical: "mldsa65"},
		{name: "mldsa87", algorithm: piv.AlgMLDSA87, canonical: "mldsa87"},
		{name: "mlkem512", algorithm: piv.AlgMLKEM512, canonical: "mlkem512"},
		{name: "MLKEM768", algorithm: piv.AlgMLKEM768, canonical: "mlkem768"},
		{name: "mlkem1024", algorithm: piv.AlgMLKEM1024, canonical: "mlkem1024"},
		{name: "ECCP256", algorithm: piv.AlgECCP256, canonical: "p256"},
		{name: "eccp384", algorithm: piv.AlgECCP384, canonical: "p384"},
	}
	for _, test := range tests {
		algorithm, name, err := ParseKeyAlgorithm(test.name)
		if err != nil {
			t.Fatalf("ParseKeyAlgorithm(%q) error = %v", test.name, err)
		}
		if algorithm != test.algorithm || name != test.canonical {
			t.Fatalf("ParseKeyAlgorithm(%q) = (0x%02X, %q), want (0x%02X, %q)", test.name, algorithm, name, test.algorithm, test.canonical)
		}
	}
	for _, name := range []string{"rsa9999", "mldsa", "mlkem", "bogus"} {
		if _, _, err := ParseKeyAlgorithm(name); err == nil {
			t.Fatalf("ParseKeyAlgorithm(%q): expected UsageError, got nil", name)
		}
	}
}

func TestInferPublicKeyAlgorithmYubiKey6(t *testing.T) {
	rsa3072 := &rsa.PublicKey{N: new(big.Int).Lsh(big.NewInt(1), 3071), E: 65537}
	algorithm, name, err := InferPublicKeyAlgorithm(rsa3072)
	if err != nil {
		t.Fatalf("InferPublicKeyAlgorithm(rsa3072) error = %v", err)
	}
	if algorithm != piv.AlgRSA3072 || name != "rsa3072" {
		t.Fatalf("InferPublicKeyAlgorithm(rsa3072) = (0x%02X, %q), want (0x05, rsa3072)", algorithm, name)
	}

	rsa4096 := &rsa.PublicKey{N: new(big.Int).Lsh(big.NewInt(1), 4095), E: 65537}
	algorithm, name, err = InferPublicKeyAlgorithm(rsa4096)
	if err != nil {
		t.Fatalf("InferPublicKeyAlgorithm(rsa4096) error = %v", err)
	}
	if algorithm != piv.AlgRSA4096 || name != "rsa4096" {
		t.Fatalf("InferPublicKeyAlgorithm(rsa4096) = (0x%02X, %q), want (0x16, rsa4096)", algorithm, name)
	}

	opaqueTests := []struct {
		key       *piv.OpaquePublicKey
		algorithm byte
		name      string
	}{
		{key: &piv.OpaquePublicKey{Algorithm: piv.AlgEd25519}, algorithm: piv.AlgEd25519, name: "ed25519"},
		{key: &piv.OpaquePublicKey{Algorithm: piv.AlgX25519}, algorithm: piv.AlgX25519, name: "x25519"},
		{key: &piv.OpaquePublicKey{Algorithm: piv.AlgMLDSA44}, algorithm: piv.AlgMLDSA44, name: "mldsa44"},
		{key: &piv.OpaquePublicKey{Algorithm: piv.AlgMLKEM1024}, algorithm: piv.AlgMLKEM1024, name: "mlkem1024"},
	}
	for _, test := range opaqueTests {
		algorithm, name, err := InferPublicKeyAlgorithm(test.key)
		if err != nil {
			t.Fatalf("InferPublicKeyAlgorithm(%s) error = %v", test.name, err)
		}
		if algorithm != test.algorithm || name != test.name {
			t.Fatalf("InferPublicKeyAlgorithm() = (0x%02X, %q), want (0x%02X, %q)", algorithm, name, test.algorithm, test.name)
		}
	}

	if _, _, err := InferPublicKeyAlgorithm(&piv.OpaquePublicKey{}); err == nil || !strings.Contains(err.Error(), "unsupported") {
		t.Fatalf("unknown opaque algorithm: expected unsupported error, got %v", err)
	}
}

func TestEncodePublicKeyRejectsPQCOpaque(t *testing.T) {
	for _, algorithm := range []byte{piv.AlgMLDSA44, piv.AlgMLDSA65, piv.AlgMLDSA87, piv.AlgMLKEM512, piv.AlgMLKEM768, piv.AlgMLKEM1024} {
		_, err := EncodePublicKey(&piv.OpaquePublicKey{Algorithm: algorithm, Raw: []byte{0x01}}, "pem")
		if err == nil {
			t.Fatalf("algorithm 0x%02X: expected UnsupportedError, got nil", algorithm)
		}
		cliErr, ok := err.(*CLIError)
		if !ok || cliErr.Code != "unsupported-capability" {
			t.Fatalf("algorithm 0x%02X: expected unsupported-capability, got %#v", algorithm, err)
		}
	}
}
