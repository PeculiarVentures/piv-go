package adapters_test

import (
	"crypto/rsa"
	"math/big"
	"testing"

	adaptercore "github.com/PeculiarVentures/piv-go/adapters"
	"github.com/PeculiarVentures/piv-go/adapters/slots"
	"github.com/PeculiarVentures/piv-go/piv"
)

func TestNormalizeKeyAlgorithmYubiKey6(t *testing.T) {
	tests := []struct {
		algorithm byte
		want      adaptercore.KeyAlgorithm
	}{
		{algorithm: piv.AlgRSA3072, want: adaptercore.KeyAlgorithmRSA3072},
		{algorithm: piv.AlgRSA4096, want: adaptercore.KeyAlgorithmRSA4096},
		{algorithm: piv.AlgEd25519, want: adaptercore.KeyAlgorithmEd25519},
		{algorithm: piv.AlgX25519, want: adaptercore.KeyAlgorithmX25519},
		{algorithm: piv.AlgMLDSA44, want: adaptercore.KeyAlgorithmMLDSA44},
		{algorithm: piv.AlgMLDSA65, want: adaptercore.KeyAlgorithmMLDSA65},
		{algorithm: piv.AlgMLDSA87, want: adaptercore.KeyAlgorithmMLDSA87},
		{algorithm: piv.AlgMLKEM512, want: adaptercore.KeyAlgorithmMLKEM512},
		{algorithm: piv.AlgMLKEM768, want: adaptercore.KeyAlgorithmMLKEM768},
		{algorithm: piv.AlgMLKEM1024, want: adaptercore.KeyAlgorithmMLKEM1024},
	}
	for _, test := range tests {
		if got := adaptercore.NormalizeKeyAlgorithm(test.algorithm); got != test.want {
			t.Fatalf("NormalizeKeyAlgorithm(0x%02X) = %q, want %q", test.algorithm, got, test.want)
		}
		if string(test.want) != map[byte]string{
			piv.AlgRSA3072: "rsa3072", piv.AlgRSA4096: "rsa4096",
			piv.AlgEd25519: "ed25519", piv.AlgX25519: "x25519",
			piv.AlgMLDSA44: "mldsa44", piv.AlgMLDSA65: "mldsa65", piv.AlgMLDSA87: "mldsa87",
			piv.AlgMLKEM512: "mlkem512", piv.AlgMLKEM768: "mlkem768", piv.AlgMLKEM1024: "mlkem1024",
		}[test.algorithm] {
			t.Fatalf("KeyAlgorithm constant for 0x%02X has unexpected value %q", test.algorithm, test.want)
		}
	}
}

func TestPublicKeyAlgorithmNameYubiKey6(t *testing.T) {
	rsa3072 := &rsa.PublicKey{N: new(big.Int).Lsh(big.NewInt(1), 3071), E: 65537}
	if got := slots.PublicKeyAlgorithmName(rsa3072); got != "rsa3072" {
		t.Fatalf("PublicKeyAlgorithmName(rsa3072) = %q, want rsa3072", got)
	}
	rsa4096 := &rsa.PublicKey{N: new(big.Int).Lsh(big.NewInt(1), 4095), E: 65537}
	if got := slots.PublicKeyAlgorithmName(rsa4096); got != "rsa4096" {
		t.Fatalf("PublicKeyAlgorithmName(rsa4096) = %q, want rsa4096", got)
	}

	opaqueTests := []struct {
		algorithm byte
		want      string
	}{
		{algorithm: piv.AlgEd25519, want: "ed25519"},
		{algorithm: piv.AlgX25519, want: "x25519"},
		{algorithm: piv.AlgMLDSA44, want: "mldsa44"},
		{algorithm: piv.AlgMLDSA65, want: "mldsa65"},
		{algorithm: piv.AlgMLDSA87, want: "mldsa87"},
		{algorithm: piv.AlgMLKEM512, want: "mlkem512"},
		{algorithm: piv.AlgMLKEM768, want: "mlkem768"},
		{algorithm: piv.AlgMLKEM1024, want: "mlkem1024"},
	}
	for _, test := range opaqueTests {
		if got := slots.PublicKeyAlgorithmName(&piv.OpaquePublicKey{Algorithm: test.algorithm}); got != test.want {
			t.Fatalf("PublicKeyAlgorithmName(0x%02X) = %q, want %q", test.algorithm, got, test.want)
		}
	}
}
