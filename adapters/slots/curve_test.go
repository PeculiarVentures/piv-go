package slots_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"testing"

	"github.com/PeculiarVentures/piv-go/adapters/slots"
)

// namedCurve carries the bit size of P-256 but a different curve identity. Its
// arithmetic is irrelevant to this display test; signing must use actual keys.
type namedCurve struct{ elliptic.Curve }

func (namedCurve) Params() *elliptic.CurveParams {
	p := *elliptic.P256().Params()
	p.Name = "secp256k1"
	return &p
}

func TestPublicKeyAlgorithmNameUsesExactCurveIdentity(t *testing.T) {
	for _, tt := range []struct {
		curve elliptic.Curve
		want  string
	}{
		{elliptic.P256(), "eccp256"}, {elliptic.P384(), "eccp384"}, {elliptic.P521(), "eccp521"},
		{namedCurve{elliptic.P256()}, "ecdsa-secp256k1"},
	} {
		got := slots.PublicKeyAlgorithmName(&ecdsa.PublicKey{Curve: tt.curve})
		if got != tt.want {
			t.Fatalf("curve %s = %q, want %q", tt.curve.Params().Name, got, tt.want)
		}
	}
	if got := slots.PublicKeyAlgorithmName(&ecdsa.PublicKey{}); got != "ecdsa-unknown" {
		t.Fatalf("missing curve = %q", got)
	}
}
