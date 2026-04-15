package adapters_test

import (
	"testing"

	adaptercore "github.com/PeculiarVentures/piv-go/adapters"
	"github.com/PeculiarVentures/piv-go/emulator"
	"github.com/PeculiarVentures/piv-go/piv"
)

func TestResolveKeyMetadataFallsBackWithoutAdapter(t *testing.T) {
	runtime := adaptercore.NewRuntime(adaptercore.NewSession(piv.NewClient(emulator.NewCard())), nil)

	metadata, err := adaptercore.ResolveKeyMetadata(runtime, piv.SlotSignature)
	if err != nil {
		t.Fatalf("ResolveKeyMetadata() error = %v", err)
	}
	if metadata.Slot != piv.SlotSignature {
		t.Fatalf("unexpected slot %s", metadata.Slot)
	}
	if metadata.Source != adaptercore.ResolutionSourceFallback {
		t.Fatalf("unexpected source %q", metadata.Source)
	}
	if metadata.PINPolicy != adaptercore.PINPolicyUnknown {
		t.Fatalf("unexpected PIN policy %q", metadata.PINPolicy)
	}
	if metadata.Algorithm != adaptercore.KeyAlgorithmUnknown {
		t.Fatalf("unexpected algorithm %q", metadata.Algorithm)
	}
	if metadata.TouchPolicy != adaptercore.TouchPolicyUnknown {
		t.Fatalf("unexpected touch policy %q", metadata.TouchPolicy)
	}
}

func TestDeriveSignAuthorization(t *testing.T) {
	tests := []struct {
		name         string
		policy       adaptercore.PINPolicy
		requiresPIN  bool
		canSignNoPIN bool
		known        bool
	}{
		{name: "unknown", policy: adaptercore.PINPolicyUnknown},
		{name: "never", policy: adaptercore.PINPolicyNever, canSignNoPIN: true, known: true},
		{name: "once", policy: adaptercore.PINPolicyOnce, requiresPIN: true, known: true},
		{name: "always", policy: adaptercore.PINPolicyAlways, requiresPIN: true, known: true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			authorization := adaptercore.DeriveSignAuthorization(adaptercore.KeyMetadata{Slot: piv.SlotSignature, PINPolicy: test.policy, Source: adaptercore.ResolutionSourceVendorMetadata})
			if authorization.RequiresPIN() != test.requiresPIN {
				t.Fatalf("RequiresPIN() = %t, want %t", authorization.RequiresPIN(), test.requiresPIN)
			}
			if authorization.CanSignWithoutPIN() != test.canSignNoPIN {
				t.Fatalf("CanSignWithoutPIN() = %t, want %t", authorization.CanSignWithoutPIN(), test.canSignNoPIN)
			}
			if authorization.IsKnown() != test.known {
				t.Fatalf("IsKnown() = %t, want %t", authorization.IsKnown(), test.known)
			}
		})
	}
}

func TestNormalizeMetadataEnums(t *testing.T) {
	if got := adaptercore.NormalizeKeyAlgorithm(piv.AlgECCP256); got != adaptercore.KeyAlgorithmECCP256 {
		t.Fatalf("NormalizeKeyAlgorithm() = %q, want %q", got, adaptercore.KeyAlgorithmECCP256)
	}
	if got := adaptercore.NormalizeKeyAlgorithm(0xFF); got != adaptercore.KeyAlgorithmUnknown {
		t.Fatalf("NormalizeKeyAlgorithm() = %q, want unknown", got)
	}
	if got := adaptercore.NormalizePINPolicy(0x01); got != adaptercore.PINPolicyOnce {
		t.Fatalf("NormalizePINPolicy() = %q, want %q", got, adaptercore.PINPolicyOnce)
	}
	if got := adaptercore.NormalizePINPolicy(0xFF); got != adaptercore.PINPolicyUnknown {
		t.Fatalf("NormalizePINPolicy() = %q, want unknown", got)
	}
	if got := adaptercore.NormalizeTouchPolicy(0x02); got != adaptercore.TouchPolicyCached {
		t.Fatalf("NormalizeTouchPolicy() = %q, want %q", got, adaptercore.TouchPolicyCached)
	}
	if got := adaptercore.NormalizeTouchPolicy(0xFF); got != adaptercore.TouchPolicyUnknown {
		t.Fatalf("NormalizeTouchPolicy() = %q, want unknown", got)
	}
}
