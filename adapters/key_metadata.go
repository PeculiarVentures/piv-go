package adapters

import (
	"fmt"

	"github.com/PeculiarVentures/piv-go/piv"
)

// ResolutionSource describes how normalized token metadata or decisions were resolved.
type ResolutionSource string

const (
	// ResolutionSourceUnknown indicates the origin of the data is unknown.
	ResolutionSourceUnknown ResolutionSource = "unknown"
	// ResolutionSourceStandardMetadata indicates the data came from standard PIV metadata.
	ResolutionSourceStandardMetadata ResolutionSource = "standard-metadata"
	// ResolutionSourceVendorMetadata indicates the data came from vendor-specific metadata.
	ResolutionSourceVendorMetadata ResolutionSource = "vendor-metadata"
	// ResolutionSourceFallback indicates the data was produced by a conservative fallback path.
	ResolutionSourceFallback ResolutionSource = "fallback"
)

// PINPolicy describes the normalized authorization policy associated with a key.
type PINPolicy string

const (
	// PINPolicyUnknown indicates the token policy could not be determined.
	PINPolicyUnknown PINPolicy = "unknown"
	// PINPolicyNever indicates a key can be used without a preceding VERIFY PIN.
	PINPolicyNever PINPolicy = "never"
	// PINPolicyOnce indicates one successful VERIFY PIN can be reused for the current authenticated session.
	PINPolicyOnce PINPolicy = "once"
	// PINPolicyAlways indicates VERIFY PIN is required before each signing operation.
	PINPolicyAlways PINPolicy = "always"
)

// KeyAlgorithm describes the normalized algorithm metadata associated with a slot key.
type KeyAlgorithm string

const (
	// KeyAlgorithmUnknown indicates the algorithm could not be determined.
	KeyAlgorithmUnknown KeyAlgorithm = "unknown"
	// KeyAlgorithmECCP256 indicates an ECC P-256 key.
	KeyAlgorithmECCP256 KeyAlgorithm = "eccp256"
	// KeyAlgorithmECCP384 indicates an ECC P-384 key.
	KeyAlgorithmECCP384 KeyAlgorithm = "eccp384"
	// KeyAlgorithmRSA1024 indicates an RSA-1024 key.
	KeyAlgorithmRSA1024 KeyAlgorithm = "rsa1024"
	// KeyAlgorithmRSA2048 indicates an RSA-2048 key.
	KeyAlgorithmRSA2048 KeyAlgorithm = "rsa2048"
)

// TouchPolicy describes the normalized presence policy for user touch interaction.
type TouchPolicy string

const (
	// TouchPolicyUnknown indicates the token does not expose a normalized touch policy.
	TouchPolicyUnknown TouchPolicy = "unknown"
	// TouchPolicyNever indicates no touch interaction is required.
	TouchPolicyNever TouchPolicy = "never"
	// TouchPolicyAlways indicates each operation requires touch confirmation.
	TouchPolicyAlways TouchPolicy = "always"
	// TouchPolicyCached indicates touch approval may be reused for a short cache window.
	TouchPolicyCached TouchPolicy = "cached"
)

// KeyMetadata describes the best-effort normalized metadata available for a key slot.
//
// The model is intentionally partial: tokens may omit fields or expose only a
// subset that the library can normalize today. Unknown fields remain set to the
// corresponding unknown enum values. VendorFields may include optional raw or
// vendor-specific data for diagnostic or future use.
type KeyMetadata struct {
	Slot         piv.Slot
	Algorithm    KeyAlgorithm
	PINPolicy    PINPolicy
	TouchPolicy  TouchPolicy
	Source       ResolutionSource
	VendorFields map[string][]byte
}

// KeyMetadataAdapter exposes token-specific key metadata resolution.
type KeyMetadataAdapter interface {
	// KeyMetadata returns best-effort normalized metadata for the specified slot.
	KeyMetadata(session *Session, slot piv.Slot) (KeyMetadata, error)
}

// SignAuthorization describes the normalized authorization decision for signing.
type SignAuthorization struct {
	Slot      piv.Slot
	PINPolicy PINPolicy
	Source    ResolutionSource
}

// IsKnown reports whether the authorization policy is known.
func (a SignAuthorization) IsKnown() bool {
	return a.PINPolicy != "" && a.PINPolicy != PINPolicyUnknown
}

// RequiresPIN reports whether the slot requires VERIFY PIN before signing.
func (a SignAuthorization) RequiresPIN() bool {
	return a.PINPolicy == PINPolicyOnce || a.PINPolicy == PINPolicyAlways
}

// CanSignWithoutPIN reports whether the slot can sign without VERIFY PIN.
func (a SignAuthorization) CanSignWithoutPIN() bool {
	return a.PINPolicy == PINPolicyNever
}

// NormalizeKeyAlgorithm maps a PIV algorithm identifier into a normalized key algorithm value.
func NormalizeKeyAlgorithm(value byte) KeyAlgorithm {
	switch value {
	case piv.AlgECCP256:
		return KeyAlgorithmECCP256
	case piv.AlgECCP384:
		return KeyAlgorithmECCP384
	case piv.AlgRSA1024:
		return KeyAlgorithmRSA1024
	case piv.AlgRSA2048:
		return KeyAlgorithmRSA2048
	default:
		return KeyAlgorithmUnknown
	}
}

// NormalizePINPolicy maps commonly used vendor PIN policy values to a normalized form.
func NormalizePINPolicy(value byte) PINPolicy {
	switch value {
	case 0x00:
		return PINPolicyNever
	case 0x01:
		return PINPolicyOnce
	case 0x02:
		return PINPolicyAlways
	default:
		return PINPolicyUnknown
	}
}

// NormalizeTouchPolicy maps commonly used touch policy values to a normalized form.
func NormalizeTouchPolicy(value byte) TouchPolicy {
	switch value {
	case 0x00:
		return TouchPolicyNever
	case 0x01:
		return TouchPolicyAlways
	case 0x02:
		return TouchPolicyCached
	default:
		return TouchPolicyUnknown
	}
}

// ResolveKeyMetadata returns best-effort normalized metadata for a resolved runtime and slot.
func ResolveKeyMetadata(runtime *Runtime, slot piv.Slot) (KeyMetadata, error) {
	if runtime == nil || runtime.Session == nil {
		return KeyMetadata{}, fmt.Errorf("adapters: session is required")
	}
	return ResolveKeyMetadataWithSession(runtime.Session, runtime.Adapter, slot)
}

// ResolveKeyMetadataWithSession returns best-effort normalized metadata for an explicit session and adapter pair.
func ResolveKeyMetadataWithSession(session *Session, adapter Adapter, slot piv.Slot) (KeyMetadata, error) {
	if err := requireSessionClient(session); err != nil {
		return KeyMetadata{}, err
	}
	if metadataAdapter, ok := adapter.(KeyMetadataAdapter); ok {
		session.Observe(LogLevelDebug, adapter, "resolve-key-metadata", "using adapter-specific key metadata for %s", slot)
		metadata, err := metadataAdapter.KeyMetadata(session, slot)
		if err != nil {
			return KeyMetadata{}, err
		}
		return normalizeResolvedMetadata(metadata, slot, ResolutionSourceVendorMetadata), nil
	}
	if adapter != nil {
		session.Observe(LogLevelDebug, adapter, "resolve-key-metadata", "adapter does not expose key metadata for %s; using fallback metadata", slot)
	} else {
		session.Observe(LogLevelDebug, adapter, "resolve-key-metadata", "no adapter matched selected reader; using fallback metadata for %s", slot)
	}
	return unknownKeyMetadata(slot), nil
}

// DeriveSignAuthorization builds a signing decision from best-effort key metadata.
func DeriveSignAuthorization(metadata KeyMetadata) SignAuthorization {
	policy := metadata.PINPolicy
	if policy == "" {
		policy = PINPolicyUnknown
	}
	source := metadata.Source
	if source == "" {
		source = ResolutionSourceUnknown
	}
	return SignAuthorization{Slot: metadata.Slot, PINPolicy: policy, Source: source}
}

// ResolveSignAuthorization resolves best-effort key metadata and derives a signing decision from it.
func ResolveSignAuthorization(runtime *Runtime, slot piv.Slot) (SignAuthorization, error) {
	metadata, err := ResolveKeyMetadata(runtime, slot)
	if err != nil {
		return SignAuthorization{}, err
	}
	return DeriveSignAuthorization(metadata), nil
}

func normalizeResolvedMetadata(metadata KeyMetadata, slot piv.Slot, defaultSource ResolutionSource) KeyMetadata {
	metadata.Slot = slot
	if metadata.Algorithm == "" {
		metadata.Algorithm = KeyAlgorithmUnknown
	}
	if metadata.PINPolicy == "" {
		metadata.PINPolicy = PINPolicyUnknown
	}
	if metadata.TouchPolicy == "" {
		metadata.TouchPolicy = TouchPolicyUnknown
	}
	if metadata.Source == "" {
		metadata.Source = defaultSource
	}
	if len(metadata.VendorFields) != 0 {
		metadata.VendorFields = cloneVendorFields(metadata.VendorFields)
	}
	return metadata
}

func unknownKeyMetadata(slot piv.Slot) KeyMetadata {
	return KeyMetadata{
		Slot:        slot,
		Algorithm:   KeyAlgorithmUnknown,
		PINPolicy:   PINPolicyUnknown,
		TouchPolicy: TouchPolicyUnknown,
		Source:      ResolutionSourceFallback,
	}
}

func cloneVendorFields(values map[string][]byte) map[string][]byte {
	clone := make(map[string][]byte, len(values))
	for key, value := range values {
		clone[key] = append([]byte(nil), value...)
	}
	return clone
}
