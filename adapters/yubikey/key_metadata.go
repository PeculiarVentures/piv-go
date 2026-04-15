package yubikey

import (
	"github.com/PeculiarVentures/piv-go/adapters"
	"github.com/PeculiarVentures/piv-go/piv"
)

// KeyMetadata returns best-effort normalized YubiKey key metadata for one slot.
func (a *Adapter) KeyMetadata(session *adapters.Session, slot piv.Slot) (adapters.KeyMetadata, error) {
	if err := requireSessionClient(session); err != nil {
		return adapters.KeyMetadata{}, err
	}

	session.Observe(adapters.LogLevelDebug, a, "resolve-key-metadata", "reading YubiKey slot metadata for %s", slot)
	metadata, err := readSlotMetadata(session.Client, slot)
	if err != nil {
		session.Observe(adapters.LogLevelDebug, a, "resolve-key-metadata", "YubiKey slot metadata unavailable for %s; using fallback metadata", slot)
		return adapters.KeyMetadata{
			Slot:        slot,
			Algorithm:   adapters.KeyAlgorithmUnknown,
			PINPolicy:   adapters.PINPolicyUnknown,
			TouchPolicy: adapters.TouchPolicyUnknown,
			Source:      adapters.ResolutionSourceFallback,
		}, nil
	}

	vendorFields := map[string][]byte{
		"yubikey/algorithm-raw":    {metadata.Algorithm},
		"yubikey/pin-policy-raw":   {metadata.PINPolicy},
		"yubikey/touch-policy-raw": {metadata.TouchPolicy},
	}
	if metadata.Generated {
		vendorFields["yubikey/generated"] = []byte{0x01}
	} else {
		vendorFields["yubikey/generated"] = []byte{0x00}
	}

	return adapters.KeyMetadata{
		Slot:         slot,
		Algorithm:    adapters.NormalizeKeyAlgorithm(metadata.Algorithm),
		PINPolicy:    normalizeYubiKeyPINPolicy(metadata.PINPolicy),
		TouchPolicy:  normalizeYubiKeyTouchPolicy(metadata.TouchPolicy),
		Source:       adapters.ResolutionSourceVendorMetadata,
		VendorFields: vendorFields,
	}, nil
}

func normalizeYubiKeyPINPolicy(value byte) adapters.PINPolicy {
	switch value {
	case 0x01:
		return adapters.PINPolicyNever
	case 0x02:
		return adapters.PINPolicyOnce
	case 0x03:
		return adapters.PINPolicyAlways
	default:
		return adapters.PINPolicyUnknown
	}
}

func normalizeYubiKeyTouchPolicy(value byte) adapters.TouchPolicy {
	switch value {
	case 0x01:
		return adapters.TouchPolicyNever
	case 0x02:
		return adapters.TouchPolicyAlways
	case 0x03:
		return adapters.TouchPolicyCached
	default:
		return adapters.TouchPolicyUnknown
	}
}
