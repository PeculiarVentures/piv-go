package yubikey

import (
	"errors"

	"github.com/PeculiarVentures/piv-go/adapters"
	adapterslots "github.com/PeculiarVentures/piv-go/adapters/slots"
	"github.com/PeculiarVentures/piv-go/iso7816"
	"github.com/PeculiarVentures/piv-go/piv"
)

// DescribeSlot uses YubiKey slot metadata to detect keys even when no standard
// public key object has been written to the slot object. The standard
// description is read once (key and certificate objects in one pass) and the
// vendor metadata is read once; successful values and errors are merged into
// the returned description without repeated reads.
func (a *Adapter) DescribeSlot(session *adapters.Session, slot piv.Slot) (adapters.SlotDescription, error) {
	description, err := adapterslots.DescribeSlotWithSession(session, nil, slot)
	if err != nil {
		return adapters.SlotDescription{}, err
	}

	session.Observe(adapters.LogLevelDebug, a, "describe-slot", "reading YubiKey slot metadata for %s", slot)
	metadata, metaErr := readSlotMetadata(session.Client, slot)
	metadataUnsupported := isMetadataUnsupported(metaErr)
	switch {
	case metaErr == nil && metadata.PublicKey != nil:
		session.Observe(adapters.LogLevelDebug, a, "describe-slot", "using YubiKey metadata to mark public key presence for %s", slot)
		description.SetKeyState(adapters.SlotStatePresent, nil)
		description.PublicKey = metadata.PublicKey
		description.PublicKeySource = adapters.PublicKeySourceMetadata
		description.KeyAlgorithm = adapterslots.PublicKeyAlgorithmName(metadata.PublicKey)
	case metaErr == nil:
		// A successful slot metadata response establishes a key even when
		// this firmware omits the public-key field. Retain any public key
		// parsed from the slot object or its certificate.
		description.SetKeyState(adapters.SlotStatePresent, nil)
	case isNotFound(metaErr):
		// GET_METADATA reports the private-key slot itself as empty.
		description.SetKeyState(adapters.SlotStateAbsent, nil)
	default:
		if metadataUnsupported {
			// NEO cannot report private-key metadata. Public storage remains
			// useful, but cannot establish the current private-key state.
			if description.KeyState == adapters.SlotStateUnknown {
				description.KeyUnknownReason = adapters.KeyUnknownReasonUnobservable
			}
		} else {
			// A transient GET METADATA failure prevents proof of private-key
			// presence even if 7F49 supplied a valid public key. Keep that
			// public key and any independent certificate observation.
			description.SetKeyState(adapters.SlotStateError, errors.Join(description.KeyError, metaErr))
		}
	}

	if metaErr == nil {
		normalized := keyMetadataForSlot(slot, metadata)
		description.Metadata = &normalized
	}

	if metadataUnsupported && description.KeyState == adapters.SlotStateUnknown {
		session.Observe(adapters.LogLevelDebug, a, "describe-slot", "GET METADATA is unsupported; public storage cannot establish private-key presence for %s", slot)
	}

	return description, nil
}

// isNotFound reports a definitive empty-slot status from GET_METADATA:
// 6A82 (file not found) or 6A88 (referenced data not found, the empty-slot
// signal used by yubikit _list_keys). Unsupported metadata permits a
// public-object fallback; other failures are exposed as SlotStateError.
func isNotFound(err error) bool {
	return iso7816.IsStatus(err, iso7816.SwFileNotFound) ||
		iso7816.IsStatus(err, iso7816.SwReferencedDataNotFound)
}
