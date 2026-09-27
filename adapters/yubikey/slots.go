package yubikey

import (
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
	metadataUnavailable := metaErr != nil && !isNotFound(metaErr)
	switch {
	case metaErr == nil && metadata.PublicKey != nil:
		session.Observe(adapters.LogLevelDebug, a, "describe-slot", "using YubiKey metadata to mark public key presence for %s", slot)
		description.SetKeyState(adapters.SlotStatePresent, nil)
		description.PublicKey = metadata.PublicKey
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
		// Without slot metadata (for example YubiKey NEO with 6D00/6E00,
		// or a transport failure) an empty key view is ambiguous: the
		// certificate and the public key share one slot object, so a
		// private key may exist while nothing is observable.
		if description.KeyState != adapters.SlotStatePresent && description.KeyState != adapters.SlotStateError {
			if iso7816.IsStatus(metaErr, iso7816.SwInsNotSupported) || iso7816.IsStatus(metaErr, iso7816.SwClaNotSupported) {
				description.SetKeyState(adapters.SlotStateUnknown, nil)
			} else {
				description.SetKeyState(adapters.SlotStateError, metaErr)
			}
		}
	}

	if metaErr == nil {
		normalized := keyMetadataForSlot(slot, metadata)
		description.Metadata = &normalized
	}

	// Without slot metadata (for example YubiKey NEO) an empty key view is
	// ambiguous: the certificate and the public key share one slot object,
	// so a private key may exist while nothing is observable. Surface the
	// guidance in the operation trace where blind-slot diagnosis happens.
	if metadataUnavailable && !description.KeyPresent {
		session.Observe(adapters.LogLevelDebug, a, "describe-slot", "NEO shares certificate and public-key object without GET METADATA; re-import key or certificate to restore view for %s", slot)
	}

	return description, nil
}

// isNotFound reports a definitive empty-slot status from GET_METADATA:
// 6A82 (file not found) or 6A88 (referenced data not found, the empty-slot
// signal used by yubikit _list_keys). All other errors leave the state
// unknown.
func isNotFound(err error) bool {
	return iso7816.IsStatus(err, iso7816.SwFileNotFound) ||
		iso7816.IsStatus(err, iso7816.SwReferencedDataNotFound)
}
