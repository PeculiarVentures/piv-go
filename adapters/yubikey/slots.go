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
		description.KeyPresent = true
		description.KeyUnknown = false
		description.KeyError = nil
		description.PublicKey = metadata.PublicKey
		description.KeyAlgorithm = adapterslots.PublicKeyAlgorithmName(metadata.PublicKey)
	case metaErr == nil:
		// Metadata read succeeded but carries no public key: the slot is
		// empty per metadata, so keep the standard view as-is. A standard
		// not-found stays definitely absent; a standard unknown stays
		// unknown. A standard present stays present.
		if description.KeyPresent {
			description.KeyUnknown = false
			description.KeyError = nil
		}
	case isNotFound(metaErr):
		// GET_METADATA reports the slot itself as empty (6A82/6A88),
		// which is authoritative absence: clear any unknown carried
		// from the standard view unless a key object was observed.
		if !description.KeyPresent {
			description.KeyPresent = false
			description.KeyError = nil
		}
		description.KeyUnknown = false
	default:
		// Without slot metadata (for example YubiKey NEO with 6D00/6E00,
		// or a transport failure) an empty key view is ambiguous: the
		// certificate and the public key share one slot object, so a
		// private key may exist while nothing is observable.
		if description.KeyPresent {
			description.KeyUnknown = false
			description.KeyError = nil
		} else {
			description.KeyPresent = false
			description.KeyUnknown = true
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
