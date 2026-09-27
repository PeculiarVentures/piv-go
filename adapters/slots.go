package adapters

import (
	"crypto"

	"github.com/PeculiarVentures/piv-go/piv"
)

// SlotDescription summarizes the observable state of a PIV slot.
//
// One DescribeSlot call performs at most one key read, one certificate read
// and one metadata read, so all fields describe a single pass over the slot.
// Read and parse failures are exposed through the matching *Error field with
// the successful values kept alongside them instead of being swallowed.
type SlotDescription struct {
	KeyPresent bool
	// KeyUnknown reports that key absence could not be confirmed: the
	// public-key read failed with an ambiguous error (transport failure,
	// unsupported instruction, unparsable object) rather than a definitive
	// not-found status. Callers should treat KeyPresent=false with
	// KeyUnknown=true as "state unknown", not "key definitely absent".
	// Deletion success is confirmed separately by the delete operation.
	KeyUnknown   bool
	KeyAlgorithm string
	// KeyError carries the error that prevented a definitive key read when
	// KeyUnknown is true. It is nil when the key read succeeded or the key
	// was definitively absent.
	KeyError error
	// PublicKey is the parsed public key when the key read succeeded.
	PublicKey   crypto.PublicKey
	CertPresent bool
	CertLabel   string
	// CertUnknown reports that certificate absence could not be confirmed:
	// the certificate read failed with an ambiguous error rather than a
	// definitive not-found status. CertError carries that error.
	CertUnknown bool
	// CertDER is the certificate payload read from the slot. It is kept
	// even when x509 parsing fails, with CertError carrying the failure.
	CertDER []byte
	// CertError carries a certificate read or parse error. It is nil when
	// the certificate parsed successfully or was definitively absent.
	CertError error
	// Metadata carries the normalized vendor metadata when the adapter
	// could read it; nil when metadata is unavailable for the slot.
	Metadata *KeyMetadata
}

// SlotInspector defines adapter-specific slot inspection behavior.
type SlotInspector interface {
	// DescribeSlot returns the current state of the specified slot.
	DescribeSlot(session *Session, slot piv.Slot) (SlotDescription, error)
}
