package adapters

import (
	"crypto"

	"github.com/PeculiarVentures/piv-go/piv"
)

// SlotState describes presence, absence, an unobservable state, or a read error.
type SlotState string

const (
	SlotStatePresent SlotState = "present"
	SlotStateAbsent  SlotState = "absent"
	SlotStateUnknown SlotState = "unknown"
	SlotStateError   SlotState = "error"
)

// KeyUnknownReason explains a private-key state that cannot be established
// through passive inspection. An empty reason means the key state is known or
// the read failed; failures are reported by SlotStateError and KeyError.
type KeyUnknownReason string

const (
	// KeyUnknownReasonUnobservable means the available public objects and
	// metadata cannot establish whether a private key occupies the slot.
	KeyUnknownReasonUnobservable KeyUnknownReason = "unobservable"
)

// PublicKeySource identifies the object from which a public key was read.
// Stored templates and certificates are writable public copies and may not
// match the private key currently occupying the slot.
type PublicKeySource string

const (
	PublicKeySourceMetadata       PublicKeySource = "metadata"
	PublicKeySourceStoredTemplate PublicKeySource = "stored_template"
	PublicKeySourceCertificate    PublicKeySource = "certificate"
)

// SlotDescription summarizes the observable state of a PIV slot.
//
// One DescribeSlot call reads each physical data object at most once, so all
// fields describe a single pass over the slot. Read and parse failures are
// exposed through the matching *Error field alongside successful values.
// KeyState describes the adapter's evidence of a private key. Standard PIV
// GET DATA exposes public storage only, so neither a readable nor a missing
// object establishes private-key presence or absence. PublicKey can be known
// while KeyState is unknown.
type SlotDescription struct {
	KeyState   SlotState
	KeyPresent bool
	// KeyUnknownReason describes a successful but private-key-blind read.
	// It is empty for known states and read or parse errors.
	KeyUnknownReason KeyUnknownReason
	// KeyUnknown reports that private-key presence or absence is unknown.
	// GET DATA not-found and empty objects are unknown without authoritative
	// vendor metadata, as are ambiguous read failures.
	// Deletion success is confirmed separately by the delete operation.
	KeyUnknown   bool
	KeyAlgorithm string
	// KeyError carries the error that prevented interpretation of a key read.
	// It is nil for an unevidenced private key with otherwise valid storage.
	KeyError error
	// PublicKey is the parsed public material, independent of private-key state.
	PublicKey crypto.PublicKey
	// PublicKeySource is empty when no public key could be read. Callers must
	// inspect KeyState separately before asserting private-key presence.
	PublicKeySource PublicKeySource
	CertState       SlotState
	CertPresent     bool
	CertLabel       string
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

// SetKeyState updates the typed state and its legacy flags together.
func (d *SlotDescription) SetKeyState(state SlotState, err error) {
	d.KeyState = state
	d.KeyPresent = state == SlotStatePresent
	d.KeyUnknown = state == SlotStateUnknown || state == SlotStateError
	d.KeyError = err
	d.KeyUnknownReason = ""
}

// SetCertState updates the typed state and its legacy flags together.
func (d *SlotDescription) SetCertState(state SlotState, err error) {
	d.CertState = state
	d.CertPresent = state == SlotStatePresent
	d.CertUnknown = state == SlotStateUnknown || state == SlotStateError && len(d.CertDER) == 0
	d.CertError = err
}

// SlotInspector defines adapter-specific slot inspection behavior.
type SlotInspector interface {
	// DescribeSlot returns the current state of the specified slot.
	DescribeSlot(session *Session, slot piv.Slot) (SlotDescription, error)
}
