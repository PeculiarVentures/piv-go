// Package adapters provides vendor-specific adapters for PIV-compatible tokens.
//
// Each vendor sub-package implements the Adapter interface to handle
// vendor-specific APDU quirks, algorithm support, PIN policies, and
// extended features beyond the standard PIV specification.
package adapters

import (
	"crypto"

	"github.com/PeculiarVentures/piv-go/piv"
)

// Adapter defines the base contract for vendor-specific token behavior.
//
// Implementations identify themselves by reader name and may extend the
// standard PIV lifecycle with additional capability interfaces defined in this
// package.
type Adapter interface {
	// Name returns the adapter name.
	Name() string

	// MatchReader reports whether the adapter should handle the specified reader.
	MatchReader(readerName string) bool
}

// KeyGenerationAdapter defines hooks around device-specific key generation.
//
// The standard PIV key generation flow remains in piv.Client.GenerateKeyPair.
// Adapters use this capability to prepare vendor state before the standard
// command runs and to persist vendor-specific metadata after the key pair has
// been generated.
type KeyGenerationAdapter interface {
	// PrepareGenerateKey performs any vendor-specific setup required before the
	// standard key generation command is executed.
	PrepareGenerateKey(session *Session, slot piv.Slot, algorithm byte) error
	// FinalizeGenerateKey persists vendor-specific metadata after the standard
	// key generation command succeeds.
	FinalizeGenerateKey(session *Session, slot piv.Slot, algorithm byte, publicKey crypto.PublicKey) error
}

// KeyDeletionAdapter defines device-specific key deletion behavior.
//
// Tokens that can delete slot keys outside the baseline PIV object lifecycle
// implement this capability to encapsulate the required APDU sequence.
type KeyDeletionAdapter interface {
	// DeleteKey removes the key and any device-specific metadata associated with
	// the specified slot.
	DeleteKey(session *Session, slot piv.Slot) error
}

// CertificateAdapter defines device-specific certificate lifecycle overrides.
//
// The standard certificate lifecycle lives in piv.Client.ReadCertificate,
// piv.Client.ReadPublicKey, piv.Client.PutCertificate, and
// piv.Client.DeleteCertificate. Adapters implement this capability when a token
// stores certificates or public key material in vendor-specific objects in
// addition to, or instead of, the standard PIV slot object.
type CertificateAdapter interface {
	// ReadCertificate returns the raw certificate bytes for the specified slot.
	ReadCertificate(session *Session, slot piv.Slot) ([]byte, error)
	// ReadPublicKey returns the public key material associated with the slot.
	ReadPublicKey(session *Session, slot piv.Slot) (crypto.PublicKey, error)
	// PutCertificate stores the certificate bytes for the specified slot.
	PutCertificate(session *Session, slot piv.Slot, certData []byte) error
	// DeleteCertificate removes the certificate while preserving any
	// vendor-specific slot state required by the token.
	DeleteCertificate(session *Session, slot piv.Slot) error
}

// SerialNumberAdapter defines vendor-specific serial number retrieval.
//
// Some tokens expose a vendor command for serial number lookup that is not
// available through the standard PIV object model.
type SerialNumberAdapter interface {
	// SerialNumber returns the token serial number.
	SerialNumber(session *Session) ([]byte, error)
}

// CHUIDAdapter defines vendor-specific CHUID retrieval.
//
// Some tokens store or expose the CHUID object through non-standard PIV
// object tags, so adapters may implement a vendor-specific lookup.
type CHUIDAdapter interface {
	// CHUID returns the CHUID object bytes.
	CHUID(session *Session) ([]byte, error)
}

// LabelAdapter defines vendor-specific token label retrieval.
//
// Some tokens expose a vendor-specific label or product name that is not
// available through the standard PIV object model.
type LabelAdapter interface {
	// Label returns the token label or vendor-assigned token name.
	Label(session *Session) (string, error)
}
