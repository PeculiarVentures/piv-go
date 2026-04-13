package adapters

import (
	"fmt"

	"github.com/PeculiarVentures/piv-go/piv"
)

// PINStatus aliases the standard PIV PIN status model used by adapter helpers.
type PINStatus = piv.PINStatus

// PINAdapter exposes token-specific status handling for card PIN references.
type PINAdapter interface {
	// PINStatus reports the current state of the specified PIN reference.
	PINStatus(session *Session, pinType piv.PINType) (PINStatus, error)
}

// CredentialAdapter exposes administrative credential rotation flows.
type CredentialAdapter interface {
	// ChangePIN rotates the cardholder PIN.
	ChangePIN(session *Session, oldPIN string, newPIN string) error
	// ChangePUK rotates the PUK.
	ChangePUK(session *Session, oldPUK string, newPUK string) error
	// ChangeManagementKey rotates the management key using the session's current
	// management credentials and the new key material.
	ChangeManagementKey(session *Session, newAlgorithm byte, newKey []byte) error
}

// ManagementKeyAlgorithmAdapter resolves the algorithm used for ambiguous
// management key encodings such as 24-byte YubiKey management keys.
type ManagementKeyAlgorithmAdapter interface {
	// ManagementKeyAlgorithm returns the management key algorithm to use for the
	// provided key material.
	ManagementKeyAlgorithm(session *Session, key []byte) (byte, error)
}

// PINRecoveryAdapter exposes PIN recovery using the PUK.
type PINRecoveryAdapter interface {
	// UnblockPIN resets the PIN retry counter and installs a new PIN.
	UnblockPIN(session *Session, puk string, newPIN string) error
}

// ResetAdapter exposes destructive reset operations.
type ResetAdapter interface {
	// ResetSlot clears vendor-specific state associated with a slot.
	ResetSlot(session *Session, slot piv.Slot) error
	// DescribeReset returns the reset policy requirements for the token.
	DescribeReset(session *Session) (ResetRequirements, error)
	// ResetToken resets the selected PIV application using adapter-specific parameters.
	ResetToken(session *Session, params ResetTokenParams) error
}

// ResetRequirements describes the policy requirements for a token reset flow.
type ResetRequirements struct {
	// RequiresPUK reports whether the reset flow requires a PUK value.
	RequiresPUK bool
	// Fields describes the credential inputs required by the reset flow.
	Fields []InitializationField
}

// ResetTokenParams carries token reset input values.
type ResetTokenParams struct {
	// PUK is the current PUK value used by tokens that require it for reset.
	PUK string
}

// ResolveManagementKeyAlgorithm determines the algorithm to use for the
// provided management key material, consulting the adapter when the key length
// is ambiguous.
func ResolveManagementKeyAlgorithm(session *Session, adapter Adapter, key []byte) (byte, error) {
	switch len(key) {
	case 16:
		return piv.AlgAES128, nil
	case 24:
		if algorithmAdapter, ok := adapter.(ManagementKeyAlgorithmAdapter); ok {
			algorithm, err := algorithmAdapter.ManagementKeyAlgorithm(session, key)
			if err != nil {
				return 0, err
			}
			if algorithm != 0 {
				return algorithm, nil
			}
		}
		return piv.Alg3DES, nil
	case 32:
		return piv.AlgAES256, nil
	default:
		return 0, fmt.Errorf("unsupported management key length %d", len(key))
	}
}
