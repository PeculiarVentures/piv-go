package safenet

import (
	"fmt"

	"github.com/PeculiarVentures/piv-go/adapters"
	"github.com/PeculiarVentures/piv-go/iso7816"
	"github.com/PeculiarVentures/piv-go/piv"
)

// ResetSlot clears the SafeNet generation and mirror objects for the specified slot.
func (a *Adapter) ResetSlot(session *adapters.Session, slot piv.Slot) error {
	session.Observe(adapters.LogLevelInfo, a, "reset-slot", "starting SafeNet slot reset for %s", slot)
	if err := session.AuthenticateManagementKey(a); err != nil {
		return fmt.Errorf("authenticate management key: %w", err)
	}
	if err := selectAdminApplet(session.Client); err != nil {
		return err
	}
	if err := readVersion(session.Client); err != nil {
		return err
	}
	session.Observe(adapters.LogLevelDebug, a, "reset-slot", "clearing SafeNet objects for slot %s", slot)
	return a.resetSlot(session.Client, slot)
}

// DescribeReset reports the SafeNet reset policy requirements.
func (a *Adapter) DescribeReset(session *adapters.Session) (adapters.ResetRequirements, error) {
	if err := requireSession(session); err != nil {
		return adapters.ResetRequirements{}, err
	}
	return adapters.ResetRequirements{
		RequiresPUK: true,
		Fields: []adapters.InitializationField{{
			Name:        "puk",
			Label:       "PUK",
			Description: "Current PUK required to validate and perform SafeNet token reset",
			Secret:      true,
			Required:    true,
		}},
	}, nil
}

// ResetToken clears SafeNet vendor objects and restores the default
// management key so the token can be reinitialized with factory credentials.
func (a *Adapter) ResetToken(session *adapters.Session, params adapters.ResetTokenParams) error {
	if params.PUK == "" {
		return fmt.Errorf("safenet: PUK is required for token reset")
	}
	session.Observe(adapters.LogLevelInfo, a, "reset-token", "starting SafeNet token reset")
	if err := session.AuthenticateManagementKey(a); err != nil {
		return fmt.Errorf("authenticate management key: %w", err)
	}
	if err := selectAdminApplet(session.Client); err != nil {
		return err
	}
	if err := readVersion(session.Client); err != nil {
		return err
	}

	structure, err := a.determineTokenStructure(session)
	if err != nil {
		return err
	}
	session.Observe(adapters.LogLevelDebug, a, "reset-token", "clearing vendor containers")
	if err := a.clearContainers(session, structure, nil); err != nil {
		return err
	}

	for _, object := range piv.KnownObjects() {
		session.Observe(adapters.LogLevelDebug, a, "reset-token", "clearing PIV data object %06X", object.Tag)
		if err := clearSafeNetObject(session.Client, object.Tag, iso7816.EncodeTLV(0x53, nil)); err != nil {
			return fmt.Errorf("reset PIV data object %X: %w", object.Tag, err)
		}
	}

	if err := readResetCredentialMetadata(session.Client); err != nil {
		return err
	}

	session.Observe(adapters.LogLevelDebug, a, "reset-token", "restoring default PIN")
	if err := session.Client.UnblockPIN(params.PUK, defaultPIN); err != nil {
		return fmt.Errorf("restore default PIN with provided PUK: %w", err)
	}

	session.Observe(adapters.LogLevelDebug, a, "reset-token", "restoring default PUK")
	if err := session.Client.ChangePUK(params.PUK, defaultPUK); err != nil {
		return fmt.Errorf("restore default PUK: %w", err)
	}

	session.Observe(adapters.LogLevelDebug, a, "reset-token", "restoring default management key")
	if err := a.ChangeManagementKey(session, piv.AlgAES128, defaultManagementKey); err != nil {
		return fmt.Errorf("restore default management key: %w", err)
	}

	session.Observe(adapters.LogLevelInfo, a, "reset-token", "completed SafeNet token reset")
	return nil
}
