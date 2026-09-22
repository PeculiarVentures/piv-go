package yubikey

import (
	"fmt"

	"github.com/PeculiarVentures/piv-go/adapters"
	"github.com/PeculiarVentures/piv-go/piv"
)

// ReadCertificate reads a certificate from the slot using the standard PIV object.
//
// The YubiKey attestation slot (0xF9) is served from the vendor attestation
// object (0x5FFF01) holding the long-lived attestation certificate.
func (a *Adapter) ReadCertificate(session *adapters.Session, slot piv.Slot) ([]byte, error) {
	if err := requireSessionClient(session); err != nil {
		return nil, err
	}
	if slot == SlotAttestation {
		return a.AttestationCertificate(session)
	}
	return session.Client.ReadCertificate(slot)
}

// PutCertificate writes a certificate to the slot using the standard PIV object.
func (a *Adapter) PutCertificate(session *adapters.Session, slot piv.Slot, certData []byte) error {
	if err := requireSessionClient(session); err != nil {
		return err
	}
	if err := session.AuthenticateManagementKey(a); err != nil {
		return fmt.Errorf("authenticate management key: %w", err)
	}
	return session.Client.PutCertificate(slot, certData)
}

// DeleteCertificate removes a certificate from the slot using the standard PIV object.
func (a *Adapter) DeleteCertificate(session *adapters.Session, slot piv.Slot) error {
	if err := requireSessionClient(session); err != nil {
		return err
	}
	if err := session.AuthenticateManagementKey(a); err != nil {
		return fmt.Errorf("authenticate management key: %w", err)
	}
	return session.Client.DeleteCertificate(slot)
}
