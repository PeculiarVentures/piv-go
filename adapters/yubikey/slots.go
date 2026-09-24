package yubikey

import (
	"crypto/x509"

	"github.com/PeculiarVentures/piv-go/adapters"
	adapterslots "github.com/PeculiarVentures/piv-go/adapters/slots"
	"github.com/PeculiarVentures/piv-go/piv"
)

// DescribeSlot uses YubiKey slot metadata to detect keys even when no standard
// public key object has been written to the slot object.
func (a *Adapter) DescribeSlot(session *adapters.Session, slot piv.Slot) (adapters.SlotDescription, error) {
	description, err := adapterslots.DescribeSlotWithSession(session, nil, slot)
	if err != nil {
		return adapters.SlotDescription{}, err
	}

	session.Observe(adapters.LogLevelDebug, a, "describe-slot", "reading YubiKey slot metadata for %s", slot)
	metadata, err := readSlotMetadata(session.Client, slot)
	metadataUnavailable := err != nil
	if err == nil && metadata.PublicKey != nil {
		session.Observe(adapters.LogLevelDebug, a, "describe-slot", "using YubiKey metadata to mark public key presence for %s", slot)
		description.KeyPresent = true
		description.KeyAlgorithm = adapterslots.PublicKeyAlgorithmName(metadata.PublicKey)
	}

	if certData, err := session.Client.ReadCertificate(slot); err == nil {
		if cert, parseErr := x509.ParseCertificate(certData); parseErr == nil {
			description.CertPresent = true
			description.CertLabel = adapterslots.CertificateSummary(cert)
		}
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
