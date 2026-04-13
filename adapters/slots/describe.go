package slots

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"fmt"

	"github.com/PeculiarVentures/piv-go/adapters"
	"github.com/PeculiarVentures/piv-go/piv"
)

// DescribeSlot returns a slot description using either an adapter override or
// the standard PIV data objects.

func DescribeSlot(runtime *adapters.Runtime, slot piv.Slot) (adapters.SlotDescription, error) {
	if runtime == nil || runtime.Session == nil {
		return adapters.SlotDescription{}, fmt.Errorf("adapters: session is required")
	}
	return DescribeSlotWithSession(runtime.Session, runtime.Adapter, slot)
}

// DescribeSlotWithSession returns a slot description using an explicit session and adapter pair.
func DescribeSlotWithSession(session *adapters.Session, adapter adapters.Adapter, slot piv.Slot) (adapters.SlotDescription, error) {
	if inspector, ok := adapter.(adapters.SlotInspector); ok {
		session.Observe(adapters.LogLevelDebug, adapter, "describe-slot", "using adapter-specific slot inspection for %s", slot)
		return inspector.DescribeSlot(session, slot)
	}
	session.Observe(adapters.LogLevelDebug, adapter, "describe-slot", "falling back to standard slot inspection for %s", slot)
	return describeStandardSlot(session, slot)
}

// PublicKeyAlgorithmName returns a human-readable name for a public key.
func PublicKeyAlgorithmName(publicKey crypto.PublicKey) string {
	switch key := publicKey.(type) {
	case *ecdsa.PublicKey:
		switch key.Curve.Params().BitSize {
		case 256:
			return "eccp256"
		case 384:
			return "eccp384"
		default:
			return fmt.Sprintf("ecdsa-%d", key.Curve.Params().BitSize)
		}
	case *rsa.PublicKey:
		switch bits := key.N.BitLen(); {
		case bits <= 1024:
			return "rsa1024"
		case bits <= 2048:
			return "rsa2048"
		default:
			return fmt.Sprintf("rsa%d", bits)
		}
	default:
		return fmt.Sprintf("%T", publicKey)
	}
}

// CertificateSummary returns a compact label for a parsed certificate.
func CertificateSummary(cert *x509.Certificate) string {
	if cert.Subject.CommonName != "" {
		return fmt.Sprintf("CN=%s", cert.Subject.CommonName)
	}
	if subject := cert.Subject.String(); subject != "" {
		return subject
	}
	return cert.SerialNumber.Text(16)
}

func describeStandardSlot(session *adapters.Session, slot piv.Slot) (adapters.SlotDescription, error) {
	if err := requireSessionClient(session); err != nil {
		return adapters.SlotDescription{}, err
	}

	description := adapters.SlotDescription{KeyAlgorithm: "-", CertLabel: "-"}

	publicKey, keyErr := session.Client.ReadPublicKey(slot)
	if keyErr == nil {
		description.KeyPresent = true
		description.KeyAlgorithm = PublicKeyAlgorithmName(publicKey)
	}

	certData, certErr := session.Client.ReadCertificate(slot)
	if certErr == nil {
		cert, err := x509.ParseCertificate(certData)
		if err == nil {
			description.CertPresent = true
			description.CertLabel = CertificateSummary(cert)
		}
	}

	return description, nil
}

func requireSessionClient(session *adapters.Session) error {
	if session == nil {
		return fmt.Errorf("adapters: nil session")
	}
	if session.Client == nil {
		return fmt.Errorf("adapters: session client is required")
	}
	return nil
}
