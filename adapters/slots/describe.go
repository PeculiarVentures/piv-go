package slots

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"fmt"

	"github.com/PeculiarVentures/piv-go/adapters"
	"github.com/PeculiarVentures/piv-go/iso7816"
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
		case bits <= 3072:
			return "rsa3072"
		case bits <= 4096:
			return "rsa4096"
		default:
			return fmt.Sprintf("rsa%d", bits)
		}
	case *piv.OpaquePublicKey:
		return opaquePublicKeyAlgorithmName(key.Algorithm, publicKey)
	case piv.OpaquePublicKey:
		return opaquePublicKeyAlgorithmName(key.Algorithm, publicKey)
	default:
		return fmt.Sprintf("%T", publicKey)
	}
}

// opaquePublicKeyAlgorithmName resolves the display name of a YubiKey 6
// opaque public key from its algorithm identifier.
func opaquePublicKeyAlgorithmName(algorithm byte, publicKey crypto.PublicKey) string {
	if name := adapters.NormalizeKeyAlgorithm(algorithm); name != adapters.KeyAlgorithmUnknown {
		return string(name)
	}
	return fmt.Sprintf("%T", publicKey)
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
	switch {
	case keyErr == nil:
		description.KeyPresent = true
		description.KeyAlgorithm = PublicKeyAlgorithmName(publicKey)
		description.PublicKey = publicKey
	case isKeyNotFound(keyErr):
		// A 6A82/6A88 status definitively reports the key absent.
	default:
		// The key read failed without a definitive not-found status, so
		// absence cannot be confirmed. Surface unknown instead of absent
		// and keep the error for callers.
		description.KeyPresent = false
		description.KeyUnknown = true
		description.KeyError = keyErr
	}

	certData, certErr := session.Client.ReadCertificate(slot)
	switch {
	case certErr == nil:
		description.CertDER = certData
		cert, err := x509.ParseCertificate(certData)
		if err == nil {
			description.CertPresent = true
			description.CertLabel = CertificateSummary(cert)
		} else {
			// The slot object decoded but its payload is not an X.509
			// certificate: keep the raw certificate bytes and expose the
			// parse failure instead of reporting an absent certificate.
			description.CertPresent = false
			description.CertError = err
		}
	case isKeyNotFound(certErr):
		// A 6A82/6A88 status definitively reports the certificate absent.
	default:
		description.CertUnknown = true
		description.CertError = certErr
	}

	return description, nil
}

// isKeyNotFound reports whether an object read failure definitively means
// the object is absent: only a 6A82/6A88 status. Object structure errors
// (for example a 9000 response carrying a malformed object without tag
// 0x53) leave the state unknown: the card answered, but the content cannot
// be interpreted as either present or absent. It is used for both the key
// and the certificate object reads.
func isKeyNotFound(err error) bool {
	if err == nil {
		return false
	}
	return iso7816.IsStatus(err, iso7816.SwFileNotFound) || iso7816.IsStatus(err, iso7816.SwReferencedDataNotFound)
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
