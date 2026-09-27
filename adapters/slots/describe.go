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
	tag, err := piv.ObjectIDForSlot(slot)
	if err != nil {
		return adapters.SlotDescription{}, err
	}
	data, readErr := session.Client.GetData(tag)
	return DescribeDataObject(data, readErr), nil
}

// DescribeDataObject interprets one GET DATA response as both the stored key
// and certificate view. It is also used for vendor mirror objects.
func DescribeDataObject(data []byte, readErr error) adapters.SlotDescription {
	d := adapters.SlotDescription{KeyAlgorithm: "-", CertLabel: "-"}
	if readErr != nil {
		if isKeyNotFound(readErr) {
			// GET DATA reports public object storage, not the private-key
			// slot. A missing object cannot prove that the key is absent.
			d.SetKeyState(adapters.SlotStateUnknown, nil)
			d.SetCertState(adapters.SlotStateAbsent, nil)
		} else {
			d.SetKeyState(adapters.SlotStateError, readErr)
			d.SetCertState(adapters.SlotStateError, readErr)
		}
		return d
	}
	outer, err := iso7816.ParseAllTLV(data)
	if err == nil && len(outer) == 1 && outer[0].Tag == 0x53 {
		var inner []*iso7816.TLV
		inner, err = iso7816.ParseAllTLV(outer[0].Value)
		if err == nil {
			var keyTLV, certTLV *iso7816.TLV
			for _, tlv := range inner {
				switch tlv.Tag {
				case 0x7F49:
					if keyTLV != nil {
						err = fmt.Errorf("piv: duplicate public key tag 0x7F49")
					}
					keyTLV = tlv
				case 0x70:
					if certTLV != nil {
						err = fmt.Errorf("piv: duplicate certificate tag 0x70")
					}
					certTLV = tlv
				case 0x71, 0xFE:
				default:
					err = fmt.Errorf("piv: unsupported slot object tag 0x%X", tlv.Tag)
				}
			}
			if err == nil {
				if keyTLV == nil {
					// Even an empty 53 proves only that public storage is
					// empty. A private key may still occupy the slot.
					d.SetKeyState(adapters.SlotStateUnknown, nil)
				} else {
					key, keyErr := piv.ParsePublicKeyObject(data)
					if keyErr != nil {
						d.SetKeyState(adapters.SlotStateError, keyErr)
					} else {
						d.SetKeyState(adapters.SlotStatePresent, nil)
						d.PublicKey = key
						d.KeyAlgorithm = PublicKeyAlgorithmName(key)
					}
				}
				if certTLV == nil {
					d.SetCertState(adapters.SlotStateAbsent, nil)
				} else {
					d.CertDER = append([]byte(nil), certTLV.Value...)
					certKey, certLabel, certErr := certificatePublicKeyAndLabel(d.CertDER)
					if certErr != nil {
						d.SetCertState(adapters.SlotStateError, certErr)
					} else {
						d.SetCertState(adapters.SlotStatePresent, nil)
						d.CertLabel = certLabel
						if d.PublicKey == nil {
							d.PublicKey = certKey
							d.KeyAlgorithm = PublicKeyAlgorithmName(certKey)
						}
					}
				}
				return d
			}
		}
	}
	if err == nil {
		err = fmt.Errorf("piv: expected one slot data object tag 0x53")
	}
	d.SetKeyState(adapters.SlotStateError, err)
	d.SetCertState(adapters.SlotStateError, err)
	return d
}

func certificatePublicKeyAndLabel(der []byte) (crypto.PublicKey, string, error) {
	cert, x509Err := x509.ParseCertificate(der)
	if x509Err == nil && cert.PublicKey != nil {
		return cert.PublicKey, CertificateSummary(cert), nil
	}
	// Go's x509 parser may accept ML-DSA certificate structure while leaving
	// PublicKey nil. The algorithm-aware PIV parser recovers and validates it.
	pq, pqErr := piv.ParseMLDSACertificateDER(der)
	if pqErr == nil {
		label := "ML-DSA certificate"
		if cert != nil {
			label = CertificateSummary(cert)
		}
		return &piv.OpaquePublicKey{Algorithm: pq.Algorithm, Raw: append([]byte(nil), pq.PublicKey...)}, label, nil
	}
	if x509Err != nil {
		return nil, "", x509Err
	}
	return nil, "", fmt.Errorf("piv: unsupported certificate public key")
}

// isKeyNotFound identifies 6A82/6A88 GET DATA statuses. They prove public
// object absence, but cannot establish private-key absence.
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
