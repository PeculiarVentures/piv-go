package safenet

import (
	"crypto"
	"crypto/x509"
	"fmt"

	"github.com/PeculiarVentures/piv-go/adapters"
	adapterslots "github.com/PeculiarVentures/piv-go/adapters/slots"
	"github.com/PeculiarVentures/piv-go/iso7816"
	"github.com/PeculiarVentures/piv-go/piv"
)

// ReadCertificate reads a certificate from the SafeNet token.
// It prefers the standard PIV certificate object and falls back to the SafeNet
// mirror object only when the standard object is unavailable.
func (a *Adapter) ReadCertificate(session *adapters.Session, slot piv.Slot) ([]byte, error) {
	if err := requireSessionClient(session); err != nil {
		return nil, err
	}

	certData, err := session.Client.ReadCertificate(slot)
	if err == nil {
		session.Observe(adapters.LogLevelDebug, a, "read-certificate", "read standard certificate object for slot %s", slot)
		return certData, nil
	}
	session.Observe(adapters.LogLevelInfo, a, "read-certificate", "standard certificate object unavailable for slot %s, falling back to SafeNet mirror object", slot)

	tag, err := mirrorObjectTag(slot)
	if err != nil {
		return nil, err
	}
	data, err := session.Client.GetData(tag)
	if err != nil {
		return nil, fmt.Errorf("read SafeNet certificate for slot %s: %w", slot, err)
	}
	return piv.ParseCertificateObject(data)
}

// ReadPublicKey reads a public key from SafeNet slot storage.
func (a *Adapter) ReadPublicKey(session *adapters.Session, slot piv.Slot) (crypto.PublicKey, error) {
	if err := requireSessionClient(session); err != nil {
		return nil, err
	}

	publicKey, err := session.Client.ReadStoredPublicKey(slot)
	if err == nil {
		session.Observe(adapters.LogLevelDebug, a, "read-public-key", "read stored public key object for slot %s", slot)
		return publicKey, nil
	}
	session.Observe(adapters.LogLevelInfo, a, "read-public-key", "stored public key unavailable for slot %s, probing SafeNet mirror object", slot)

	tag, tagErr := mirrorObjectTag(slot)
	if tagErr != nil {
		return nil, tagErr
	}
	data, mirrorErr := session.Client.GetData(tag)
	if mirrorErr == nil {
		publicKey, parseErr := piv.ParsePublicKeyObject(data)
		if parseErr == nil {
			session.Observe(adapters.LogLevelDebug, a, "read-public-key", "parsed public key from SafeNet mirror object for slot %s", slot)
			return publicKey, nil
		}
	}

	session.Observe(adapters.LogLevelInfo, a, "read-public-key", "falling back to certificate-derived public key for slot %s", slot)
	if certData, certErr := a.ReadCertificate(session, slot); certErr == nil {
		if cert, parseErr := x509.ParseCertificate(certData); parseErr == nil {
			return cert.PublicKey, nil
		}
	}

	if mirrorErr != nil {
		return nil, fmt.Errorf("read SafeNet public key for slot %s: %w", slot, mirrorErr)
	}

	certData, certErr := piv.ParseCertificateObject(data)
	if certErr == nil {
		cert, parseErr := x509.ParseCertificate(certData)
		if parseErr == nil {
			return cert.PublicKey, nil
		}
		return nil, fmt.Errorf("read SafeNet public key for slot %s: %w", slot, parseErr)
	}

	return nil, fmt.Errorf("read SafeNet public key for slot %s: %w", slot, err)
}

// DescribeSlot reports the observable slot state, including SafeNet mirror
// objects used when the standard PIV slot object is incomplete.
func (a *Adapter) DescribeSlot(session *adapters.Session, slot piv.Slot) (adapters.SlotDescription, error) {
	description := adapters.SlotDescription{KeyAlgorithm: "-", CertLabel: "-"}
	session.Observe(adapters.LogLevelDebug, a, "describe-slot", "inspecting SafeNet slot %s", slot)

	publicKey, keyErr := a.ReadPublicKey(session, slot)
	if keyErr == nil {
		description.KeyPresent = true
		description.KeyAlgorithm = adapterslots.PublicKeyAlgorithmName(publicKey)
	}

	certData, certErr := session.Client.ReadCertificate(slot)
	if certErr != nil {
		session.Observe(adapters.LogLevelDebug, a, "describe-slot", "standard certificate unavailable for slot %s, delegating to SafeNet certificate reader", slot)
		certData, certErr = a.ReadCertificate(session, slot)
	}
	if certErr == nil {
		if cert, err := x509.ParseCertificate(certData); err == nil {
			description.CertPresent = true
			description.CertLabel = adapterslots.CertificateSummary(cert)
		}
	}

	return description, nil
}

// PutCertificate stores the certificate in the standard PIV slot object and preserves
// an existing SafeNet mirror public-key object when present.
func (a *Adapter) PutCertificate(session *adapters.Session, slot piv.Slot, certData []byte) error {
	session.Observe(adapters.LogLevelInfo, a, "put-certificate", "storing certificate for slot %s", slot)
	if err := session.AuthenticateManagementKey(a); err != nil {
		return fmt.Errorf("authenticate management key: %w", err)
	}

	mirrorTag, err := mirrorObjectTag(slot)
	if err != nil {
		return err
	}

	preserveMirrorPublicKey := false
	mirrorData, err := session.Client.GetData(mirrorTag)
	if err == nil {
		if _, parseErr := piv.ParsePublicKeyObject(mirrorData); parseErr == nil {
			preserveMirrorPublicKey = true
			session.Observe(adapters.LogLevelDebug, a, "put-certificate", "preserving SafeNet mirror public key object for slot %s", slot)
		}
	} else if !iso7816.IsStatus(err, iso7816.SwFileNotFound) && !iso7816.IsStatus(err, iso7816.SwWrongData) && !iso7816.IsStatus(err, iso7816.SwReferencedDataNotFound) {
		return fmt.Errorf("read existing SafeNet mirror object for slot %s: %w", slot, err)
	}

	if err := session.Client.PutCertificate(slot, certData); err != nil {
		return fmt.Errorf("store standard certificate for slot %s: %w", slot, err)
	}

	if !preserveMirrorPublicKey {
		session.Observe(adapters.LogLevelDebug, a, "put-certificate", "writing SafeNet mirror certificate object for slot %s", slot)
		if err := session.Client.PutData(mirrorTag, buildCertificateObject(certData)); err != nil {
			return fmt.Errorf("store SafeNet certificate for slot %s: %w", slot, err)
		}
	}
	return nil
}

// DeleteCertificate removes the certificate from the SafeNet mirror object and the standard PIV slot object.
func (a *Adapter) DeleteCertificate(session *adapters.Session, slot piv.Slot) error {
	session.Observe(adapters.LogLevelInfo, a, "delete-certificate", "deleting certificate for slot %s", slot)
	if err := session.AuthenticateManagementKey(a); err != nil {
		return fmt.Errorf("authenticate management key: %w", err)
	}
	publicObject, publicObjectErr := a.publicKeyMirrorObject(session.Client, slot)

	tag, err := mirrorObjectTag(slot)
	if err != nil {
		return err
	}
	if publicObjectErr == nil {
		session.Observe(adapters.LogLevelDebug, a, "delete-certificate", "preserving SafeNet mirror public key metadata for slot %s", slot)
		if err := session.Client.PutData(tag, publicObject); err != nil {
			return fmt.Errorf("preserve SafeNet key metadata for slot %s: %w", slot, err)
		}
	} else {
		session.Observe(adapters.LogLevelDebug, a, "delete-certificate", "removing SafeNet mirror certificate object for slot %s", slot)
		if err := session.Client.PutData(tag, iso7816.EncodeTLV(0x53, nil)); err != nil {
			return fmt.Errorf("delete SafeNet certificate for slot %s: %w", slot, err)
		}
	}
	dataTag, err := piv.ObjectIDForSlot(slot)
	if err != nil {
		return err
	}
	if publicObjectErr == nil {
		if err := session.Client.PutData(dataTag, publicObject); err != nil {
			return fmt.Errorf("restore public key object for slot %s: %w", slot, err)
		}
		return nil
	}
	if err := session.Client.PutData(dataTag, iso7816.EncodeTLV(0x53, nil)); err != nil {
		return fmt.Errorf("delete standard certificate for slot %s: %w", slot, err)
	}
	return nil
}

func (a *Adapter) publicKeyMirrorObject(client *piv.Client, slot piv.Slot) ([]byte, error) {
	tag, err := mirrorObjectTag(slot)
	if err != nil {
		return nil, err
	}
	if data, err := client.GetData(tag); err == nil {
		if publicKey, err := piv.ParsePublicKeyObject(data); err == nil {
			alg, err := algorithmForPublicKey(publicKey)
			if err != nil {
				return nil, err
			}
			return encodePublicObject(alg, publicKey)
		}
		if certData, err := piv.ParseCertificateObject(data); err == nil {
			return publicKeyMirrorObjectFromCertificate(certData)
		}
	}

	certData, err := client.GetCertificate(slot)
	if err != nil {
		return nil, fmt.Errorf("read certificate for slot %s: %w", slot, err)
	}
	return publicKeyMirrorObjectFromCertificate(certData)
}

func publicKeyMirrorObjectFromCertificate(certData []byte) ([]byte, error) {
	cert, err := x509.ParseCertificate(certData)
	if err != nil {
		return nil, fmt.Errorf("parse certificate: %w", err)
	}
	alg, err := algorithmForPublicKey(cert.PublicKey)
	if err != nil {
		return nil, err
	}
	return encodePublicObject(alg, cert.PublicKey)
}

func buildCertificateObject(certData []byte) []byte {
	certObj := iso7816.EncodeTLV(0x70, certData)
	certObj = append(certObj, iso7816.EncodeTLV(0x71, []byte{0x00})...)
	certObj = append(certObj, iso7816.EncodeTLV(0xFE, nil)...)
	return iso7816.EncodeTLV(0x53, certObj)
}
