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
	if err := requireSessionClient(session); err != nil {
		return adapters.SlotDescription{}, err
	}
	session.Observe(adapters.LogLevelDebug, a, "describe-slot", "inspecting SafeNet slot %s", slot)
	standardTag, err := piv.ObjectIDForSlot(slot)
	if err != nil {
		return adapters.SlotDescription{}, err
	}
	standardData, standardErr := session.Client.GetData(standardTag)
	standard := adapterslots.DescribeDataObject(standardData, standardErr)
	mirrorTag, err := mirrorObjectTag(slot)
	if err != nil {
		// Slots without a SafeNet mirror still have a standard PIV view.
		return standard, nil
	}
	mirrorData, mirrorErr := session.Client.GetData(mirrorTag)
	mirror := adapterslots.DescribeDataObject(mirrorData, mirrorErr)
	return mergeSlotObjects(standard, mirror), nil
}

func mergeSlotObjects(standard, mirror adapters.SlotDescription) adapters.SlotDescription {
	d := standard
	if mirror.KeyState == adapters.SlotStatePresent && standard.KeyState != adapters.SlotStatePresent {
		d.SetKeyState(adapters.SlotStatePresent, nil)
		d.PublicKey = mirror.PublicKey
		d.KeyAlgorithm = mirror.KeyAlgorithm
	} else if standard.KeyState != adapters.SlotStatePresent {
		state, err := mergeObjectState(standard.KeyState, standard.KeyError, mirror.KeyState, mirror.KeyError)
		d.SetKeyState(state, err)
	}
	if mirror.CertState == adapters.SlotStatePresent && standard.CertState != adapters.SlotStatePresent {
		d.CertDER = mirror.CertDER
		d.CertLabel = mirror.CertLabel
		d.SetCertState(adapters.SlotStatePresent, nil)
	} else if standard.CertState != adapters.SlotStatePresent {
		state, err := mergeObjectState(standard.CertState, standard.CertError, mirror.CertState, mirror.CertError)
		if len(d.CertDER) == 0 {
			d.CertDER = mirror.CertDER
		}
		d.SetCertState(state, err)
	}
	if d.KeyState == adapters.SlotStateUnknown && d.KeyError == nil {
		d.KeyUnknownReason = adapters.KeyUnknownReasonUnobservable
	}
	if d.KeyState != adapters.SlotStatePresent && d.CertState == adapters.SlotStatePresent {
		// A certificate identifies public material but does not prove that
		// the matching private key is available on the token.
		if d.PublicKey == nil {
			if standard.CertState == adapters.SlotStatePresent {
				d.PublicKey = standard.PublicKey
			} else {
				d.PublicKey = mirror.PublicKey
			}
			d.KeyAlgorithm = adapterslots.PublicKeyAlgorithmName(d.PublicKey)
		}
	}
	return d
}

func mergeObjectState(first adapters.SlotState, firstErr error, second adapters.SlotState, secondErr error) (adapters.SlotState, error) {
	if first == adapters.SlotStatePresent || second == adapters.SlotStatePresent {
		return adapters.SlotStatePresent, nil
	}
	if first == adapters.SlotStateError {
		return first, firstErr
	}
	if second == adapters.SlotStateError {
		return second, secondErr
	}
	if first == adapters.SlotStateUnknown || second == adapters.SlotStateUnknown {
		return adapters.SlotStateUnknown, nil
	}
	return adapters.SlotStateAbsent, nil
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

// isKeyNotFound reports whether a public-key read failure definitively means
// the key is absent: only a 6A82/6A88 status (unwrapped through the SafeNet
// reader). Object structure errors leave the state unknown.
func isKeyNotFound(err error) bool {
	if err == nil {
		return false
	}
	return iso7816.IsStatus(err, iso7816.SwFileNotFound) || iso7816.IsStatus(err, iso7816.SwReferencedDataNotFound)
}
