package safenet

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"fmt"

	"github.com/PeculiarVentures/piv-go/adapters"
	"github.com/PeculiarVentures/piv-go/iso7816"
	"github.com/PeculiarVentures/piv-go/piv"
)

// PrepareGenerateKey runs the SafeNet-specific pre-generation sequence.
func (a *Adapter) PrepareGenerateKey(session *adapters.Session, slot piv.Slot, algorithm byte) error {
	if err := session.AuthenticateManagementKey(a); err != nil {
		return fmt.Errorf("authenticate management key: %w", err)
	}
	if err := selectAdminApplet(session.Client); err != nil {
		return err
	}
	if err := readVersion(session.Client); err != nil {
		return err
	}
	if err := readMetadata(session.Client, slot); err != nil {
		return err
	}
	if algorithm == piv.AlgECCP256 {
		if err := loadECCP256Parameters(session.Client, slot, algorithm); err != nil {
			return err
		}
	}
	return nil
}

// FinalizeGenerateKey stores the generated key metadata in SafeNet-specific and standard objects.
func (a *Adapter) FinalizeGenerateKey(session *adapters.Session, slot piv.Slot, algorithm byte, publicKey crypto.PublicKey) error {
	privateTag, err := mirrorObjectTag(slot)
	if err != nil {
		return fmt.Errorf("resolve SafeNet mirror object for slot %s: %w", slot, err)
	}

	obj, err := encodePublicObject(algorithm, publicKey)
	if err != nil {
		return fmt.Errorf("encode public object: %w", err)
	}

	if err := session.Client.PutData(privateTag, obj); err != nil {
		return fmt.Errorf("store SafeNet mirror object for slot %s: %w", slot, err)
	}

	genTag, err := generationObjectTag(slot)
	if err != nil {
		return err
	}

	metadata, err := getMetadata(session.Client, genTag)
	if err != nil {
		return fmt.Errorf("verify SafeNet generation metadata for slot %s: %w", slot, err)
	}
	if err := verifyGenerationMetadata(metadata, algorithm); err != nil {
		return fmt.Errorf("verify SafeNet generation metadata for slot %s: %w", slot, err)
	}

	present, err := a.hasStandardPublicKeyObject(session.Client, slot)
	if err != nil {
		return err
	}
	if !present {
		if err := session.Client.StoreGeneratedPublicKey(slot, algorithm, publicKey); err != nil {
			return fmt.Errorf("store standard generated public key for slot %s: %w", slot, err)
		}
	}

	stored, err := session.Client.GetData(privateTag)
	if err != nil {
		return fmt.Errorf("verify SafeNet mirror object for slot %s: %w", slot, err)
	}
	if !bytes.Equal(stored, obj) {
		return fmt.Errorf("verified SafeNet mirror object for slot %s does not match generated public key", slot)
	}

	return nil
}

func (a *Adapter) hasStandardPublicKeyObject(client *piv.Client, slot piv.Slot) (bool, error) {
	tag, err := piv.ObjectIDForSlot(slot)
	if err != nil {
		return false, err
	}
	data, err := client.GetData(tag)
	if err != nil {
		if iso7816.IsStatus(err, iso7816.SwFileNotFound) || iso7816.IsStatus(err, iso7816.SwWrongData) || iso7816.IsStatus(err, iso7816.SwReferencedDataNotFound) {
			return false, nil
		}
		return false, err
	}

	if _, err := piv.ParsePublicKeyObject(data); err == nil {
		return true, nil
	}
	if _, err := piv.ParseCertificateObject(data); err == nil {
		return false, fmt.Errorf("standard slot object %s already contains a certificate", slot)
	}
	return false, fmt.Errorf("standard slot object %s contains unsupported data", slot)
}

func verifyGenerationMetadata(data []byte, algorithm byte) error {
	tlvs, err := iso7816.ParseAllTLV(data)
	if err != nil {
		return err
	}

	statusTLV := findRecursiveTLV(tlvs, 0x8A)
	if statusTLV == nil || len(statusTLV.Value) == 0 {
		return fmt.Errorf("generation metadata missing generation status")
	}
	if statusTLV.Value[0] != 0x05 {
		return fmt.Errorf("generation metadata status is %02X, expected 05", statusTLV.Value[0])
	}

	algorithmTLV := findRecursiveTLV(tlvs, 0x80)
	if algorithmTLV == nil || len(algorithmTLV.Value) == 0 {
		return fmt.Errorf("generation metadata missing algorithm")
	}
	if algorithmTLV.Value[0] != algorithm {
		return fmt.Errorf("generation metadata algorithm is %02X, expected %02X", algorithmTLV.Value[0], algorithm)
	}

	stateTLV := findRecursiveTLV(tlvs, 0x9D)
	if stateTLV == nil || len(stateTLV.Value) == 0 {
		return fmt.Errorf("generation metadata missing key state")
	}
	if stateTLV.Value[0] != 0x55 {
		return fmt.Errorf("generation metadata state is %02X, expected 55", stateTLV.Value[0])
	}

	return nil
}

// DeleteKey clears SafeNet vendor objects and the associated public data object for the slot.
func (a *Adapter) DeleteKey(session *adapters.Session, slot piv.Slot) error {
	if err := session.AuthenticateManagementKey(a); err != nil {
		return fmt.Errorf("authenticate management key: %w", err)
	}

	vendorTag, err := generationObjectTag(slot)
	if err != nil {
		return err
	}
	if err := session.Client.PutData(vendorTag, iso7816.EncodeTLV(0x7F48, nil)); err != nil {
		return fmt.Errorf("clear SafeNet 7F48 for slot %s: %w", slot, err)
	}
	if err := session.Client.PutData(vendorTag, iso7816.EncodeTLV(0x7F49, nil)); err != nil {
		return fmt.Errorf("clear SafeNet 7F49 for slot %s: %w", slot, err)
	}

	if privateTag, err := mirrorObjectTag(slot); err == nil {
		if err := session.Client.PutData(privateTag, iso7816.EncodeTLV(0x53, nil)); err != nil {
			return fmt.Errorf("clear SafeNet mirror object for slot %s: %w", slot, err)
		}
	}

	dataTag, err := piv.ObjectIDForSlot(slot)
	if err != nil {
		return err
	}
	if err := session.Client.PutData(dataTag, iso7816.EncodeTLV(0x53, nil)); err != nil {
		return fmt.Errorf("clear standard slot object for slot %s: %w", slot, err)
	}
	return nil
}

func loadECCP256Parameters(client *piv.Client, slot piv.Slot, algorithm byte) error {
	tag, err := generationObjectTag(slot)
	if err != nil {
		return err
	}
	for _, parameter := range eccP256Parameters {
		inner := iso7816.EncodeTLV(0x80, []byte{algorithm})
		inner = append(inner, iso7816.EncodeTLV(parameter.tag, parameter.value)...)
		if err := client.PutData(tag, iso7816.EncodeTLV(0x7F49, inner)); err != nil {
			return fmt.Errorf("prepare SafeNet ECC parameters for slot %s: %w", slot, err)
		}
	}
	return nil
}

func (a *Adapter) resetSlot(client *piv.Client, slot piv.Slot) error {
	vendorTag, err := generationObjectTag(slot)
	if err != nil {
		return err
	}
	if err := client.PutData(vendorTag, iso7816.EncodeTLV(0x7F48, nil)); err != nil {
		return fmt.Errorf("reset slot %s 7F48: %w", slot, err)
	}
	if err := client.PutData(vendorTag, iso7816.EncodeTLV(0x7F49, nil)); err != nil {
		return fmt.Errorf("reset slot %s 7F49: %w", slot, err)
	}

	mirrorTag, err := mirrorObjectTag(slot)
	if err != nil {
		return err
	}
	if err := client.PutData(mirrorTag, iso7816.EncodeTLV(0x53, nil)); err != nil {
		return fmt.Errorf("reset slot %s mirror public object: %w", slot, err)
	}
	return nil
}

func encodePublicObject(algorithm byte, publicKey crypto.PublicKey) ([]byte, error) {
	template, err := encodePublicKeyTemplate(algorithm, publicKey)
	if err != nil {
		return nil, err
	}
	data := append([]byte{}, template...)
	data = append(data, iso7816.EncodeTLV(0x71, []byte{0x00})...)
	data = append(data, iso7816.EncodeTLV(0xFE, nil)...)
	return iso7816.EncodeTLV(0x53, data), nil
}

func encodePublicKeyTemplate(algorithm byte, publicKey crypto.PublicKey) ([]byte, error) {
	switch algorithm {
	case piv.AlgRSA1024, piv.AlgRSA2048:
		rsaKey, ok := publicKey.(*rsa.PublicKey)
		if !ok {
			return nil, fmt.Errorf("expected RSA public key, got %T", publicKey)
		}
		template := iso7816.EncodeTLV(0x81, rsaKey.N.Bytes())
		template = append(template, iso7816.EncodeTLV(0x82, bigIntBytes(rsaKey.E))...)
		return iso7816.EncodeTLV(0x7F49, template), nil
	case piv.AlgECCP256, piv.AlgECCP384:
		ecdsaKey, ok := publicKey.(*ecdsa.PublicKey)
		if !ok {
			return nil, fmt.Errorf("expected ECDSA public key, got %T", publicKey)
		}
		point, err := ecdsaKey.Bytes()
		if err != nil {
			return nil, err
		}
		return iso7816.EncodeTLV(0x7F49, iso7816.EncodeTLV(0x86, point)), nil
	default:
		return nil, fmt.Errorf("unsupported algorithm 0x%02X", algorithm)
	}
}

func algorithmForPublicKey(publicKey crypto.PublicKey) (byte, error) {
	switch key := publicKey.(type) {
	case *ecdsa.PublicKey:
		switch key.Curve {
		case elliptic.P256():
			return piv.AlgECCP256, nil
		case elliptic.P384():
			return piv.AlgECCP384, nil
		default:
			return 0, fmt.Errorf("unsupported ECDSA curve")
		}
	case *rsa.PublicKey:
		if key.N.BitLen() <= 1024 {
			return piv.AlgRSA1024, nil
		}
		return piv.AlgRSA2048, nil
	default:
		return 0, fmt.Errorf("unsupported public key type %T", publicKey)
	}
}

func bigIntBytes(value int) []byte {
	return []byte{byte(value >> 16), byte(value >> 8), byte(value)}
}
