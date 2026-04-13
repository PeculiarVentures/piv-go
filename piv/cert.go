package piv

import (
	"crypto"
	"crypto/elliptic"
	"crypto/rsa"
	"fmt"
	"math/big"

	"github.com/PeculiarVentures/piv-go/iso7816"
)

// ReadCertificate reads and returns the raw certificate bytes from the given slot.
// It handles the TLV unwrapping of the PIV certificate object.
func (c *Client) ReadCertificate(slot Slot) ([]byte, error) {
	return c.GetCertificate(slot)
}

// ReadPublicKey reads a public key from the slot's standard PIV data object.
func (c *Client) ReadPublicKey(slot Slot) (crypto.PublicKey, error) {
	return c.ReadStoredPublicKey(slot)
}

// PutCertificate writes a certificate to the specified slot.
func (c *Client) PutCertificate(slot Slot, certData []byte) error {
	// Build certificate object: 0x70 = cert, 0x71 = cert info (uncompressed), 0xFE = error detection
	certObj := iso7816.EncodeTLV(0x70, certData)
	certObj = append(certObj, iso7816.EncodeTLV(0x71, []byte{0x00})...)
	certObj = append(certObj, iso7816.EncodeTLV(0xFE, nil)...)

	tag := slotToObjectID(slot)
	dataTLV := iso7816.EncodeTLV(0x53, certObj)
	if err := c.PutData(tag, dataTLV); err != nil {
		return fmt.Errorf("piv: put certificate slot %s: %w", slot, err)
	}
	return nil
}

// DeleteCertificate clears the slot's standard PIV certificate object.
func (c *Client) DeleteCertificate(slot Slot) error {
	tag, err := ObjectIDForSlot(slot)
	if err != nil {
		return err
	}
	if err := c.PutData(tag, iso7816.EncodeTLV(0x53, nil)); err != nil {
		return fmt.Errorf("piv: delete certificate slot %s: %w", slot, err)
	}
	return nil
}

// ParseCertificateObject extracts the DER certificate from a stored PIV data object.
func ParseCertificateObject(data []byte) ([]byte, error) {
	outerTLVs, err := iso7816.ParseAllTLV(data)
	if err != nil {
		return nil, fmt.Errorf("piv: parse data object TLV: %w", err)
	}
	dataObj := iso7816.FindTag(outerTLVs, 0x53)
	if dataObj == nil {
		return nil, fmt.Errorf("piv: data object tag 0x53 not found")
	}

	tlvs, err := iso7816.ParseAllTLV(dataObj.Value)
	if err != nil {
		return nil, fmt.Errorf("piv: parse certificate TLV: %w", err)
	}
	certTLV := iso7816.FindTag(tlvs, 0x70)
	if certTLV == nil {
		return nil, fmt.Errorf("piv: certificate tag 0x70 not found")
	}
	return certTLV.Value, nil
}

// ParsePublicKeyObject extracts a public key from a stored PIV data object.
func ParsePublicKeyObject(data []byte) (crypto.PublicKey, error) {
	outerTLVs, err := iso7816.ParseAllTLV(data)
	if err != nil {
		return nil, fmt.Errorf("piv: parse data object TLV: %w", err)
	}
	dataObj := iso7816.FindTag(outerTLVs, 0x53)
	if dataObj == nil {
		return nil, fmt.Errorf("piv: data object tag 0x53 not found")
	}

	templateTLVs, err := iso7816.ParseAllTLV(dataObj.Value)
	if err != nil {
		return nil, fmt.Errorf("piv: parse public key object: %w", err)
	}
	keyTLV := iso7816.FindTag(templateTLVs, 0x7F49)
	if keyTLV == nil {
		return nil, fmt.Errorf("piv: public key tag 0x7F49 not found")
	}

	innerTLVs, err := iso7816.ParseAllTLV(keyTLV.Value)
	if err != nil {
		return nil, fmt.Errorf("piv: parse public key template: %w", err)
	}

	if pointTLV := iso7816.FindTag(innerTLVs, 0x86); pointTLV != nil {
		switch len(pointTLV.Value) {
		case 65:
			return parseECDSAPublicKey(elliptic.P256(), innerTLVs)
		case 97:
			return parseECDSAPublicKey(elliptic.P384(), innerTLVs)
		default:
			return nil, fmt.Errorf("piv: unsupported EC point length %d", len(pointTLV.Value))
		}
	}

	modulusTLV := iso7816.FindTag(innerTLVs, 0x81)
	exponentTLV := iso7816.FindTag(innerTLVs, 0x82)
	if modulusTLV == nil || exponentTLV == nil {
		return nil, fmt.Errorf("piv: unsupported public key encoding")
	}
	exponent := new(big.Int).SetBytes(exponentTLV.Value)
	if !exponent.IsInt64() {
		return nil, fmt.Errorf("piv: RSA exponent is too large")
	}
	return &rsa.PublicKey{N: new(big.Int).SetBytes(modulusTLV.Value), E: int(exponent.Int64())}, nil
}

// ReadStoredPublicKey reads a public key from the slot's data object.
func (c *Client) ReadStoredPublicKey(slot Slot) (crypto.PublicKey, error) {
	tag, err := ObjectIDForSlot(slot)
	if err != nil {
		return nil, err
	}
	data, err := c.GetData(tag)
	if err != nil {
		return nil, fmt.Errorf("piv: get public key from slot %s: %w", slot, err)
	}
	return ParsePublicKeyObject(data)
}

// PutData writes a TLV payload to the specified PIV or vendor-specific object tag.
func (c *Client) PutData(tag uint, value []byte) error {
	tagTLV := iso7816.EncodeTLV(0x5C, iso7816.EncodeTag(tag))
	data := append(tagTLV, value...)
	if len(data) <= 0xFF {
		return c.putDataChunk(0x00, data, true)
	}

	const maxChunkSize = 216
	for len(data) > maxChunkSize {
		if err := c.putDataChunk(0x10, data[:maxChunkSize], false); err != nil {
			return err
		}
		data = data[maxChunkSize:]
	}
	return c.putDataChunk(0x00, data, true)
}

func (c *Client) putDataChunk(cla byte, data []byte, final bool) error {
	cmd := &iso7816.Command{
		Cla:  cla,
		Ins:  0xDB, // PUT DATA
		P1:   0x3F,
		P2:   0xFF,
		Data: data,
		Le:   -1,
	}
	if final {
		cmd.Le = 256
	}

	resp, err := c.sendCommand(cmd)
	if err != nil {
		return err
	}
	if err := resp.Err(); err != nil {
		return err
	}
	return nil
}
