package piv

import (
	"fmt"

	"github.com/PeculiarVentures/piv-go/iso7816"
)

// Client provides high-level PIV operations on a smart card.
type Client struct {
	card Card
}

// NewClient creates a new PIV Client using the provided card transport.
func NewClient(card Card) *Client {
	return &Client{card: card}
}

// Select sends the SELECT command to activate the PIV application on the card.
func (c *Client) Select() error {
	resp, err := c.sendCommand(selectCommand())
	if err != nil {
		return fmt.Errorf("piv: select: %w", err)
	}
	if err := resp.Err(); err != nil {
		return fmt.Errorf("piv: select: %w", err)
	}
	return nil
}

// GetData retrieves a data object identified by the given tag from the card.
func (c *Client) GetData(tag uint) ([]byte, error) {
	resp, err := c.sendCommand(getDataCommand(tag))
	if err != nil {
		return nil, fmt.Errorf("piv: get data %X: %w", tag, err)
	}
	if err := resp.Err(); err != nil {
		return nil, fmt.Errorf("piv: get data %X: %w", tag, err)
	}
	return resp.Data, nil
}

// VerifyPIN sends the VERIFY command to authenticate the cardholder PIN.
func (c *Client) VerifyPIN(pin string) error {
	resp, err := c.sendCommand(verifyPINCommand(pin))
	if err != nil {
		return fmt.Errorf("piv: verify pin: %w", err)
	}
	sw := resp.StatusWord()
	if retries, ok := iso7816.IsPINRetryStatus(sw); ok {
		return fmt.Errorf("piv: verify pin: wrong PIN, %d retries remaining", retries)
	}
	if err := resp.Err(); err != nil {
		return fmt.Errorf("piv: verify pin: %w", err)
	}
	return nil
}

// GetCertificate reads the certificate from the specified slot.
func (c *Client) GetCertificate(slot Slot) ([]byte, error) {
	tag := slotToObjectID(slot)
	data, err := c.GetData(tag)
	if err != nil {
		return nil, fmt.Errorf("piv: get certificate from slot %s: %w", slot, err)
	}
	cert, err := ParseCertificateObject(data)
	if err != nil {
		return nil, fmt.Errorf("piv: get certificate from slot %s: %w", slot, err)
	}
	return cert, nil
}

// Sign performs a GENERAL AUTHENTICATE operation to sign data using
// the key in the specified slot with the given algorithm.
//
// RSA-3072/4096 apply host-side PKCS#1 v1.5 type-1 formatting so the
// challenge is exactly modulus-length: the YubiKey 6 firmware performs the
// raw RSA private-key operation and rejects short challenges with 6A8x. A
// 32-byte message is wrapped with the SHA-256 DigestInfo (matching CLI
// --hash sha256); any other length is type-1 padded raw (matching CLI --hash
// none, mirroring crypto/rsa.SignPKCS1v15 with hash 0). RSA-1024/2048 keep
// their existing wire behavior unchanged. Ed25519 and ML-DSA sign the raw
// message without padding. X25519 cannot sign and rejects with "x25519
// cannot sign: use ECDH"; ML-KEM has no sign flow and gap-rejects without
// sending an APDU.
func (c *Client) Sign(alg byte, slot Slot, data []byte) ([]byte, error) {
	if alg == AlgX25519 {
		return nil, x25519SignError(fmt.Sprintf("slot %s", slot))
	}
	if IsMLKEMAlgorithm(alg) {
		return nil, unsupportedExtendedAlgorithmError(fmt.Sprintf("sign with slot %s", slot), alg)
	}
	if alg == AlgRSA3072 || alg == AlgRSA4096 {
		padded, err := formatExtendedRSAChallenge(alg, data)
		if err != nil {
			return nil, err
		}
		data = padded
	}
	resp, err := c.sendCommand(generalAuthenticateCommand(alg, slot, data))
	if err != nil {
		return nil, fmt.Errorf("piv: sign with slot %s: %w", slot, err)
	}
	if err := resp.Err(); err != nil {
		return nil, fmt.Errorf("piv: sign with slot %s: %w", slot, err)
	}

	// Parse the response: tag 0x7C contains dynamic auth template
	tlvs, err := iso7816.ParseAllTLV(resp.Data)
	if err != nil {
		return nil, fmt.Errorf("piv: parse sign response: %w", err)
	}
	authTLV := iso7816.FindTag(tlvs, 0x7C)
	if authTLV == nil {
		return nil, fmt.Errorf("piv: auth response tag 0x7C not found")
	}

	// Inside 0x7C, tag 0x82 contains the signature
	innerTLVs, err := iso7816.ParseAllTLV(authTLV.Value)
	if err != nil {
		return nil, fmt.Errorf("piv: parse auth template: %w", err)
	}
	sigTLV := iso7816.FindTag(innerTLVs, 0x82)
	if sigTLV == nil {
		return nil, fmt.Errorf("piv: signature tag 0x82 not found")
	}
	return sigTLV.Value, nil
}

// Execute sends an arbitrary ISO 7816 command through the client transport.
func (c *Client) Execute(cmd *iso7816.Command) (*iso7816.Response, error) {
	return c.sendCommand(cmd)
}

// sha256DigestInfoPrefix is the DER DigestInfo prefix for SHA-256 used in
// PKCS#1 v1.5 signatures (RFC 8017): the 32-byte digest follows.
var sha256DigestInfoPrefix = []byte{
	0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86,
	0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05,
	0x00, 0x04, 0x20,
}

// extendedRSAModulusLength returns the modulus byte length for the YubiKey 6
// RSA extension algorithms that require host-side challenge formatting.
func extendedRSAModulusLength(algorithm byte) (int, bool) {
	switch algorithm {
	case AlgRSA3072:
		return 384, true
	case AlgRSA4096:
		return 512, true
	default:
		return 0, false
	}
}

// formatExtendedRSAChallenge formats a sign challenge for RSA-3072/4096 as a
// PKCS#1 v1.5 type-1 encryption block of exactly modulus length: EM = 00 01
// FF..FF 00 || T. A 32-byte message is treated as a SHA-256 digest and
// wrapped with the DigestInfo prefix; any other message is padded raw.
// Oversize messages are rejected before any APDU is sent.
func formatExtendedRSAChallenge(algorithm byte, data []byte) ([]byte, error) {
	k, ok := extendedRSAModulusLength(algorithm)
	if !ok {
		return nil, fmt.Errorf("piv: unsupported RSA challenge algorithm 0x%02X", algorithm)
	}
	t := data
	if len(data) == 32 {
		t = append(append([]byte(nil), sha256DigestInfoPrefix...), data...)
	}
	if len(t) > k-11 {
		return nil, fmt.Errorf("piv: RSA message too long for algorithm 0x%02X: got %d bytes, maximum %d", algorithm, len(data), k-11)
	}
	em := make([]byte, k)
	em[0] = 0x00
	em[1] = 0x01
	for i := 2; i < k-len(t)-1; i++ {
		em[i] = 0xFF
	}
	em[k-len(t)-1] = 0x00
	copy(em[k-len(t):], t)
	return em, nil
}

// CalculateSecret performs X25519 ECDH key agreement with the slot key and a
// 32-byte peer public key: GENERAL AUTHENTICATE 00 87 E1 <slot> carrying
// 7C{82 empty, 85 peer} and returning 7C{82 32-byte secret}.
func (c *Client) CalculateSecret(slot Slot, peerPublicKey []byte) ([]byte, error) {
	if len(peerPublicKey) != 32 {
		return nil, fmt.Errorf("piv: unsupported ECDH peer key length %d, must be 32 bytes", len(peerPublicKey))
	}
	inner := iso7816.EncodeTLV(0x82, nil)
	inner = append(inner, iso7816.EncodeTLV(0x85, peerPublicKey)...)
	cmd := &iso7816.Command{
		Cla:  0x00,
		Ins:  0x87, // GENERAL AUTHENTICATE
		P1:   AlgX25519,
		P2:   byte(slot),
		Data: iso7816.EncodeTLV(0x7C, inner),
		Le:   256,
	}
	resp, err := c.sendCommand(cmd)
	if err != nil {
		return nil, fmt.Errorf("piv: ECDH with slot %s: %w", slot, err)
	}
	if err := resp.Err(); err != nil {
		return nil, fmt.Errorf("piv: ECDH with slot %s: %w", slot, err)
	}
	tlvs, err := iso7816.ParseAllTLV(resp.Data)
	if err != nil {
		return nil, fmt.Errorf("piv: parse ECDH response: %w", err)
	}
	authTLV := iso7816.FindTag(tlvs, 0x7C)
	if authTLV == nil {
		return nil, fmt.Errorf("piv: auth response tag 0x7C not found")
	}
	innerTLVs, err := iso7816.ParseAllTLV(authTLV.Value)
	if err != nil {
		return nil, fmt.Errorf("piv: parse auth template: %w", err)
	}
	secretTLV := iso7816.FindTag(innerTLVs, 0x82)
	if secretTLV == nil {
		return nil, fmt.Errorf("piv: secret tag 0x82 not found")
	}
	if len(secretTLV.Value) != 32 {
		return nil, fmt.Errorf("piv: unexpected ECDH secret length %d", len(secretTLV.Value))
	}
	return append([]byte(nil), secretTLV.Value...), nil
}

func (c *Client) sendCommand(cmd *iso7816.Command) (*iso7816.Response, error) {
	raw, err := c.card.Transmit(cmd.Bytes())
	if err != nil {
		return nil, err
	}
	resp, err := iso7816.ParseResponse(raw)
	if err != nil {
		return nil, err
	}

	// Handle response chaining: SW1=0x61 means more data is available.
	// Send GET RESPONSE (INS=0xC0) to retrieve remaining chunks.
	data := resp.Data
	for resp.HasMoreData() {
		le := int(resp.SW2)
		if le == 0 {
			le = 256
		}
		getResp := &iso7816.Command{
			Cla: 0x00,
			Ins: 0xC0, // GET RESPONSE
			P1:  0x00,
			P2:  0x00,
			Le:  le,
		}
		raw, err = c.card.Transmit(getResp.Bytes())
		if err != nil {
			return nil, err
		}
		resp, err = iso7816.ParseResponse(raw)
		if err != nil {
			return nil, err
		}
		data = append(data, resp.Data...)
	}
	resp.Data = data

	return resp, nil
}
