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
func (c *Client) Sign(alg byte, slot Slot, data []byte) ([]byte, error) {
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
