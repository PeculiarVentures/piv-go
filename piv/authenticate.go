package piv

import (
	"fmt"

	"github.com/PeculiarVentures/piv-go/iso7816"
)

// Authenticate performs a GENERAL AUTHENTICATE operation with the specified
// algorithm and slot using the provided challenge data.
func (c *Client) Authenticate(algorithm byte, slot Slot, challenge []byte) ([]byte, error) {
	inner := iso7816.EncodeTLV(0x82, nil)
	inner = append(inner, iso7816.EncodeTLV(0x81, challenge)...)
	authTemplate := iso7816.EncodeTLV(0x7C, inner)

	cmd := &iso7816.Command{
		Cla:  0x00,
		Ins:  0x87,
		P1:   algorithm,
		P2:   byte(slot),
		Data: authTemplate,
		Le:   256,
	}

	resp, err := c.sendCommand(cmd)
	if err != nil {
		return nil, fmt.Errorf("piv: authenticate: %w", err)
	}
	if err := resp.Err(); err != nil {
		return nil, fmt.Errorf("piv: authenticate: %w", err)
	}

	tlvs, err := iso7816.ParseAllTLV(resp.Data)
	if err != nil {
		return nil, fmt.Errorf("piv: parse auth response: %w", err)
	}
	authTLV := iso7816.FindTag(tlvs, 0x7C)
	if authTLV == nil {
		return nil, fmt.Errorf("piv: auth tag 0x7C not found")
	}

	innerTLVs, err := iso7816.ParseAllTLV(authTLV.Value)
	if err != nil {
		return nil, fmt.Errorf("piv: parse auth template: %w", err)
	}
	sigTLV := iso7816.FindTag(innerTLVs, 0x82)
	if sigTLV == nil {
		return nil, fmt.Errorf("piv: response tag 0x82 not found")
	}
	return sigTLV.Value, nil
}
