package piv

import (
	"fmt"

	"github.com/PeculiarVentures/piv-go/iso7816"
)

// PINType represents a PIV PIN reference.
type PINType byte

// PIN reference values.
const (
	PINTypeCard PINType = 0x80
	PINTypePUK  PINType = 0x81
)

// PINStatus describes the observed state of a PIV reference value.
type PINStatus struct {
	Type        PINType
	RetriesLeft int
	Blocked     bool
	Verified    bool
}

// PINStatus reads the state of the specified reference without presenting a value.
func (c *Client) PINStatus(pinType PINType) (PINStatus, error) {
	status := PINStatus{Type: pinType, RetriesLeft: -1}

	resp, err := c.sendCommand(verifyPINStatusCommand(pinType))
	if err != nil {
		return status, fmt.Errorf("piv: read pin status: %w", err)
	}

	sw := resp.StatusWord()
	if sw == iso7816.SwSuccess {
		status.Verified = true
		return status, nil
	}
	if retries, ok := iso7816.IsPINRetryStatus(sw); ok {
		status.RetriesLeft = retries
		return status, nil
	}
	if sw == iso7816.SwAuthBlocked {
		status.Blocked = true
		status.RetriesLeft = 0
		return status, nil
	}
	if err := resp.Err(); err != nil {
		return status, fmt.Errorf("piv: read pin status: %w", err)
	}
	return status, nil
}

// VerifyPINWithType verifies a PIN of the specified type.
func (c *Client) VerifyPINWithType(pinType PINType, pin string) error {
	paddedPIN := padPIN(pin)
	cmd := &iso7816.Command{
		Cla:  0x00,
		Ins:  0x20,
		P1:   0x00,
		P2:   byte(pinType),
		Data: paddedPIN,
		Le:   -1,
	}
	resp, err := c.sendCommand(cmd)
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

// ChangePIN changes the cardholder PIN using CHANGE REFERENCE DATA.
func (c *Client) ChangePIN(oldPIN string, newPIN string) error {
	return c.changeReferenceData(PINTypeCard, oldPIN, newPIN, "change pin")
}

// ChangePUK changes the PUK using CHANGE REFERENCE DATA.
func (c *Client) ChangePUK(oldPUK string, newPUK string) error {
	return c.changeReferenceData(PINTypePUK, oldPUK, newPUK, "change puk")
}

// UnblockPIN resets the PIN retry counter using the PUK and installs a new PIN.
func (c *Client) UnblockPIN(puk string, newPIN string) error {
	cmd, err := resetRetryCounterCommand(puk, newPIN)
	if err != nil {
		return err
	}
	resp, err := c.sendCommand(cmd)
	if err != nil {
		return fmt.Errorf("piv: unblock pin: %w", err)
	}
	if err := resp.Err(); err != nil {
		return fmt.Errorf("piv: unblock pin: %w", err)
	}
	return nil
}

func (c *Client) changeReferenceData(pinType PINType, currentValue string, newValue string, operation string) error {
	cmd, err := changeReferenceDataCommand(pinType, currentValue, newValue)
	if err != nil {
		return err
	}
	resp, err := c.sendCommand(cmd)
	if err != nil {
		return fmt.Errorf("piv: %s: %w", operation, err)
	}
	if err := resp.Err(); err != nil {
		return fmt.Errorf("piv: %s: %w", operation, err)
	}
	return nil
}
