package yubikey

import (
	"bytes"
	"fmt"

	"github.com/PeculiarVentures/piv-go/adapters"
	"github.com/PeculiarVentures/piv-go/iso7816"
	"github.com/PeculiarVentures/piv-go/piv"
)

// DescribeReset reports the YubiKey reset policy requirements.
func (a *Adapter) DescribeReset(session *adapters.Session) (adapters.ResetRequirements, error) {
	if session != nil {
		session.Observe(adapters.LogLevelDebug, a, "describe-reset", "YubiKey reset does not require additional fields")
	}
	return adapters.ResetRequirements{}, nil
}

// ResetToken resets the YubiKey PIV applet to factory defaults.
func (a *Adapter) ResetToken(session *adapters.Session, params adapters.ResetTokenParams) error {
	if err := requireSessionClient(session); err != nil {
		return err
	}
	session.Observe(adapters.LogLevelInfo, a, "reset-token", "starting YubiKey token reset")
	if err := blockPIN(a, session); err != nil {
		return err
	}
	if err := blockPUK(a, session); err != nil {
		return err
	}
	session.Observe(adapters.LogLevelDebug, a, "reset-token", "issuing standard PIV reset")
	if err := session.Client.Reset(); err != nil {
		return err
	}
	session.ManagementAlgorithm = 0
	session.ManagementKey = append([]byte(nil), defaultManagementKey...)
	session.Observe(adapters.LogLevelInfo, a, "reset-token", "completed YubiKey token reset")
	return nil
}

func blockPIN(adapter *Adapter, session *adapters.Session) error {
	status, err := readPINMetadata(session.Client, piv.PINTypeCard)
	if err != nil {
		session.Observe(adapters.LogLevelDebug, adapter, "reset-token", "falling back to standard PIN retry status while blocking PIN")
		pivStatus, statusErr := session.Client.PINStatus(piv.PINTypeCard)
		if statusErr != nil {
			return fmt.Errorf("yubikey: read PIN retry status: %w", statusErr)
		}
		status.AttemptsRemaining = pivStatus.RetriesLeft
	} else {
		session.Observe(adapters.LogLevelDebug, adapter, "reset-token", "using YubiKey metadata to block PIN")
	}
	for status.AttemptsRemaining > 0 {
		retries, err := submitInvalidPIN(session.Client)
		if err != nil {
			return err
		}
		status.AttemptsRemaining = retries
	}
	return nil
}

func blockPUK(adapter *Adapter, session *adapters.Session) error {
	status, err := readPINMetadata(session.Client, piv.PINTypePUK)
	if err != nil {
		session.Observe(adapters.LogLevelDebug, adapter, "reset-token", "PUK metadata unavailable, using one-step fallback to block PUK")
		status.AttemptsRemaining = 1
	} else {
		session.Observe(adapters.LogLevelDebug, adapter, "reset-token", "using YubiKey metadata to block PUK")
	}
	for status.AttemptsRemaining > 0 {
		retries, err := submitInvalidPUKReset(session.Client)
		if err != nil {
			return err
		}
		status.AttemptsRemaining = retries
	}
	return nil
}

func submitInvalidPIN(client *piv.Client) (int, error) {
	cmd := &iso7816.Command{
		Cla:  0x00,
		Ins:  0x20,
		P1:   0x00,
		P2:   byte(piv.PINTypeCard),
		Data: bytes.Repeat([]byte{0xFF}, 8),
		Le:   -1,
	}
	resp, err := client.Execute(cmd)
	if err != nil {
		return 0, fmt.Errorf("yubikey: block PIN step: %w", err)
	}
	return retriesFromResponse(resp, "block PIN step")
}

func submitInvalidPUKReset(client *piv.Client) (int, error) {
	data := append(bytes.Repeat([]byte{0xFF}, 8), bytes.Repeat([]byte{0xFF}, 8)...)
	cmd := &iso7816.Command{
		Cla:  0x00,
		Ins:  0x2C,
		P1:   0x00,
		P2:   byte(piv.PINTypeCard),
		Data: data,
		Le:   -1,
	}
	resp, err := client.Execute(cmd)
	if err != nil {
		return 0, fmt.Errorf("yubikey: block PUK step: %w", err)
	}
	return retriesFromResponse(resp, "block PUK step")
}

func retriesFromResponse(resp *iso7816.Response, operation string) (int, error) {
	sw := resp.StatusWord()
	if retries, ok := iso7816.IsPINRetryStatus(sw); ok {
		return retries, nil
	}
	if sw == iso7816.SwAuthBlocked || sw == iso7816.SwSuccess {
		return 0, nil
	}
	if err := resp.Err(); err != nil {
		return 0, fmt.Errorf("yubikey: %s: %w", operation, err)
	}
	return 0, nil
}
