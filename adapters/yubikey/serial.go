package yubikey

import (
	"errors"
	"fmt"

	"github.com/PeculiarVentures/piv-go/adapters"
	"github.com/PeculiarVentures/piv-go/iso7816"
)

// ErrSerialNumberUnavailable means that neither PIV nor OTP supplied a serial.
var ErrSerialNumberUnavailable = errors.New("yubikey: serial number unavailable")

// SerialNumber returns the token serial number for YubiKey PIV tokens.
func (a *Adapter) SerialNumber(session *adapters.Session) ([]byte, error) {
	if err := requireSessionClient(session); err != nil {
		return nil, err
	}
	if err := session.Client.Select(); err != nil {
		return nil, fmt.Errorf("yubikey: select PIV application: %w", err)
	}

	resp, err := session.Client.Execute(&iso7816.Command{Cla: 0x00, Ins: 0xF8, P1: 0x00, P2: 0x00, Le: 0x00})
	if err != nil {
		return nil, fmt.Errorf("yubikey: read serial number: %w", err)
	}
	pivErr := resp.Err()
	if pivErr == nil {
		if len(resp.Data) == 4 && resp.Data[0]|resp.Data[1]|resp.Data[2]|resp.Data[3] != 0 {
			return append([]byte(nil), resp.Data...), nil
		}
		pivErr = fmt.Errorf("invalid PIV GET SERIAL value (%d bytes)", len(resp.Data))
	} else if !iso7816.IsStatus(pivErr, iso7816.SwInsNotSupported) &&
		!iso7816.IsStatus(pivErr, iso7816.SwIncorrectP1P2) &&
		!iso7816.IsStatus(pivErr, iso7816.SwReferencedDataNotFound) {
		return nil, fmt.Errorf("yubikey: read serial number: %w", pivErr)
	}
	serial, otpErr := executeOTP(session.Client, "read serial", &iso7816.Command{
		Cla: 0x00, Ins: 0x01, P1: 0x10, P2: 0x00, Le: 256,
	})
	if otpErr != nil {
		return nil, errors.Join(ErrSerialNumberUnavailable, fmt.Errorf("PIV GET SERIAL: %w", pivErr), otpErr)
	}
	if len(serial) != 4 || serial[0]|serial[1]|serial[2]|serial[3] == 0 {
		return nil, fmt.Errorf("%w: OTP serial has invalid value (%d bytes)", ErrSerialNumberUnavailable, len(serial))
	}
	return serial, nil
}
