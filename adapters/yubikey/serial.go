package yubikey

import (
	"fmt"

	"github.com/PeculiarVentures/piv-go/adapters"
	"github.com/PeculiarVentures/piv-go/iso7816"
)

// SerialNumber returns the token serial number for YubiKey PIV tokens.
func (a *Adapter) SerialNumber(session *adapters.Session) ([]byte, error) {
	if err := session.Client.Select(); err != nil {
		return nil, fmt.Errorf("yubikey: select PIV application: %w", err)
	}

	resp, err := session.Client.Execute(&iso7816.Command{Cla: 0x00, Ins: 0xF8, P1: 0x00, P2: 0x00, Le: 0x00})
	if err != nil {
		return nil, fmt.Errorf("yubikey: read serial number: %w", err)
	}
	if err := resp.Err(); err != nil {
		return nil, fmt.Errorf("yubikey: read serial number: %w", err)
	}
	return resp.Data, nil
}
