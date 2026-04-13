package safenet

import (
	"fmt"

	"github.com/PeculiarVentures/piv-go/adapters"
	"github.com/PeculiarVentures/piv-go/iso7816"
)

// SerialNumber returns the vendor-specific hardware serial number for SafeNet.
func (a *Adapter) SerialNumber(session *adapters.Session) ([]byte, error) {
	if _, err := session.Client.Execute(&iso7816.Command{Cla: 0x02, Ins: 0xA4, P1: 0x04, P2: 0x00, Le: -1}); err != nil {
		return nil, fmt.Errorf("safenet: select vendor application: %w", err)
	}

	resp, err := session.Client.Execute(&iso7816.Command{Cla: 0x82, Ins: 0xCA, P1: 0x01, P2: 0x04, Le: 0x00})
	if err != nil {
		return nil, fmt.Errorf("safenet: read serial number: %w", err)
	}
	if err := resp.Err(); err != nil {
		return nil, fmt.Errorf("safenet: read serial number: %w", err)
	}

	if len(resp.Data) < 3 {
		return nil, fmt.Errorf("safenet: serial number response too short")
	}
	length := int(resp.Data[2])
	if len(resp.Data) < 3+length {
		return nil, fmt.Errorf("safenet: serial number response length mismatch: expected %d, got %d", length, len(resp.Data)-3)
	}
	return resp.Data[3 : 3+length], nil
}
