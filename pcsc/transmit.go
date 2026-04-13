package pcsc

import "fmt"

// TransmitAPDU sends an APDU command to the card and validates
// that a response of at least 2 bytes (status word) is returned.
func TransmitAPDU(card *Card, apdu []byte) ([]byte, error) {
	resp, err := card.Transmit(apdu)
	if err != nil {
		return nil, err
	}
	if len(resp) < 2 {
		return nil, fmt.Errorf("pcsc: response too short (%d bytes)", len(resp))
	}
	return resp, nil
}
