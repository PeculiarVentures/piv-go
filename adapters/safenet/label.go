package safenet

import (
	"bytes"
	"fmt"
	"strings"

	"github.com/PeculiarVentures/piv-go/adapters"
	"github.com/PeculiarVentures/piv-go/iso7816"
)

var safeNetTokenLabelMap = map[string]string{
	"Token Fusion NFC PIV":  "IDPrime PIV",
	"eToken Fusion NFC PIV": "IDPrime PIV",
}

func normalizeSafeNetTokenLabel(vendorLabel string) string {
	if mapped, ok := safeNetTokenLabelMap[vendorLabel]; ok {
		return mapped
	}
	return vendorLabel
}

// Label returns the token label for SafeNet tokens.
//
// SafeNet devices may expose vendor-specific names such as "Token Fusion NFC PIV"
// or "eToken Fusion NFC PIV". This method normalizes those values to a canonical
// label and appends the token serial number.
func (a *Adapter) Label(session *adapters.Session) (string, error) {
	if err := session.Client.Select(); err != nil {
		return "", fmt.Errorf("safenet: select PIV application: %w", err)
	}

	resp, err := session.Client.Execute(&iso7816.Command{
		Cla:  0x00,
		Ins:  0xCB,
		P1:   0x3F,
		P2:   0xFF,
		Data: []byte{0x5C, 0x03, 0x5F, 0xFF, 0x12},
		Le:   0x05,
	})
	if err != nil {
		return "", fmt.Errorf("safenet: read token label: %w", err)
	}
	if err := resp.Err(); err != nil {
		return "", fmt.Errorf("safenet: read token label: %w", err)
	}

	vendorLabel := normalizeSafeNetTokenLabel(parseSafeNetTokenLabel(resp.Data))
	serial, err := a.SerialNumber(session)
	if err != nil {
		return "", fmt.Errorf("safenet: read token label: %w", err)
	}
	return fmt.Sprintf("%s #%s", vendorLabel, normalizeSafeNetByteString(serial)), nil
}

func parseSafeNetTokenLabel(data []byte) string {
	label := normalizeSafeNetByteString(data)
	for i := 0; i+6 <= len(data); {
		if data[i] == 0x80 && data[i+1] == 0x00 && data[i+2] == 0x11 {
			subTag := data[i+3]
			length := int(data[i+4])
			start := i + 5
			end := start + length
			if end > len(data) {
				break
			}
			value := normalizeSafeNetByteString(data[start:end])
			if subTag == 0x01 && value != "" {
				return value
			}
			i = end
			continue
		}
		i++
	}
	return label
}

func normalizeSafeNetByteString(data []byte) string {
	data = bytes.Trim(data, "\x00")
	data = bytes.TrimSpace(data)
	filtered := make([]byte, 0, len(data))
	for _, b := range data {
		if b >= 0x20 && b <= 0x7e {
			filtered = append(filtered, b)
		}
	}
	return strings.TrimSpace(string(filtered))
}
