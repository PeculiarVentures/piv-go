package adapters

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/PeculiarVentures/piv-go/iso7816"
	"github.com/PeculiarVentures/piv-go/piv"
)

// CHUID represents the parsed components of a PIV CHUID object.
type CHUID struct {
	Raw        []byte `json:"raw,omitempty"`
	FASCN      string `json:"fasc_n,omitempty"`
	GUID       string `json:"guid,omitempty"`
	Expiration string `json:"expiration,omitempty"`
}

// ReadCHUID reads the CHUID object using the resolved runtime.
func ReadCHUID(runtime *Runtime) (CHUID, error) {
	return ReadCHUIDWithSession(runtime.Session, runtime.Adapter)
}

// ReadCHUIDWithSession reads the CHUID object for the provided session and adapter.
func ReadCHUIDWithSession(session *Session, adapter Adapter) (CHUID, error) {
	if session == nil {
		return CHUID{}, fmt.Errorf("adapters: session is required")
	}
	var raw []byte
	var err error
	if chuidAdapter, ok := adapter.(CHUIDAdapter); ok {
		raw, err = chuidAdapter.CHUID(session)
	} else {
		raw, err = session.Client.GetData(piv.ObjectCHUID)
	}
	if err != nil {
		return CHUID{}, err
	}
	return parseCHUID(raw)
}

func parseCHUID(data []byte) (CHUID, error) {
	result := CHUID{Raw: append([]byte(nil), data...)}
	if len(data) == 0 {
		return result, nil
	}

	tlvs, err := iso7816.ParseAllTLV(data)
	if err != nil {
		return result, err
	}

	payload := data
	if len(tlvs) == 1 && tlvs[0].Tag == 0x53 {
		payload = tlvs[0].Value
	}

	inner, err := iso7816.ParseAllTLV(payload)
	if err != nil {
		return result, err
	}

	for _, tlv := range inner {
		switch tlv.Tag {
		case 0x30:
			result.FASCN = strings.ToUpper(hex.EncodeToString(tlv.Value))
		case 0x34:
			result.GUID = formatGUID(tlv.Value)
		case 0x35:
			result.Expiration = formatExpiration(strings.TrimSpace(string(tlv.Value)))
		}
	}

	return result, nil
}

func formatGUID(value []byte) string {
	if len(value) != 16 {
		return strings.ToUpper(hex.EncodeToString(value))
	}
	return strings.ToUpper(fmt.Sprintf("%08x-%04x-%04x-%04x-%s",
		binary.BigEndian.Uint32(value[0:4]),
		binary.BigEndian.Uint16(value[4:6]),
		binary.BigEndian.Uint16(value[6:8]),
		binary.BigEndian.Uint16(value[8:10]),
		hex.EncodeToString(value[10:16]),
	))
}

func formatExpiration(value string) string {
	if len(value) == 8 {
		return fmt.Sprintf("%s-%s-%s", value[0:4], value[4:6], value[6:8])
	}
	return value
}
