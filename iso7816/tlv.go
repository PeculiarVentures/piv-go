package iso7816

import "fmt"

// TLV represents a BER-TLV (Tag-Length-Value) structure.
type TLV struct {
	Tag   uint
	Value []byte
}

// ParseTLV parses a single BER-TLV structure from the input.
// It returns the parsed TLV and the remaining bytes.
func ParseTLV(data []byte) (*TLV, []byte, error) {
	if len(data) == 0 {
		return nil, nil, fmt.Errorf("iso7816: empty TLV data")
	}

	tag, offset, err := parseTag(data)
	if err != nil {
		return nil, nil, err
	}

	if offset >= len(data) {
		return nil, nil, fmt.Errorf("iso7816: TLV missing length")
	}

	length, lenBytes, err := parseLength(data[offset:])
	if err != nil {
		return nil, nil, err
	}
	offset += lenBytes

	if offset+length > len(data) {
		return nil, nil, fmt.Errorf("iso7816: TLV value exceeds data (need %d, have %d)", length, len(data)-offset)
	}

	value := make([]byte, length)
	copy(value, data[offset:offset+length])

	return &TLV{Tag: tag, Value: value}, data[offset+length:], nil
}

// ParseAllTLV parses all BER-TLV structures from the input.
func ParseAllTLV(data []byte) ([]*TLV, error) {
	var result []*TLV
	remaining := data
	for len(remaining) > 0 {
		tlv, rest, err := ParseTLV(remaining)
		if err != nil {
			return nil, err
		}
		result = append(result, tlv)
		remaining = rest
	}
	return result, nil
}

// EncodeTLV encodes a TLV structure into bytes.
func EncodeTLV(tag uint, value []byte) []byte {
	tagBytes := EncodeTag(tag)
	lenBytes := encodeLength(len(value))
	buf := make([]byte, 0, len(tagBytes)+len(lenBytes)+len(value))
	buf = append(buf, tagBytes...)
	buf = append(buf, lenBytes...)
	buf = append(buf, value...)
	return buf
}

// FindTag searches for a specific tag in a slice of TLV structures.
func FindTag(tlvs []*TLV, tag uint) *TLV {
	for _, t := range tlvs {
		if t.Tag == tag {
			return t
		}
	}
	return nil
}

func parseTag(data []byte) (uint, int, error) {
	if len(data) == 0 {
		return 0, 0, fmt.Errorf("iso7816: empty tag")
	}
	tag := uint(data[0])
	offset := 1

	if data[0]&0x1F == 0x1F {
		for offset < len(data) {
			tag = tag<<8 | uint(data[offset])
			offset++
			if data[offset-1]&0x80 == 0 {
				break
			}
		}
	}
	return tag, offset, nil
}

func parseLength(data []byte) (int, int, error) {
	if len(data) == 0 {
		return 0, 0, fmt.Errorf("iso7816: empty length")
	}
	if data[0] < 0x80 {
		return int(data[0]), 1, nil
	}
	numBytes := int(data[0] & 0x7F)
	if numBytes == 0 || numBytes > 4 {
		return 0, 0, fmt.Errorf("iso7816: unsupported length encoding (%d bytes)", numBytes)
	}
	if 1+numBytes > len(data) {
		return 0, 0, fmt.Errorf("iso7816: length bytes exceed data")
	}
	length := 0
	for i := 1; i <= numBytes; i++ {
		length = length<<8 | int(data[i])
	}
	return length, 1 + numBytes, nil
}

// EncodeTag encodes a BER-TLV tag into its byte representation.
func EncodeTag(tag uint) []byte {
	if tag <= 0xFF {
		return []byte{byte(tag)}
	}
	if tag <= 0xFFFF {
		return []byte{byte(tag >> 8), byte(tag)}
	}
	if tag <= 0xFFFFFF {
		return []byte{byte(tag >> 16), byte(tag >> 8), byte(tag)}
	}
	return []byte{byte(tag >> 24), byte(tag >> 16), byte(tag >> 8), byte(tag)}
}

func encodeLength(length int) []byte {
	if length < 0x80 {
		return []byte{byte(length)}
	}
	if length <= 0xFF {
		return []byte{0x81, byte(length)}
	}
	return []byte{0x82, byte(length >> 8), byte(length)}
}
