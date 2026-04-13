package iso7816

import "fmt"

// Command represents an ISO 7816 command APDU.
type Command struct {
	Cla  byte
	Ins  byte
	P1   byte
	P2   byte
	Data []byte
	Le   int // expected response length; -1 means no Le field
}

// Bytes encodes the command APDU into a byte slice.
func (c *Command) Bytes() []byte {
	header := []byte{c.Cla, c.Ins, c.P1, c.P2}
	dataLen := len(c.Data)

	if dataLen == 0 && c.Le < 0 {
		// Case 1: no data, no Le
		return header
	}

	if dataLen == 0 && c.Le >= 0 {
		// Case 2: no data, Le present
		buf := make([]byte, 5)
		copy(buf, header)
		if c.Le == 256 {
			buf[4] = 0x00
		} else {
			buf[4] = byte(c.Le)
		}
		return buf
	}

	if dataLen > 0 && c.Le < 0 {
		// Case 3: data present, no Le
		buf := make([]byte, 5+dataLen)
		copy(buf, header)
		buf[4] = byte(dataLen)
		copy(buf[5:], c.Data)
		return buf
	}

	// Case 4: data present, Le present
	buf := make([]byte, 6+dataLen)
	copy(buf, header)
	buf[4] = byte(dataLen)
	copy(buf[5:], c.Data)
	if c.Le == 256 {
		buf[5+dataLen] = 0x00
	} else {
		buf[5+dataLen] = byte(c.Le)
	}
	return buf
}

// ParseCommand parses a raw byte slice into a Command.
func ParseCommand(raw []byte) (*Command, error) {
	if len(raw) < 4 {
		return nil, fmt.Errorf("iso7816: command too short (%d bytes)", len(raw))
	}
	cmd := &Command{
		Cla: raw[0],
		Ins: raw[1],
		P1:  raw[2],
		P2:  raw[3],
		Le:  -1,
	}

	if len(raw) == 4 {
		return cmd, nil
	}

	if len(raw) == 5 {
		le := int(raw[4])
		if le == 0 {
			le = 256
		}
		cmd.Le = le
		return cmd, nil
	}

	lc := int(raw[4])
	if len(raw) < 5+lc {
		return nil, fmt.Errorf("iso7816: data length mismatch: Lc=%d, available=%d", lc, len(raw)-5)
	}
	cmd.Data = make([]byte, lc)
	copy(cmd.Data, raw[5:5+lc])

	if len(raw) == 5+lc {
		return cmd, nil
	}

	if len(raw) == 6+lc {
		le := int(raw[5+lc])
		if le == 0 {
			le = 256
		}
		cmd.Le = le
		return cmd, nil
	}

	return nil, fmt.Errorf("iso7816: unexpected command length %d", len(raw))
}
