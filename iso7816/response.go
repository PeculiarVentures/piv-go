package iso7816

import "fmt"

// Response represents an ISO 7816 response APDU.
type Response struct {
	Data []byte
	SW1  byte
	SW2  byte
}

// StatusWord returns the combined SW1/SW2 status word.
func (r *Response) StatusWord() uint16 {
	return uint16(r.SW1)<<8 | uint16(r.SW2)
}

// IsSuccess returns true if the status word indicates success (0x9000).
func (r *Response) IsSuccess() bool {
	return r.SW1 == 0x90 && r.SW2 == 0x00
}

// HasMoreData returns true if SW1 indicates more data is available (0x61xx).
func (r *Response) HasMoreData() bool {
	return r.SW1 == 0x61
}

// Err returns an error if the response indicates a non-success status.
func (r *Response) Err() error {
	if r.IsSuccess() || r.HasMoreData() {
		return nil
	}
	return StatusError(r.StatusWord())
}

// ParseResponse parses a raw response byte slice into a Response.
func ParseResponse(raw []byte) (*Response, error) {
	if len(raw) < 2 {
		return nil, fmt.Errorf("iso7816: response too short (%d bytes)", len(raw))
	}
	resp := &Response{
		SW1: raw[len(raw)-2],
		SW2: raw[len(raw)-1],
	}
	if len(raw) > 2 {
		resp.Data = make([]byte, len(raw)-2)
		copy(resp.Data, raw[:len(raw)-2])
	}
	return resp, nil
}
