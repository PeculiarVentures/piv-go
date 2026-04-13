package piv

import "fmt"

// Reset resets the selected PIV application to its initial state.
// Cards typically require both PIN and PUK to be blocked before accepting it.
func (c *Client) Reset() error {
	resp, err := c.sendCommand(resetCommand())
	if err != nil {
		return fmt.Errorf("piv: reset token: %w", err)
	}
	if err := resp.Err(); err != nil {
		return fmt.Errorf("piv: reset token: %w", err)
	}
	return nil
}
