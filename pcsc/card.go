package pcsc

import "github.com/ebfe/scard"

var apduLogger func(direction string, payload []byte)

// SetAPDULogger configures a callback that receives APDU request and response
// frames sent through the PC/SC transport.
func SetAPDULogger(logger func(direction string, payload []byte)) {
	apduLogger = logger
}

// Card wraps scard.Card and implements the transport-level card interface.
type Card struct {
	card *scard.Card
}

// Transmit sends the given APDU command to the card and returns the response.
func (c *Card) Transmit(command []byte) ([]byte, error) {
	if apduLogger != nil {
		apduLogger("->", command)
	}
	resp, err := c.card.Transmit(command)
	if err != nil {
		return nil, wrapError("transmit", err)
	}
	if apduLogger != nil {
		apduLogger("<-", resp)
	}
	return resp, nil
}

// Begin starts a transaction on the card.
func (c *Card) Begin() error {
	if err := c.card.BeginTransaction(); err != nil {
		return wrapError("begin transaction", err)
	}
	return nil
}

// End ends a transaction on the card.
func (c *Card) End() error {
	if err := c.card.EndTransaction(scard.LeaveCard); err != nil {
		return wrapError("end transaction", err)
	}
	return nil
}

// Close disconnects the card from the reader.
func (c *Card) Close() error {
	if err := c.card.Disconnect(scard.LeaveCard); err != nil {
		return wrapError("disconnect", err)
	}
	return nil
}
