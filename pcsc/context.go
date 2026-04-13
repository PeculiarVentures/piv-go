package pcsc

import "github.com/ebfe/scard"

// Context wraps scard.Context and provides methods for reader discovery
// and card connection.
type Context struct {
	ctx *scard.Context
}

// NewContext establishes a new PC/SC context.
func NewContext() (*Context, error) {
	ctx, err := scard.EstablishContext()
	if err != nil {
		return nil, wrapError("establish context", err)
	}
	return &Context{ctx: ctx}, nil
}

// ListReaders returns the names of all connected PC/SC readers.
func (c *Context) ListReaders() ([]string, error) {
	readers, err := c.ctx.ListReaders()
	if err != nil {
		return nil, wrapError("list readers", err)
	}
	return readers, nil
}

// Connect connects to a card in the named reader using the shared protocol.
func (c *Context) Connect(reader string) (*Card, error) {
	sc, err := c.ctx.Connect(reader, scard.ShareShared, scard.ProtocolAny)
	if err != nil {
		return nil, wrapError("connect", err)
	}
	return &Card{card: sc}, nil
}

// Release releases the PC/SC context.
func (c *Context) Release() error {
	if err := c.ctx.Release(); err != nil {
		return wrapError("release context", err)
	}
	return nil
}
