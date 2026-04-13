package piv

// Card defines the interface for smart card communication.
// This abstraction allows the PIV layer to be independent of the transport.
type Card interface {
	Transmit(command []byte) ([]byte, error)
	Begin() error
	End() error
	Close() error
}
