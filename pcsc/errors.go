package pcsc

import "fmt"

// Error represents a PC/SC transport error.
type Error struct {
	Op  string
	Err error
}

func (e *Error) Error() string {
	return fmt.Sprintf("pcsc: %s: %v", e.Op, e.Err)
}

func (e *Error) Unwrap() error {
	return e.Err
}

func wrapError(op string, err error) error {
	return &Error{Op: op, Err: err}
}
