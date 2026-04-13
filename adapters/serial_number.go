package adapters

import "fmt"

var ErrSerialNumberUnsupported = fmt.Errorf("adapters: serial number is not supported by this token")

// ReadSerialNumber reads the token serial number using the resolved runtime.
func ReadSerialNumber(runtime *Runtime) ([]byte, error) {
	return ReadSerialNumberWithSession(runtime.Session, runtime.Adapter)
}

// ReadSerialNumberWithSession reads the token serial number for the provided
// session and adapter pair.
func ReadSerialNumberWithSession(session *Session, adapter Adapter) ([]byte, error) {
	if session == nil {
		return nil, fmt.Errorf("adapters: session is required")
	}
	if serialAdapter, ok := adapter.(SerialNumberAdapter); ok {
		return serialAdapter.SerialNumber(session)
	}
	return nil, ErrSerialNumberUnsupported
}
