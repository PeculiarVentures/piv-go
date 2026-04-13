package adapters

import "fmt"

var ErrTokenLabelUnsupported = fmt.Errorf("adapters: token label is not supported by this token")

// ReadTokenLabel reads the token label using the resolved runtime.
func ReadTokenLabel(runtime *Runtime) (string, error) {
	return ReadTokenLabelWithSession(runtime.Session, runtime.Adapter)
}

// ReadTokenLabelWithSession reads the token label for the provided session and
// adapter pair.
func ReadTokenLabelWithSession(session *Session, adapter Adapter) (string, error) {
	if session == nil {
		return "", fmt.Errorf("adapters: session is required")
	}
	if labelAdapter, ok := adapter.(LabelAdapter); ok {
		return labelAdapter.Label(session)
	}
	return "", ErrTokenLabelUnsupported
}
