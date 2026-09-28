package adapters

import "fmt"

// TokenIdentity contains the raw serial and the adapter's display label.
// Each value has an independent read error so a failed label query does not
// discard a successfully read serial number.
type TokenIdentity struct {
	SerialNumber []byte
	Label        string
	SerialError  error
	LabelError   error
}

// TokenIdentityAdapter can provide both identity values from one serial read.
type TokenIdentityAdapter interface {
	Identity(session *Session) (TokenIdentity, error)
}

// ReadTokenIdentity reads identity using a resolved runtime.
func ReadTokenIdentity(runtime *Runtime) (TokenIdentity, error) {
	if runtime == nil {
		return TokenIdentity{}, fmt.Errorf("adapters: runtime is required")
	}
	return ReadTokenIdentityWithSession(runtime.Session, runtime.Adapter)
}

// ReadTokenIdentityWithSession reads the token's serial and display label.
// It returns a top-level error only when the session cannot be used; ordinary
// field failures are reported through TokenIdentity.SerialError/LabelError.
func ReadTokenIdentityWithSession(session *Session, adapter Adapter) (TokenIdentity, error) {
	if session == nil || session.Client == nil {
		return TokenIdentity{}, fmt.Errorf("adapters: session client is required")
	}
	if identityAdapter, ok := adapter.(TokenIdentityAdapter); ok {
		return identityAdapter.Identity(session)
	}
	serial, serialErr := ReadSerialNumberWithSession(session, adapter)
	label, labelErr := ReadTokenLabelWithSession(session, adapter)
	return TokenIdentity{
		SerialNumber: append([]byte(nil), serial...),
		Label:        label,
		SerialError:  serialErr,
		LabelError:   labelErr,
	}, nil
}
