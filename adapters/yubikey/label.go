package yubikey

import (
	"errors"
	"fmt"
	"math/big"

	"github.com/PeculiarVentures/piv-go/adapters"
)

// Label returns the token label for YubiKey tokens.
//
// This follows the pkcs11-tool convention of formatting YubiKey PIV labels as
// "YubiKey PIV #<serial>" where <serial> is the decimal representation of the
// YubiKey serial number.
func (a *Adapter) Label(session *adapters.Session) (string, error) {
	identity, err := a.Identity(session)
	if err != nil {
		return "", err
	}
	return identity.Label, identity.LabelError
}

// Identity returns serial and label from one serial-number query.
func (a *Adapter) Identity(session *adapters.Session) (adapters.TokenIdentity, error) {
	serialBytes, err := a.SerialNumber(session)
	if err != nil {
		if errors.Is(err, ErrPIVRestore) {
			return adapters.TokenIdentity{}, err
		}
		return adapters.TokenIdentity{SerialError: err, LabelError: err}, nil
	}
	serial := new(big.Int).SetBytes(serialBytes)
	return adapters.TokenIdentity{
		SerialNumber: serialBytes,
		Label:        fmt.Sprintf("YubiKey PIV #%s", serial.String()),
	}, nil
}
