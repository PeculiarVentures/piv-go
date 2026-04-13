package yubikey

import (
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
	serialBytes, err := a.SerialNumber(session)
	if err != nil {
		return "", err
	}
	serial := new(big.Int).SetBytes(serialBytes)
	return fmt.Sprintf("YubiKey PIV #%s", serial.String()), nil
}
