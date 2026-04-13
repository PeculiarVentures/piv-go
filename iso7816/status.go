package iso7816

import (
	"errors"
	"fmt"
)

// Well-known ISO 7816 status words.
const (
	SwSuccess                uint16 = 0x9000
	SwFileNotFound           uint16 = 0x6A82
	SwSecurityNotSatisfied   uint16 = 0x6982
	SwAuthBlocked            uint16 = 0x6983
	SwConditionsNotMet       uint16 = 0x6985
	SwWrongData              uint16 = 0x6A80
	SwReferencedDataNotFound uint16 = 0x6A88
	SwIncorrectP1P2          uint16 = 0x6A86
	SwWrongLength            uint16 = 0x6700
	SwInsNotSupported        uint16 = 0x6D00
	SwClaNotSupported        uint16 = 0x6E00
	SwUnknown                uint16 = 0x6F00
)

var statusMessages = map[uint16]string{
	SwSuccess:                "success",
	SwFileNotFound:           "file not found",
	SwSecurityNotSatisfied:   "security status not satisfied",
	SwAuthBlocked:            "authentication method blocked",
	SwConditionsNotMet:       "conditions of use not satisfied",
	SwWrongData:              "wrong data",
	SwReferencedDataNotFound: "referenced data not found",
	SwIncorrectP1P2:          "incorrect P1/P2",
	SwWrongLength:            "wrong length",
	SwInsNotSupported:        "instruction not supported",
	SwClaNotSupported:        "class not supported",
	SwUnknown:                "unknown error",
}

type statusWordCarrier interface {
	StatusWord() uint16
}

type statusError struct {
	sw uint16
}

func (e *statusError) StatusWord() uint16 {
	return e.sw
}

func (e *statusError) Error() string {
	msg, ok := statusMessages[e.sw]
	if !ok {
		msg = "unknown status"
	}
	return fmt.Sprintf("iso7816: status %04X: %s", e.sw, msg)
}

func (e *statusError) Is(target error) bool {
	t, ok := target.(*statusError)
	if !ok {
		return false
	}
	return e.sw == t.sw
}

// StatusError returns an error for the given status word.
func StatusError(sw uint16) error {
	return &statusError{sw: sw}
}

// StatusWordFromError extracts an ISO 7816 status word from err, including wrapped errors.
func StatusWordFromError(err error) (uint16, bool) {
	if err == nil {
		return 0, false
	}

	var carrier statusWordCarrier
	if !errors.As(err, &carrier) {
		return 0, false
	}
	return carrier.StatusWord(), true
}

// IsStatus reports whether err matches the provided status word.
func IsStatus(err error, sw uint16) bool {
	status, ok := StatusWordFromError(err)
	return ok && status == sw
}

// IsPINRetryStatus returns true if the status word indicates remaining PIN retries.
// In that case, the number of remaining retries is (sw & 0x0F).
func IsPINRetryStatus(sw uint16) (int, bool) {
	if sw&0xFFF0 == 0x63C0 {
		return int(sw & 0x0F), true
	}
	return 0, false
}
