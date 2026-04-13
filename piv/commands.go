package piv

import (
	"fmt"

	"github.com/PeculiarVentures/piv-go/iso7816"
)

// selectCommand returns the SELECT command APDU for the PIV application.
func selectCommand() *iso7816.Command {
	return &iso7816.Command{
		Cla:  0x00,
		Ins:  0xA4, // SELECT
		P1:   0x04, // Select by AID
		P2:   0x00,
		Data: pivAID,
		Le:   256,
	}
}

// getDataCommand returns a GET DATA command APDU for the specified object tag.
func getDataCommand(tag uint) *iso7816.Command {
	tagTLV := iso7816.EncodeTLV(0x5C, iso7816.EncodeTag(tag))
	return &iso7816.Command{
		Cla:  0x00,
		Ins:  0xCB, // GET DATA
		P1:   0x3F,
		P2:   0xFF,
		Data: tagTLV,
		Le:   256,
	}
}

// verifyPINCommand returns a VERIFY command APDU.
func verifyPINCommand(pin string) *iso7816.Command {
	paddedPIN := padPIN(pin)
	return &iso7816.Command{
		Cla:  0x00,
		Ins:  0x20, // VERIFY
		P1:   0x00,
		P2:   0x80, // PIV Card Application PIN
		Data: paddedPIN,
		Le:   -1,
	}
}

func verifyPINStatusCommand(pinType PINType) *iso7816.Command {
	return &iso7816.Command{
		Cla: 0x00,
		Ins: 0x20, // VERIFY
		P1:  0x00,
		P2:  byte(pinType),
		Le:  -1,
	}
}

func changeReferenceDataCommand(pinType PINType, currentValue string, newValue string) (*iso7816.Command, error) {
	data, err := encodedReferenceData(currentValue, newValue)
	if err != nil {
		return nil, err
	}
	return &iso7816.Command{
		Cla:  0x00,
		Ins:  0x24, // CHANGE REFERENCE DATA
		P1:   0x00,
		P2:   byte(pinType),
		Data: data,
		Le:   -1,
	}, nil
}

func resetRetryCounterCommand(puk string, newPIN string) (*iso7816.Command, error) {
	data, err := encodedReferenceData(puk, newPIN)
	if err != nil {
		return nil, err
	}
	return &iso7816.Command{
		Cla:  0x00,
		Ins:  0x2C, // RESET RETRY COUNTER
		P1:   0x00,
		P2:   byte(PINTypeCard),
		Data: data,
		Le:   -1,
	}, nil
}

func resetCommand() *iso7816.Command {
	return &iso7816.Command{
		Cla: 0x00,
		Ins: 0xFB, // RESET
		P1:  0x00,
		P2:  0x00,
		Le:  -1,
	}
}

func encodedReferenceData(currentValue string, newValue string) ([]byte, error) {
	currentEncoded, err := encodeReferenceValue("current value", currentValue)
	if err != nil {
		return nil, err
	}
	newEncoded, err := encodeReferenceValue("new value", newValue)
	if err != nil {
		return nil, err
	}
	data := append([]byte{}, currentEncoded...)
	data = append(data, newEncoded...)
	return data, nil
}

func encodeReferenceValue(name string, value string) ([]byte, error) {
	if len(value) == 0 {
		return nil, fmt.Errorf("piv: %s is required", name)
	}
	if len(value) > 8 {
		return nil, fmt.Errorf("piv: %s must be 8 bytes or fewer", name)
	}
	return padPIN(value), nil
}

// generalAuthenticateCommand returns a GENERAL AUTHENTICATE command APDU.
func generalAuthenticateCommand(alg byte, slot Slot, challenge []byte) *iso7816.Command {
	// Build dynamic authentication template (tag 0x7C)
	// 0x82 = response placeholder, 0x81 = challenge.
	// SafeNet requires this TLV order for signing.
	inner := iso7816.EncodeTLV(0x82, nil)
	inner = append(inner, iso7816.EncodeTLV(0x81, challenge)...)
	authTemplate := iso7816.EncodeTLV(0x7C, inner)

	return &iso7816.Command{
		Cla:  0x00,
		Ins:  0x87, // GENERAL AUTHENTICATE
		P1:   alg,
		P2:   byte(slot),
		Data: authTemplate,
		Le:   256,
	}
}

func managementAuthenticateCommand(alg byte, data []byte) *iso7816.Command {
	return &iso7816.Command{
		Cla:  0x00,
		Ins:  0x87, // GENERAL AUTHENTICATE
		P1:   alg,
		P2:   byte(SlotManagement),
		Data: data,
		Le:   256,
	}
}

func generateAsymmetricKeyPairCommand(slot Slot, alg byte) *iso7816.Command {
	controlReference := iso7816.EncodeTLV(0x80, []byte{alg})
	data := iso7816.EncodeTLV(0xAC, controlReference)

	return &iso7816.Command{
		Cla:  0x00,
		Ins:  0x47, // GENERATE ASYMMETRIC KEY PAIR
		P1:   0x00,
		P2:   byte(slot),
		Data: data,
		Le:   256,
	}
}

// padPIN pads the PIN to 8 bytes with 0xFF as required by PIV.
func padPIN(pin string) []byte {
	padded := make([]byte, 8)
	for i := range padded {
		padded[i] = 0xFF
	}
	copy(padded, []byte(pin))
	return padded
}
