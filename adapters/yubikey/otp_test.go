package yubikey

import (
	"bytes"
	"errors"
	"testing"

	"github.com/PeculiarVentures/piv-go/emulator"
	"github.com/PeculiarVentures/piv-go/iso7816"
	"github.com/PeculiarVentures/piv-go/piv"
)

func assertOTPSelectAndPIVRestore(t *testing.T, card *emulator.Card) {
	t.Helper()
	var selections [][]byte
	for _, raw := range card.TransmittedCommands {
		if len(raw) > 1 && raw[1] == 0xA4 {
			selections = append(selections, raw)
		}
	}
	if len(selections) < 2 {
		t.Fatalf("expected OTP SELECT and PIV restoration, got %d selects", len(selections))
	}
	otp, err := iso7816.ParseCommand(selections[len(selections)-2])
	if err != nil {
		t.Fatal(err)
	}
	pivSelect, err := iso7816.ParseCommand(selections[len(selections)-1])
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(otp.Data, otpAID) || bytes.Equal(pivSelect.Data, otpAID) {
		t.Fatalf("wrong SELECT order: OTP %X, PIV %X", otp.Data, pivSelect.Data)
	}
}

func TestSerialNumberFallsBackToOTPAndRestoresPIV(t *testing.T) {
	card := emulator.NewCard()
	card.SetSuccessResponse(0xA4, nil)
	card.SetResponse(0xF8, nil, uint16(iso7816.SwInsNotSupported))
	card.SetSuccessResponse(0x01, []byte{0x00, 0x4f, 0xf7, 0x60})
	serial, err := NewAdapter().SerialNumber(newYubiKeyPolicySession(card))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(serial, []byte{0x00, 0x4f, 0xf7, 0x60}) {
		t.Fatalf("serial = %X", serial)
	}
	assertOTPSelectAndPIVRestore(t, card)
}

func TestSerialNumberReportsTypedOTPFailureAndRestoresPIV(t *testing.T) {
	card := emulator.NewCard()
	card.SetSuccessResponse(0xA4, nil)
	card.SetResponse(0xF8, nil, uint16(iso7816.SwInsNotSupported))
	card.SetResponse(0x01, nil, uint16(iso7816.SwInsNotSupported))
	_, err := NewAdapter().SerialNumber(newYubiKeyPolicySession(card))
	if !errors.Is(err, ErrSerialNumberUnavailable) || !errors.Is(err, ErrOTPApplet) {
		t.Fatalf("expected typed serial and OTP failures, got %v", err)
	}
	var otpErr *OTPAppletError
	if !errors.As(err, &otpErr) || otpErr.Step != "read serial" {
		t.Fatalf("expected OTP read failure, got %v", err)
	}
	assertOTPSelectAndPIVRestore(t, card)
}

func TestSerialNumberMalformedPIVValueFallsBackToOTP(t *testing.T) {
	card := emulator.NewCard()
	card.SetSuccessResponse(0xA4, nil)
	card.SetSuccessResponse(0xF8, []byte{0x01, 0x02})
	card.SetSuccessResponse(0x01, []byte{0x00, 0x4f, 0xf7, 0x60})
	serial, err := NewAdapter().SerialNumber(newYubiKeyPolicySession(card))
	if err != nil || !bytes.Equal(serial, []byte{0x00, 0x4f, 0xf7, 0x60}) {
		t.Fatalf("OTP serial fallback = %X, %v", serial, err)
	}
	assertOTPSelectAndPIVRestore(t, card)
}

func TestOTPStatusVersionRestoresPIVAndGatesDeleteKey(t *testing.T) {
	card := emulator.NewCard()
	card.SetSuccessResponse(0xA4, nil)
	card.SetSuccessResponse(0x03, []byte{3, 4, 1, 0, 0, 0})
	session := newYubiKeyPolicySession(card)
	version, err := NewAdapter().OTPStatusVersion(session)
	if err != nil || version != "3.4.1" {
		t.Fatalf("OTP status = %q, %v", version, err)
	}
	assertOTPSelectAndPIVRestore(t, card)
	if supported, err := NewAdapter().SupportsDeleteKey(session); err != nil || supported {
		t.Fatalf("NEO delete support = %v, %v", supported, err)
	}
	err = NewAdapter().DeleteKey(session, piv.SlotSignature)
	if !errors.Is(err, ErrKeyDeletionUnsupported) {
		t.Fatalf("expected unsupported delete, got %v", err)
	}
	for _, raw := range card.TransmittedCommands {
		if len(raw) > 1 && (raw[1] == 0xF6 || raw[1] == 0x87) {
			t.Fatalf("old token must reject before management auth or MOVE KEY: %X", raw)
		}
	}
}

func TestOTPStatusVersionRestoreFailureDiscardsData(t *testing.T) {
	card := emulator.NewCard()
	card.EnqueueResponse(0xA4, nil, uint16(iso7816.SwSuccess))
	card.EnqueueResponse(0xA4, nil, uint16(iso7816.SwFileNotFound))
	card.SetSuccessResponse(0x03, []byte{3, 4, 1, 0, 0, 0})
	version, err := NewAdapter().OTPStatusVersion(newYubiKeyPolicySession(card))
	if version != "" || !errors.Is(err, ErrOTPApplet) || !errors.Is(err, ErrPIVRestore) || !iso7816.IsStatus(err, iso7816.SwFileNotFound) {
		t.Fatalf("restore failure must discard version and preserve status, got %q, %v", version, err)
	}
}

func TestDeleteKeyStopsWhenPIVRestoreFails(t *testing.T) {
	card := emulator.NewCard()
	card.EnqueueResponse(0xA4, nil, uint16(iso7816.SwSuccess))
	card.EnqueueResponse(0xA4, nil, uint16(iso7816.SwFileNotFound))
	card.SetSuccessResponse(0x03, []byte{5, 7, 0, 0, 0, 0})
	err := NewAdapter().DeleteKey(newYubiKeyPolicySession(card), piv.SlotSignature)
	if !errors.Is(err, ErrPIVRestore) {
		t.Fatalf("expected PIV restore failure, got %v", err)
	}
	for _, raw := range card.TransmittedCommands {
		if len(raw) > 1 && (raw[1] == 0xF6 || raw[1] == 0x87) {
			t.Fatalf("must not authenticate or delete with unknown applet state: %X", raw)
		}
	}
}

func TestSupportsDeleteKeyAtFirmwareBoundary(t *testing.T) {
	for _, tc := range []struct {
		version string
		want    bool
	}{
		{"3.4.1", false}, {"5.6.9", false}, {"5.7.0", true}, {"6.0.0", true},
	} {
		got, err := supportsDeleteKeyVersion(tc.version)
		if err != nil || got != tc.want {
			t.Fatalf("version %s: support = %v, %v; want %v", tc.version, got, err, tc.want)
		}
	}
}
