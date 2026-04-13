package piv

import (
	"bytes"
	"testing"

	"github.com/PeculiarVentures/piv-go/iso7816"

	"github.com/PeculiarVentures/piv-go/emulator"
)

func TestClientPINStatusReportsRetries(t *testing.T) {
	mock := emulator.NewCard()
	mock.SetResponse(0x20, nil, 0x63C3)

	status, err := NewClient(mock).PINStatus(PINTypeCard)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if status.RetriesLeft != 3 || status.Blocked || status.Verified {
		t.Fatalf("unexpected status: %+v", status)
	}
	if got := mock.TransmittedCommands[0]; !bytes.Equal(got, []byte{0x00, 0x20, 0x00, 0x80}) {
		t.Fatalf("unexpected APDU: %X", got)
	}
}

func TestClientPINStatusReportsBlocked(t *testing.T) {
	mock := emulator.NewCard()
	mock.SetResponse(0x20, nil, uint16(iso7816.SwAuthBlocked))

	status, err := NewClient(mock).PINStatus(PINTypePUK)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !status.Blocked || status.RetriesLeft != 0 {
		t.Fatalf("unexpected status: %+v", status)
	}
}

func TestClientChangePINUsesStandardAPDU(t *testing.T) {
	mock := emulator.NewCard()
	mock.SetSuccessResponse(0x24, nil)

	if err := NewClient(mock).ChangePIN("123456", "654321"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	want := []byte{0x00, 0x24, 0x00, 0x80, 0x10, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0xFF, 0xFF, 0x36, 0x35, 0x34, 0x33, 0x32, 0x31, 0xFF, 0xFF}
	if got := mock.TransmittedCommands[0]; !bytes.Equal(got, want) {
		t.Fatalf("unexpected APDU: %X", got)
	}
}

func TestClientChangePUKUsesStandardAPDU(t *testing.T) {
	mock := emulator.NewCard()
	mock.SetSuccessResponse(0x24, nil)

	if err := NewClient(mock).ChangePUK("12345678", "87654321"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	want := []byte{0x00, 0x24, 0x00, 0x81, 0x10, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x38, 0x37, 0x36, 0x35, 0x34, 0x33, 0x32, 0x31}
	if got := mock.TransmittedCommands[0]; !bytes.Equal(got, want) {
		t.Fatalf("unexpected APDU: %X", got)
	}
}

func TestClientUnblockPINUsesResetRetryCounter(t *testing.T) {
	mock := emulator.NewCard()
	mock.SetSuccessResponse(0x2C, nil)

	if err := NewClient(mock).UnblockPIN("12345678", "123456"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	want := []byte{0x00, 0x2C, 0x00, 0x80, 0x10, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0xFF, 0xFF}
	if got := mock.TransmittedCommands[0]; !bytes.Equal(got, want) {
		t.Fatalf("unexpected APDU: %X", got)
	}
}

func TestClientResetUsesStandardCommand(t *testing.T) {
	mock := emulator.NewCard()
	mock.SetSuccessResponse(0xFB, nil)

	if err := NewClient(mock).Reset(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got := mock.TransmittedCommands[0]; !bytes.Equal(got, []byte{0x00, 0xFB, 0x00, 0x00}) {
		t.Fatalf("unexpected APDU: %X", got)
	}
}

func TestClientChangePINRejectsLongValues(t *testing.T) {
	err := NewClient(emulator.NewCard()).ChangePIN("123456789", "654321")
	if err == nil {
		t.Fatal("expected validation error")
	}
}
