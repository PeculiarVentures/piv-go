package yubikey

import (
	"testing"

	"github.com/PeculiarVentures/piv-go/adapters"
	adapteradmin "github.com/PeculiarVentures/piv-go/adapters/admin"
	"github.com/PeculiarVentures/piv-go/emulator"
	"github.com/PeculiarVentures/piv-go/iso7816"
	"github.com/PeculiarVentures/piv-go/piv"
)

// YubiKey 4 (FW 4.2.8) answers the PUK VERIFY status probe (00 20 00 81)
// with 6A80 instead of 6A88. The PUK-only fallback must treat it as
// unknown retries, not an error, so CLI layers never see it as usage-error.
func TestYubiKeyAdapterPUKStatus6A80(t *testing.T) {
	mock := emulator.NewCard()
	mock.SetResponse(0x20, nil, 0x6A80)

	session := &adapters.Session{Client: piv.NewClient(mock), ReaderName: "Yubico YubiKey OTP+FIDO+CCID"}
	adpt := NewAdapter()

	status, err := adapteradmin.ReadPINStatus(adapters.NewRuntime(session, adpt), piv.PINTypePUK)
	if err != nil {
		t.Fatalf("expected no error for 6A80 puk status fallback, got %v", err)
	}
	if status.RetriesLeft != -1 {
		t.Fatalf("expected unknown retries (-1), got %d", status.RetriesLeft)
	}
	if status.Type != piv.PINTypePUK {
		t.Fatalf("expected PUK status type, got %v", status.Type)
	}
}

// PIN (0x80) 6A80 must still surface as an error; the graceful fallback is
// PUK-only so genuine wrong-data failures are not masked.
func TestYubiKeyAdapterPINStatus6A80StillErrors(t *testing.T) {
	mock := emulator.NewCard()
	mock.SetResponse(0x20, nil, 0x6A80)

	session := &adapters.Session{Client: piv.NewClient(mock), ReaderName: "Yubico YubiKey OTP+FIDO+CCID"}
	adpt := NewAdapter()

	_, err := adapteradmin.ReadPINStatus(adapters.NewRuntime(session, adpt), piv.PINTypeCard)
	if err == nil {
		t.Fatal("expected error for 6A80 PIN status probe, got nil")
	}
	if !iso7816.IsStatus(err, iso7816.SwWrongData) {
		t.Fatalf("expected 6A80 wrong-data error, got %v", err)
	}
}
