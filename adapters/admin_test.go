package adapters_test

import (
	"bytes"
	"testing"

	adaptercore "github.com/PeculiarVentures/piv-go/adapters"
	adapteradmin "github.com/PeculiarVentures/piv-go/adapters/admin"
	"github.com/PeculiarVentures/piv-go/piv"

	"github.com/PeculiarVentures/piv-go/emulator"
)

func TestReadPINStatusFallsBackToClient(t *testing.T) {
	mock := emulator.NewCard()
	mock.SetResponse(0x20, nil, 0x63C2)

	status, err := adapteradmin.ReadPINStatus(adaptercore.NewRuntime(adaptercore.NewSession(piv.NewClient(mock)), nil), piv.PINTypeCard)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if status.RetriesLeft != 2 {
		t.Fatalf("unexpected status: %+v", status)
	}
}

func TestChangePINFallsBackToClient(t *testing.T) {
	mock := emulator.NewCard()
	mock.SetSuccessResponse(0x24, nil)

	err := adapteradmin.ChangePIN(adaptercore.NewRuntime(adaptercore.NewSession(piv.NewClient(mock)), nil), "123456", "654321")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got := mock.TransmittedCommands[0]; !bytes.Equal(got[:4], []byte{0x00, 0x24, 0x00, 0x80}) {
		t.Fatalf("unexpected APDU: %X", got)
	}
}

func TestChangeManagementKeyRequiresCapability(t *testing.T) {
	err := adapteradmin.ChangeManagementKey(adaptercore.NewRuntime(adaptercore.NewSession(piv.NewClient(emulator.NewCard())), nil), piv.AlgAES128, make([]byte, 16))
	if err == nil {
		t.Fatal("expected unsupported capability error")
	}
}

func TestResetTokenFallsBackToClient(t *testing.T) {
	mock := emulator.NewCard()
	mock.SetSuccessResponse(0xFB, nil)

	err := adapteradmin.ResetToken(adaptercore.NewRuntime(adaptercore.NewSession(piv.NewClient(mock)), nil), adaptercore.ResetTokenParams{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got := mock.TransmittedCommands[0]; !bytes.Equal(got, []byte{0x00, 0xFB, 0x00, 0x00}) {
		t.Fatalf("unexpected APDU: %X", got)
	}
}
