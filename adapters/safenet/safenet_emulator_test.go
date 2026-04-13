package safenet

import (
	"testing"

	"github.com/PeculiarVentures/piv-go/adapters"
	"github.com/PeculiarVentures/piv-go/piv"
)

func TestNewDeleteKeyEmulatorCardSupportsDeleteKeyFlow(t *testing.T) {
	session := &adapters.Session{
		Client:        piv.NewClient(NewDeleteKeyEmulatorCard()),
		ReaderName:    "SafeNet eToken Fusion",
		ManagementKey: append([]byte(nil), defaultManagementKey...),
	}

	if err := NewAdapter().DeleteKey(session, piv.SlotAuthentication); err != nil {
		t.Fatalf("DeleteKey() error = %v", err)
	}
}

func TestNewGenerateKeyEmulatorCardSupportsVendorGenerateKeyFlow(t *testing.T) {
	client := piv.NewClient(NewGenerateKeyEmulatorCard(piv.SlotAuthentication))
	if err := client.Select(); err != nil {
		t.Fatalf("Select() error = %v", err)
	}

	session := &adapters.Session{
		Client:        client,
		ReaderName:    "SafeNet eToken Fusion",
		ManagementKey: append([]byte(nil), defaultManagementKey...),
	}

	adapter := NewAdapter()
	if err := adapter.PrepareGenerateKey(session, piv.SlotAuthentication, piv.AlgECCP256); err != nil {
		t.Fatalf("PrepareGenerateKey() error = %v", err)
	}

	publicKey, err := client.GenerateKeyPair(piv.SlotAuthentication, piv.AlgECCP256)
	if err != nil {
		t.Fatalf("GenerateKeyPair() error = %v", err)
	}

	if err := adapter.FinalizeGenerateKey(session, piv.SlotAuthentication, piv.AlgECCP256, publicKey); err != nil {
		t.Fatalf("FinalizeGenerateKey() error = %v", err)
	}
}
