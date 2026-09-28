package app

import (
	"strings"
	"testing"

	"github.com/PeculiarVentures/piv-go/adapters"
	"github.com/PeculiarVentures/piv-go/adapters/yubikey"
	"github.com/PeculiarVentures/piv-go/piv"
)

func TestParseSlotAttestationAliases(t *testing.T) {
	for _, value := range []string{"attestation", "ATTESTATION", "f9", "F9", "0xf9"} {
		slot, err := ParseSlot(value)
		if err != nil {
			t.Fatalf("ParseSlot(%q) error = %v", value, err)
		}
		if slot != yubikey.SlotAttestation {
			t.Fatalf("ParseSlot(%q) = %s, want YubiKey attestation slot %s", value, slot, yubikey.SlotAttestation)
		}
	}
	if yubikey.SlotAttestation != piv.Slot(0xF9) {
		t.Fatalf("attestation slot = %s, want F9", yubikey.SlotAttestation)
	}
}

func TestParseSlotKeepsPrimarySlots(t *testing.T) {
	slot, err := ParseSlot("9c")
	if err != nil {
		t.Fatalf("ParseSlot(9c) error = %v", err)
	}
	if slot != piv.SlotSignature {
		t.Fatalf("ParseSlot(9c) = %s, want %s", slot, piv.SlotSignature)
	}
}

func TestAttestKeyUnsupportedAdapter(t *testing.T) {
	runtime := &adapters.Runtime{Adapter: fakeAdapter{name: "safenet"}}
	_, err := attestKey(runtime, piv.SlotSignature)
	if err == nil || !strings.Contains(err.Error(), "not supported") {
		t.Fatalf("expected unsupported attestation error, got %v", err)
	}
}
