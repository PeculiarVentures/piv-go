package adapters_test

import (
	"testing"

	"github.com/PeculiarVentures/piv-go/adapters"
	"github.com/PeculiarVentures/piv-go/adapters/admin"
	"github.com/PeculiarVentures/piv-go/adapters/safenet"
	"github.com/PeculiarVentures/piv-go/adapters/yubikey"
	"github.com/PeculiarVentures/piv-go/emulator"
	"github.com/PeculiarVentures/piv-go/piv"
)

var (
	_ adapters.TokenResetAdapter = (*yubikey.Adapter)(nil)
	_ adapters.TokenResetAdapter = (*safenet.Adapter)(nil)
	_ adapters.SlotResetAdapter  = (*safenet.Adapter)(nil)
	_ adapters.ResetAdapter      = (*safenet.Adapter)(nil)
)

func TestResetRequirementsStayProviderSpecific(t *testing.T) {
	for _, tc := range []struct {
		name        string
		adapter     adapters.Adapter
		requiresPUK bool
	}{
		{"YubiKey", yubikey.NewAdapter(), false},
		{"SafeNet", safenet.NewAdapter(), true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			card := emulator.NewCard()
			runtime := adapters.NewRuntime(adapters.NewSession(piv.NewClient(card)), tc.adapter)
			requirements, err := admin.DescribeReset(runtime)
			if err != nil {
				t.Fatal(err)
			}
			if requirements.RequiresPUK != tc.requiresPUK {
				t.Fatalf("RequiresPUK=%t, want %t", requirements.RequiresPUK, tc.requiresPUK)
			}
			if len(card.TransmittedCommands) != 0 {
				t.Fatalf("describing reset changed token: %X", card.TransmittedCommands)
			}
		})
	}
}

func TestYubiKeySlotResetRemainsUnsupported(t *testing.T) {
	card := emulator.NewCard()
	runtime := adapters.NewRuntime(adapters.NewSession(piv.NewClient(card)), yubikey.NewAdapter())
	if err := admin.ResetSlot(runtime, piv.SlotSignature); err == nil {
		t.Fatal("YubiKey must not acquire SafeNet slot reset")
	}
	if len(card.TransmittedCommands) != 0 {
		t.Fatalf("unsupported slot reset sent commands: %X", card.TransmittedCommands)
	}
}

func TestSafeNetTokenResetStillRequiresPUKBeforeAPDU(t *testing.T) {
	card := emulator.NewCard()
	runtime := adapters.NewRuntime(adapters.NewSession(piv.NewClient(card)), safenet.NewAdapter())
	if err := admin.ResetToken(runtime, adapters.ResetTokenParams{}); err == nil {
		t.Fatal("SafeNet reset must require its PUK")
	}
	if len(card.TransmittedCommands) != 0 {
		t.Fatalf("SafeNet dispatched reset without PUK: %X", card.TransmittedCommands)
	}
}
