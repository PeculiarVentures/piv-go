package app

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/PeculiarVentures/piv-go/adapters/yubikey"
	"github.com/PeculiarVentures/piv-go/emulator"
	"github.com/PeculiarVentures/piv-go/piv"
)

func newAttestationGuardTargets(card *emulator.Card) *TargetResolver {
	return NewTargetResolver(mutationTestCardContextFactory{builders: map[string]func() piv.Card{
		"YubiKey Test": func() piv.Card { return card },
	}}, nil, bytes.NewReader(nil), &bytes.Buffer{})
}

func requireAttestationSlotRejected(t *testing.T, card *emulator.Card, err error) {
	t.Helper()
	if err == nil {
		t.Fatal("expected attestation slot rejection, got nil error")
	}
	var cliErr *CLIError
	if !errors.As(err, &cliErr) {
		t.Fatalf("expected *CLIError, got %T: %v", err, err)
	}
	if cliErr.Code != "usage-error" || cliErr.ExitCode != 1 {
		t.Fatalf("expected usage-error with exit code 1, got %+v", cliErr)
	}
	if !strings.Contains(cliErr.Message, "read-only") || !strings.Contains(cliErr.Hint, "cert export") {
		t.Fatalf("unexpected guard message: %+v", cliErr)
	}
	if len(card.TransmittedCommands) != 0 {
		t.Fatalf("rejected F9 mutation must not send any APDU, got %d commands: % X", len(card.TransmittedCommands), card.TransmittedCommands)
	}
}

func TestParseSlotForMutationRejectsAttestationSlot(t *testing.T) {
	for _, value := range []string{"attestation", "ATTESTATION", "f9", "F9", "0xf9", "0xF9"} {
		_, err := ParseSlotForMutation(value)
		if err == nil || !strings.Contains(err.Error(), "read-only") {
			t.Fatalf("ParseSlotForMutation(%q) expected read-only error, got %v", value, err)
		}
	}
	for _, value := range []string{"9a", "9c", "9d", "9e", "auth", "sign"} {
		if _, err := ParseSlotForMutation(value); err != nil {
			t.Fatalf("ParseSlotForMutation(%q) unexpected error: %v", value, err)
		}
	}
}

func TestMutationsRejectAttestationSlotWithoutAPDU(t *testing.T) {
	slot := yubikey.SlotAttestation
	tests := []struct {
		name string
		call func(service *MutationService) error
	}{
		{"cert-import", func(service *MutationService) error {
			_, err := service.CertImport(context.Background(), CertImportRequest{Slot: slot, Path: "/nonexistent-cert.pem"})
			return err
		}},
		{"cert-delete", func(service *MutationService) error {
			_, err := service.CertDelete(context.Background(), DeleteRequest{Slot: slot})
			return err
		}},
		{"key-generate", func(service *MutationService) error {
			_, err := service.KeyGenerate(context.Background(), KeyGenerateRequest{Slot: slot})
			return err
		}},
		{"key-import", func(service *MutationService) error {
			_, err := service.KeyImport(context.Background(), KeyImportRequest{Slot: slot, Path: "/nonexistent-key.pem"})
			return err
		}},
		{"key-delete", func(service *MutationService) error {
			_, err := service.KeyDelete(context.Background(), DeleteRequest{Slot: slot}, SecretRequest{})
			return err
		}},
		{"key-sign", func(service *MutationService) error {
			_, err := service.KeySign(context.Background(), SignRequest{Slot: slot, InputPath: "/nonexistent-payload.bin"})
			return err
		}},
		{"key-challenge", func(service *MutationService) error {
			_, err := service.KeyChallenge(context.Background(), ChallengeRequest{Slot: slot, ChallengeHex: "00"})
			return err
		}},
		{"setup-reset-slot", func(service *MutationService) error {
			_, err := service.SetupResetSlot(context.Background(), SetupResetSlotRequest{Slot: slot})
			return err
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			card := emulator.NewCard()
			service := NewMutationService(newAttestationGuardTargets(card), nil, bytes.NewReader(nil), &bytes.Buffer{})
			requireAttestationSlotRejected(t, card, test.call(service))
		})
	}
}

func TestAttestRejectsAttestationSlotWithoutAPDU(t *testing.T) {
	card := emulator.NewCard()
	info := NewInfoService(newAttestationGuardTargets(card))
	_, err := info.Attest(context.Background(), ExportRequest{
		Global: GlobalOptions{Reader: "YubiKey Test", NonInteractive: true},
		Slot:   yubikey.SlotAttestation,
	})
	if err == nil || !strings.Contains(err.Error(), "not supported") {
		t.Fatalf("expected unsupported attestation slot error, got %v", err)
	}
	mapped := (&ErrorMapper{}).Map(err)
	if mapped == nil || mapped.Code != "unsupported-capability" || mapped.ExitCode != 4 {
		t.Fatalf("attesting F9 must map to unsupported-capability exit 4, got %+v", mapped)
	}
	if len(card.TransmittedCommands) != 0 {
		t.Fatalf("rejected F9 attest must not send any APDU, got %d commands: % X", len(card.TransmittedCommands), card.TransmittedCommands)
	}
}

func TestAttestOldFirmwareMapsToUnsupportedCapability(t *testing.T) {
	card := emulator.NewCard()
	card.SetSuccessResponse(0xA4, nil)
	card.SetSuccessResponse(0xFD, []byte{0x04, 0x02, 0x09})
	card.SetSuccessResponse(0xF9, []byte{0x30, 0x00})
	info := NewInfoService(newAttestationGuardTargets(card))
	_, err := info.Attest(context.Background(), ExportRequest{
		Global: GlobalOptions{Reader: "YubiKey Test", NonInteractive: true},
		Slot:   piv.SlotSignature,
		Format: "der",
	})
	if err == nil || !strings.Contains(err.Error(), "requires 4.3.0 or later") {
		t.Fatalf("expected firmware requirement error, got %v", err)
	}
	mapped := (&ErrorMapper{}).Map(err)
	if mapped == nil || mapped.Code != "unsupported-capability" || mapped.ExitCode != 4 {
		t.Fatalf("old firmware attest must map to unsupported-capability exit 4, got %+v", mapped)
	}
	for _, command := range card.TransmittedCommands {
		if len(command) > 1 && command[1] == 0xF9 {
			t.Fatalf("ATTEST KEY must not be sent on unsupported firmware: % X", card.TransmittedCommands)
		}
	}
}
