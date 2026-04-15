package app

import (
	"bytes"
	"context"
	"crypto/elliptic"
	"os"
	"path/filepath"
	"testing"

	"github.com/PeculiarVentures/piv-go/adapters"
	internalutil "github.com/PeculiarVentures/piv-go/internal"
	"github.com/PeculiarVentures/piv-go/iso7816"
	"github.com/PeculiarVentures/piv-go/piv"

	"github.com/PeculiarVentures/piv-go/emulator"
)

type mutationTestCardContextFactory struct {
	builders map[string]func() piv.Card
}

type mutationTestCardContext struct {
	builders map[string]func() piv.Card
}

func (f mutationTestCardContextFactory) NewContext() (CardContext, error) {
	return &mutationTestCardContext{builders: f.builders}, nil
}

func (c *mutationTestCardContext) ListReaders() ([]string, error) {
	readers := make([]string, 0, len(c.builders))
	for reader := range c.builders {
		readers = append(readers, reader)
	}
	return readers, nil
}

func (c *mutationTestCardContext) Connect(reader string) (piv.Card, error) {
	return c.builders[reader](), nil
}

func (c *mutationTestCardContext) Release() error { return nil }

func TestShouldPromptPINForSign(t *testing.T) {
	tests := []struct {
		name       string
		policy     string
		explicit   bool
		wantPrompt bool
	}{
		{name: "unknown policy", policy: string(adapters.PINPolicyUnknown), wantPrompt: true},
		{name: "never policy", policy: string(adapters.PINPolicyNever), wantPrompt: false},
		{name: "once policy", policy: string(adapters.PINPolicyOnce), wantPrompt: true},
		{name: "always policy", policy: string(adapters.PINPolicyAlways), wantPrompt: true},
		{name: "explicit pin overrides never", policy: string(adapters.PINPolicyNever), explicit: true, wantPrompt: true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			prompt := shouldPromptPINForSign(adapters.SignAuthorization{PINPolicy: adapters.PINPolicy(test.policy)}, test.explicit)
			if prompt != test.wantPrompt {
				t.Fatalf("shouldPromptPINForSign() = %t, want %t", prompt, test.wantPrompt)
			}
		})
	}
}

func TestKeySignSkipsVerifyWhenPolicyAllowsSigningWithoutPIN(t *testing.T) {
	card := newSigningTestCard(t, true, 0x01)
	targets := NewTargetResolver(mutationTestCardContextFactory{builders: map[string]func() piv.Card{
		"YubiKey Test": func() piv.Card { return card },
	}}, nil, bytes.NewReader(nil), &bytes.Buffer{})
	service := NewMutationService(targets, nil, bytes.NewReader(nil), &bytes.Buffer{})
	payloadPath := writeSigningPayload(t)

	if _, err := service.KeySign(context.Background(), SignRequest{Global: GlobalOptions{Reader: "YubiKey Test", NonInteractive: true}, Slot: piv.SlotSignature, InputPath: payloadPath, Hash: "sha256", Encoding: "base64", PIN: SecretRequest{Label: "PIN", EnvVar: "PIV_PIN"}}); err != nil {
		t.Fatalf("KeySign() error = %v", err)
	}
	if hasINS(card.TransmittedCommands, 0x20) {
		t.Fatalf("expected sign flow without VERIFY, got commands: % X", card.TransmittedCommands)
	}
}

func TestKeySignUsesVerifyWhenPolicyIsUnknown(t *testing.T) {
	card := newSigningTestCard(t, false, 0x00)
	t.Setenv("PIV_PIN", "123456")
	targets := NewTargetResolver(mutationTestCardContextFactory{builders: map[string]func() piv.Card{
		"Standard Token": func() piv.Card { return card },
	}}, nil, bytes.NewReader(nil), &bytes.Buffer{})
	service := NewMutationService(targets, nil, bytes.NewReader(nil), &bytes.Buffer{})
	payloadPath := writeSigningPayload(t)

	if _, err := service.KeySign(context.Background(), SignRequest{Global: GlobalOptions{Reader: "Standard Token", NonInteractive: true}, Slot: piv.SlotSignature, InputPath: payloadPath, Hash: "sha256", Encoding: "base64", PIN: SecretRequest{Label: "PIN", EnvVar: "PIV_PIN"}}); err != nil {
		t.Fatalf("KeySign() error = %v", err)
	}
	if !hasINS(card.TransmittedCommands, 0x20) {
		t.Fatalf("expected VERIFY before signing, got commands: % X", card.TransmittedCommands)
	}
}

func TestKeySignReadsPublicKeyBeforeVerify(t *testing.T) {
	card := newVerifySensitiveSigningCard(t)
	t.Setenv("PIV_PIN", "123456")
	targets := NewTargetResolver(mutationTestCardContextFactory{builders: map[string]func() piv.Card{
		"SafeNet Test": func() piv.Card { return card },
	}}, nil, bytes.NewReader(nil), &bytes.Buffer{})
	service := NewMutationService(targets, nil, bytes.NewReader(nil), &bytes.Buffer{})
	payloadPath := writeSigningPayload(t)

	if _, err := service.KeySign(context.Background(), SignRequest{Global: GlobalOptions{Reader: "SafeNet Test", NonInteractive: true}, Slot: piv.SlotSignature, InputPath: payloadPath, Hash: "sha256", Encoding: "base64", PIN: SecretRequest{Label: "PIN", EnvVar: "PIV_PIN"}}); err != nil {
		t.Fatalf("KeySign() error = %v", err)
	}
	assertCommandOrder(t, card.TransmittedCommands, 0xCB, 0x20)
}

func TestKeyChallengeReadsPublicKeyBeforeVerify(t *testing.T) {
	card := newVerifySensitiveSigningCard(t)
	t.Setenv("PIV_PIN", "123456")
	targets := NewTargetResolver(mutationTestCardContextFactory{builders: map[string]func() piv.Card{
		"SafeNet Test": func() piv.Card { return card },
	}}, nil, bytes.NewReader(nil), &bytes.Buffer{})
	service := NewMutationService(targets, nil, bytes.NewReader(nil), &bytes.Buffer{})

	if _, err := service.KeyChallenge(context.Background(), ChallengeRequest{Global: GlobalOptions{Reader: "SafeNet Test", NonInteractive: true}, Slot: piv.SlotSignature, ChallengeHex: "813ca5285c28ccee5cab8b10ebda9c908fd6d78ed9dc94cc65ea6cb67a7f13ae", Encoding: "base64", PIN: SecretRequest{Label: "PIN", EnvVar: "PIV_PIN"}, UsePIN: true}); err != nil {
		t.Fatalf("KeyChallenge() error = %v", err)
	}
	assertCommandOrder(t, card.TransmittedCommands, 0xCB, 0x20)
}

func newSigningTestCard(t *testing.T, withMetadata bool, pinPolicy byte) *emulator.Card {
	t.Helper()
	point := internalutil.MustEncodeUncompressedPoint(elliptic.P256(), elliptic.P256().Params().Gx, elliptic.P256().Params().Gy)
	publicKeyObject := iso7816.EncodeTLV(0x53, iso7816.EncodeTLV(0x7F49, iso7816.EncodeTLV(0x86, point)))
	signatureObject := iso7816.EncodeTLV(0x7C, iso7816.EncodeTLV(0x82, []byte{0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01}))

	card := emulator.NewCard()
	card.SetSuccessResponse(0xA4, nil)
	card.SetSuccessResponse(0x20, nil)
	card.SetSuccessResponse(0x87, signatureObject)
	card.RegisterINSHandler(0xCB, func(_ *emulator.Card, _ []byte) ([]byte, error) {
		return emulator.BuildSuccessResponse(publicKeyObject), nil
	})
	if withMetadata {
		card.SetSuccessResponse(0xF7, encodeYubiKeySlotMetadata(pinPolicy, point))
	}
	return card
}

func newVerifySensitiveSigningCard(t *testing.T) *emulator.Card {
	t.Helper()
	point := internalutil.MustEncodeUncompressedPoint(elliptic.P256(), elliptic.P256().Params().Gx, elliptic.P256().Params().Gy)
	publicKeyObject := iso7816.EncodeTLV(0x53, iso7816.EncodeTLV(0x7F49, iso7816.EncodeTLV(0x86, point)))
	signatureObject := iso7816.EncodeTLV(0x7C, iso7816.EncodeTLV(0x82, []byte{0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01}))

	card := emulator.NewCard()
	card.SetSuccessResponse(0xA4, nil)

	verified := false
	card.RegisterPrefixHandler([]byte{0x00, 0x20, 0x00, 0x80}, func(_ *emulator.Card, _ []byte) ([]byte, error) {
		verified = true
		return emulator.BuildSuccessResponse(nil), nil
	})
	card.RegisterPrefixHandler([]byte{0x00, 0xCB, 0x3F, 0xFF}, func(_ *emulator.Card, _ []byte) ([]byte, error) {
		if verified {
			verified = false
		}
		return emulator.BuildSuccessResponse(publicKeyObject), nil
	})
	card.RegisterINSHandler(0x87, func(_ *emulator.Card, _ []byte) ([]byte, error) {
		if !verified {
			return emulator.BuildResponse(nil, uint16(iso7816.SwSecurityNotSatisfied)), nil
		}
		return emulator.BuildSuccessResponse(signatureObject), nil
	})

	return card
}

func encodeYubiKeySlotMetadata(pinPolicy byte, publicKey []byte) []byte {
	data := iso7816.EncodeTLV(0x01, []byte{piv.AlgECCP256})
	data = append(data, iso7816.EncodeTLV(0x02, []byte{pinPolicy, 0x00})...)
	data = append(data, iso7816.EncodeTLV(0x03, []byte{0x01})...)
	data = append(data, iso7816.EncodeTLV(0x04, iso7816.EncodeTLV(0x86, publicKey))...)
	return data
}

func writeSigningPayload(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "payload.bin")
	if err := os.WriteFile(path, []byte("test payload"), 0o644); err != nil {
		t.Fatalf("write payload: %v", err)
	}
	return path
}

func hasINS(commands [][]byte, ins byte) bool {
	for _, command := range commands {
		if len(command) > 1 && command[1] == ins {
			return true
		}
	}
	return false
}

func assertCommandOrder(t *testing.T, commands [][]byte, firstINS byte, secondINS byte) {
	t.Helper()
	firstIndex := -1
	secondIndex := -1
	for index, command := range commands {
		if len(command) <= 1 {
			continue
		}
		switch command[1] {
		case firstINS:
			if firstIndex == -1 {
				firstIndex = index
			}
		case secondINS:
			if secondIndex == -1 {
				secondIndex = index
			}
		}
	}
	if firstIndex == -1 || secondIndex == -1 {
		t.Fatalf("expected command sequence with INS %02X before %02X, got: % X", firstINS, secondINS, commands)
	}
	if firstIndex >= secondIndex {
		t.Fatalf("expected INS %02X before %02X, got: % X", firstINS, secondINS, commands)
	}
}
