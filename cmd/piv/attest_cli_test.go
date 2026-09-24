package main

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/PeculiarVentures/piv-go/emulator"
	"github.com/PeculiarVentures/piv-go/internal/cli/app"
	"github.com/PeculiarVentures/piv-go/iso7816"
	"github.com/PeculiarVentures/piv-go/piv"
)

// testAttestationPayload is a fixed canned attestation payload for CLI
// end-to-end tests. The adapter and export path treat it as opaque DER.
var testAttestationPayload = []byte{
	0x30, 0x12, 0x02, 0x01, 0x01, 0x02, 0x01, 0x9C,
	0x04, 0x08, 0x59, 0x55, 0x42, 0x49, 0x4B, 0x45,
	0x59, 0x00, 0x02, 0x01, 0x03,
}

func newAttestationCard() piv.Card {
	card := newReadyCard().(*emulator.Card)
	card.SetSuccessResponse(0xFD, []byte{0x05, 0x07, 0x00})
	card.SetSuccessResponse(0xF9, testAttestationPayload)
	return card
}

func newAttestationObjectCard() piv.Card {
	card := newReadyCard().(*emulator.Card)
	object := iso7816.EncodeTLV(0x53, append(append(iso7816.EncodeTLV(0x70, testAttestationPayload), iso7816.EncodeTLV(0x71, []byte{0x00})...), iso7816.EncodeTLV(0xFE, nil)...))
	card.SetSuccessResponse(0xCB, object)
	return card
}

func TestKeyAttestCommandFlags(t *testing.T) {
	cli, _, _ := newTestCLI(t, nil, bytes.NewReader(nil))
	root := cli.rootCommand()
	keyCommand, _, err := root.Find([]string{"key"})
	if err != nil || keyCommand == nil {
		t.Fatalf("key command not found: %v", err)
	}
	attestCommand, _, err := keyCommand.Find([]string{"attest"})
	if err != nil || attestCommand == nil {
		t.Fatalf("key attest command not found: %v", err)
	}
	if attestCommand.Use != "attest <slot>" {
		t.Fatalf("unexpected attest use %q", attestCommand.Use)
	}
	if flag := attestCommand.Flags().Lookup("format"); flag == nil {
		t.Fatal("key attest must define --format")
	}
	if flag := attestCommand.Flags().Lookup("out"); flag == nil || flag.Shorthand != "o" {
		t.Fatal("key attest must define --out/-o")
	}
}

func TestKeyAttestJSONWithFakeReader(t *testing.T) {
	targets := app.NewTargetResolver(fakeCardContextFactory{
		builders: map[string]func() piv.Card{
			"YubiKey Test": newAttestationCard,
		},
	}, nil, bytes.NewReader(nil), &bytes.Buffer{})
	cli, stdout, _ := newTestCLI(t, targets, bytes.NewReader(nil))
	if err := executeCLI(cli, "key", "attest", "9c", "--reader", "YubiKey Test", "--json"); err != nil {
		t.Fatalf("key attest: %v", err)
	}
	var envelope commandEnvelope
	if err := json.Unmarshal(stdout.Bytes(), &envelope); err != nil {
		t.Fatalf("unmarshal attest envelope: %v", err)
	}
	if envelope.Command != "key-attest" {
		t.Fatalf("unexpected command %q", envelope.Command)
	}
	var result app.ArtifactResult
	if err := json.Unmarshal(envelope.Result, &result); err != nil {
		t.Fatalf("unmarshal attest result: %v", err)
	}
	if result.Kind != "attestation" || result.Format != "pem" {
		t.Fatalf("unexpected attest artifact: %+v", result)
	}
	if !strings.Contains(result.Data, "-----BEGIN CERTIFICATE-----") {
		t.Fatalf("expected PEM certificate in attest output, got %q", result.Data)
	}
}

func TestCertExportAttestationAliasJSONWithFakeReader(t *testing.T) {
	targets := app.NewTargetResolver(fakeCardContextFactory{
		builders: map[string]func() piv.Card{
			"YubiKey Test": newAttestationObjectCard,
		},
	}, nil, bytes.NewReader(nil), &bytes.Buffer{})
	cli, stdout, _ := newTestCLI(t, targets, bytes.NewReader(nil))
	if err := executeCLI(cli, "cert", "export", "attestation", "--reader", "YubiKey Test", "--json"); err != nil {
		t.Fatalf("cert export attestation: %v", err)
	}
	var envelope commandEnvelope
	if err := json.Unmarshal(stdout.Bytes(), &envelope); err != nil {
		t.Fatalf("unmarshal cert envelope: %v", err)
	}
	if envelope.Command != "cert-export" {
		t.Fatalf("unexpected command %q", envelope.Command)
	}
	var result app.ArtifactResult
	if err := json.Unmarshal(envelope.Result, &result); err != nil {
		t.Fatalf("unmarshal cert result: %v", err)
	}
	if result.Kind != "certificate" {
		t.Fatalf("unexpected cert artifact: %+v", result)
	}
	if !strings.Contains(result.Data, "-----BEGIN CERTIFICATE-----") {
		t.Fatalf("expected PEM certificate in cert output, got %q", result.Data)
	}
}

func TestKeyGenerateRejectsAttestationSlotWithoutAPDU(t *testing.T) {
	card := newReadyCard().(*emulator.Card)
	targets := app.NewTargetResolver(fakeCardContextFactory{
		builders: map[string]func() piv.Card{
			"YubiKey Test": func() piv.Card { return card },
		},
	}, nil, bytes.NewReader(nil), &bytes.Buffer{})
	cli, stdout, stderr := newTestCLI(t, targets, bytes.NewReader(nil))
	err := executeCLI(cli, "key", "generate", "f9", "--alg", "p256", "--reader", "YubiKey Test")
	if code := exitCodeOf(t, err); code != 1 {
		t.Fatalf("exit code = %d, want 1 (err %v)", code, err)
	}
	if stdout.Len() != 0 {
		t.Fatalf("stdout must stay empty on parse error, got %q", stdout.String())
	}
	if !strings.Contains(stderr.String(), "read-only") {
		t.Fatalf("expected read-only F9 rejection on stderr, got %q", stderr.String())
	}
	if len(card.TransmittedCommands) != 0 {
		t.Fatalf("rejected F9 generate must not send any APDU, got % X", card.TransmittedCommands)
	}
}

func TestCertImportRejectsAttestationSlotWithoutAPDU(t *testing.T) {
	card := newReadyCard().(*emulator.Card)
	targets := app.NewTargetResolver(fakeCardContextFactory{
		builders: map[string]func() piv.Card{
			"YubiKey Test": func() piv.Card { return card },
		},
	}, nil, bytes.NewReader(nil), &bytes.Buffer{})
	cli, stdout, stderr := newTestCLI(t, targets, bytes.NewReader(nil))
	err := executeCLI(cli, "cert", "import", "attestation", "/nonexistent-cert.pem", "--reader", "YubiKey Test")
	if code := exitCodeOf(t, err); code != 1 {
		t.Fatalf("exit code = %d, want 1 (err %v)", code, err)
	}
	if stdout.Len() != 0 {
		t.Fatalf("stdout must stay empty on parse error, got %q", stdout.String())
	}
	if !strings.Contains(stderr.String(), "read-only") {
		t.Fatalf("expected read-only F9 rejection on stderr, got %q", stderr.String())
	}
	if len(card.TransmittedCommands) != 0 {
		t.Fatalf("rejected F9 cert import must not send any APDU, got % X", card.TransmittedCommands)
	}
}
