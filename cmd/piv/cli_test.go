package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"testing"

	"github.com/PeculiarVentures/piv-go/emulator"
	"github.com/PeculiarVentures/piv-go/internal/cli/app"
	"github.com/PeculiarVentures/piv-go/piv"
)

type fakeCardContextFactory struct {
	builders    map[string]func() piv.Card
	connectErrs map[string]error
}

type fakeCardContext struct {
	builders    map[string]func() piv.Card
	connectErrs map[string]error
}

type commandEnvelope struct {
	Command string            `json:"command"`
	Target  app.TargetSummary `json:"target"`
	Result  json.RawMessage   `json:"result"`
}

func (f fakeCardContextFactory) NewContext() (app.CardContext, error) {
	return &fakeCardContext{builders: f.builders, connectErrs: f.connectErrs}, nil
}

func (c *fakeCardContext) ListReaders() ([]string, error) {
	readers := make([]string, 0, len(c.builders)+len(c.connectErrs))
	seen := make(map[string]struct{})
	for reader := range c.builders {
		seen[reader] = struct{}{}
		readers = append(readers, reader)
	}
	for reader := range c.connectErrs {
		if _, ok := seen[reader]; ok {
			continue
		}
		readers = append(readers, reader)
	}
	return readers, nil
}

func (c *fakeCardContext) Connect(reader string) (piv.Card, error) {
	if err, ok := c.connectErrs[reader]; ok {
		return nil, err
	}
	builder, ok := c.builders[reader]
	if !ok {
		return nil, fmt.Errorf("unknown reader %s", reader)
	}
	return builder(), nil
}

func (c *fakeCardContext) Release() error { return nil }

func TestVersionJSON(t *testing.T) {
	cli, stdout, stderr := newTestCLI(t, nil, bytes.NewReader(nil))
	err := executeCLI(cli, "version", "--json")
	if err != nil {
		t.Fatalf("execute version: %v", err)
	}
	if stderr.Len() != 0 {
		t.Fatalf("expected empty stderr, got %q", stderr.String())
	}
	var envelope commandEnvelope
	if err := json.Unmarshal(stdout.Bytes(), &envelope); err != nil {
		t.Fatalf("unmarshal version envelope: %v", err)
	}
	if envelope.Command != "version" {
		t.Fatalf("unexpected command %q", envelope.Command)
	}
	var result app.VersionResult
	if err := json.Unmarshal(envelope.Result, &result); err != nil {
		t.Fatalf("unmarshal version result: %v", err)
	}
	if result.Binary != "piv" {
		t.Fatalf("unexpected binary %q", result.Binary)
	}
}

func TestConfigSetShowUnsetJSON(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), "config.yaml")
	cli, _, _ := newTestCLIWithPath(t, configPath, nil, bytes.NewReader(nil))
	if err := executeCLI(cli, "config", "set", "default-reader", "Reader A"); err != nil {
		t.Fatalf("config set: %v", err)
	}

	cli, stdout, _ := newTestCLIWithPath(t, configPath, nil, bytes.NewReader(nil))
	if err := executeCLI(cli, "config", "show", "--json"); err != nil {
		t.Fatalf("config show: %v", err)
	}
	var envelope commandEnvelope
	if err := json.Unmarshal(stdout.Bytes(), &envelope); err != nil {
		t.Fatalf("unmarshal config envelope: %v", err)
	}
	var result app.ConfigShowResult
	if err := json.Unmarshal(envelope.Result, &result); err != nil {
		t.Fatalf("unmarshal config result: %v", err)
	}
	found := false
	for _, value := range result.Values {
		if value.Key == "default-reader" && value.Value == "Reader A" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected default-reader in config values: %+v", result.Values)
	}

	cli, _, _ = newTestCLIWithPath(t, configPath, nil, bytes.NewReader(nil))
	if err := executeCLI(cli, "config", "unset", "default-reader"); err != nil {
		t.Fatalf("config unset: %v", err)
	}
}

func TestDevicesJSONWithFakeReader(t *testing.T) {
	targets := app.NewTargetResolver(fakeCardContextFactory{
		builders: map[string]func() piv.Card{
			"YubiKey Test": newReadyCard,
		},
		connectErrs: map[string]error{
			"Empty Reader": fmt.Errorf("no card"),
		},
	}, nil, bytes.NewReader(nil), &bytes.Buffer{})
	cli, stdout, _ := newTestCLI(t, targets, bytes.NewReader(nil))
	if err := executeCLI(cli, "devices", "--json"); err != nil {
		t.Fatalf("devices: %v", err)
	}
	var envelope commandEnvelope
	if err := json.Unmarshal(stdout.Bytes(), &envelope); err != nil {
		t.Fatalf("unmarshal devices envelope: %v", err)
	}
	var result app.DevicesResult
	if err := json.Unmarshal(envelope.Result, &result); err != nil {
		t.Fatalf("unmarshal devices result: %v", err)
	}
	if len(result.Devices) != 2 {
		t.Fatalf("expected 2 devices, got %d", len(result.Devices))
	}
	foundReady := false
	for _, device := range result.Devices {
		if device.Reader == "YubiKey Test" && device.PIVReady && device.Adapter == "yubikey" {
			foundReady = true
		}
	}
	if !foundReady {
		t.Fatalf("expected a ready YubiKey device in %+v", result.Devices)
	}
}

func TestSlotListJSONWithFakeReader(t *testing.T) {
	targets := app.NewTargetResolver(fakeCardContextFactory{
		builders: map[string]func() piv.Card{
			"YubiKey Test": newReadyCard,
		},
	}, nil, bytes.NewReader(nil), &bytes.Buffer{})
	cli, stdout, _ := newTestCLI(t, targets, bytes.NewReader(nil))
	if err := executeCLI(cli, "slot", "list", "--reader", "YubiKey Test", "--json"); err != nil {
		t.Fatalf("slot list: %v", err)
	}
	var envelope commandEnvelope
	if err := json.Unmarshal(stdout.Bytes(), &envelope); err != nil {
		t.Fatalf("unmarshal slot list envelope: %v", err)
	}
	if envelope.Target.Adapter != "yubikey" {
		t.Fatalf("expected yubikey adapter, got %q", envelope.Target.Adapter)
	}
	var result app.SlotListResult
	if err := json.Unmarshal(envelope.Result, &result); err != nil {
		t.Fatalf("unmarshal slot list result: %v", err)
	}
	if len(result.Slots) != 4 {
		t.Fatalf("expected 4 primary slots, got %d", len(result.Slots))
	}
}

func TestTLVDecodeJSONFromStdin(t *testing.T) {
	stdin := bytes.NewReader([]byte{0x5C, 0x03, 0x5F, 0xC1, 0x02})
	cli, stdout, _ := newTestCLI(t, nil, stdin)
	if err := executeCLI(cli, "diag", "tlv", "decode", "--json", "--in", "-"); err != nil {
		t.Fatalf("tlv decode: %v", err)
	}
	var envelope commandEnvelope
	if err := json.Unmarshal(stdout.Bytes(), &envelope); err != nil {
		t.Fatalf("unmarshal tlv envelope: %v", err)
	}
	var result app.TLVDecodeResult
	if err := json.Unmarshal(envelope.Result, &result); err != nil {
		t.Fatalf("unmarshal tlv result: %v", err)
	}
	if len(result.Nodes) != 1 || result.Nodes[0].Tag != "5C" {
		t.Fatalf("unexpected TLV nodes: %+v", result.Nodes)
	}
}

func newReadyCard() piv.Card {
	card := emulator.NewCard()
	card.RegisterINSHandler(0xA4, func(_ *emulator.Card, _ []byte) ([]byte, error) {
		return emulator.BuildSuccessResponse(nil), nil
	})
	return card
}

func newTestCLI(t *testing.T, targets *app.TargetResolver, stdin *bytes.Reader) (*cli, *bytes.Buffer, *bytes.Buffer) {
	t.Helper()
	return newTestCLIWithPath(t, filepath.Join(t.TempDir(), "config.yaml"), targets, stdin)
}

func newTestCLIWithPath(t *testing.T, configPath string, targets *app.TargetResolver, stdin *bytes.Reader) (*cli, *bytes.Buffer, *bytes.Buffer) {
	t.Helper()
	stdout := &bytes.Buffer{}
	stderr := &bytes.Buffer{}
	cli, err := newCLIWithDependencies(stdin, stdout, stderr, configPath, targets)
	if err != nil {
		t.Fatalf("newCLIWithDependencies: %v", err)
	}
	return cli, stdout, stderr
}

func executeCLI(cli *cli, args ...string) error {
	root := cli.rootCommand()
	root.SetArgs(args)
	err := root.Execute()
	if err == nil {
		return nil
	}
	var exitErr *app.ExitError
	if errors.As(err, &exitErr) && exitErr.Code == 0 {
		return nil
	}
	return err
}
