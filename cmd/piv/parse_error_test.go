package main

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/PeculiarVentures/piv-go/internal/cli/app"
)

// Parse errors must travel through ErrorMapper->Formatter->ExitError as
// usage-error exit 1, never as a raw *CLIError (which main.go maps to 9).
// Parsing happens inside the c.execute closure, so no card I/O occurs and
// the JSON envelope contract is preserved.
func TestParseErrorKeyGenerateBadAlgIsUsageExit1(t *testing.T) {
	cli, stdout, stderr := newTestCLI(t, nil, bytes.NewReader(nil))
	err := executeCLI(cli, "key", "generate", "9a", "--alg", "bogus")
	if code := exitCodeOf(t, err); code != 1 {
		t.Fatalf("exit code = %d, want 1 (err %v)", code, err)
	}
	if stdout.Len() != 0 {
		t.Fatalf("stdout must stay empty on parse error, got %q", stdout.String())
	}
	diagnostics := stderr.String()
	for _, want := range []string{"Error: unsupported key algorithm", "Hint:"} {
		if !strings.Contains(diagnostics, want) {
			t.Fatalf("stderr must contain %q, got %q", want, diagnostics)
		}
	}
}

func TestParseErrorSlotShowBadSlotIsUsageExit1(t *testing.T) {
	cli, stdout, stderr := newTestCLI(t, nil, bytes.NewReader(nil))
	err := executeCLI(cli, "slot", "show", "ff")
	if code := exitCodeOf(t, err); code != 1 {
		t.Fatalf("exit code = %d, want 1 (err %v)", code, err)
	}
	if stdout.Len() != 0 {
		t.Fatalf("stdout must stay empty on parse error, got %q", stdout.String())
	}
	if !strings.Contains(stderr.String(), "Error: unsupported slot") {
		t.Fatalf("stderr must report unsupported slot, got %q", stderr.String())
	}
}

func TestParseErrorKeyGenerateBadPinPolicyIsUsageExit1(t *testing.T) {
	cli, stdout, stderr := newTestCLI(t, nil, bytes.NewReader(nil))
	err := executeCLI(cli, "key", "generate", "9a", "--alg", "p256", "--pin-policy", "bogus")
	if code := exitCodeOf(t, err); code != 1 {
		t.Fatalf("exit code = %d, want 1 (err %v)", code, err)
	}
	if stdout.Len() != 0 {
		t.Fatalf("stdout must stay empty on parse error, got %q", stdout.String())
	}
	if !strings.Contains(stderr.String(), "Error: unsupported PIN policy") {
		t.Fatalf("stderr must report unsupported PIN policy, got %q", stderr.String())
	}
}

func TestParseErrorJSONEnvelopeIsUsageExit1(t *testing.T) {
	cli, stdout, stderr := newTestCLI(t, nil, bytes.NewReader(nil))
	err := executeCLI(cli, "key", "generate", "9a", "--alg", "bogus", "--json")
	if code := exitCodeOf(t, err); code != 1 {
		t.Fatalf("exit code = %d, want 1 (err %v)", code, err)
	}
	var envelope struct {
		Error *app.CLIError `json:"error"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &envelope); err != nil {
		t.Fatalf("unmarshal JSON error envelope: %v (stdout %q stderr %q)", err, stdout.String(), stderr.String())
	}
	if envelope.Error == nil {
		t.Fatalf("expected JSON error envelope on stdout, got %q (stderr %q)", stdout.String(), stderr.String())
	}
	if envelope.Error.Code != "usage-error" {
		t.Fatalf("expected usage-error, got %+v", envelope.Error)
	}
	if !strings.Contains(envelope.Error.Message, "unsupported key algorithm") {
		t.Fatalf("expected unsupported key algorithm message, got %+v", envelope.Error)
	}
}
