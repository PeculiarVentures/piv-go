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

// Cobra errors raised before RunE (missing required flags, bad argument
// counts, unknown flags) must travel the same usage-error exit 1 path with
// the JSON envelope contract, never as a raw error with empty stdout.
func TestCobraPreRunEErrorsAreUsageExit1(t *testing.T) {
	tests := []struct {
		name        string
		args        []string
		wantMessage string
	}{
		{"generate missing alg", []string{"key", "generate", "9a"}, `required flag(s) "alg" not set`},
		{"generate no slot", []string{"key", "generate", "--alg", "p256"}, "accepts 1 arg(s), received 0"},
		{"generate extra slot", []string{"key", "generate", "9a", "9c", "--alg", "p256"}, "accepts 1 arg(s), received 2"},
		{"generate unknown flag", []string{"key", "generate", "9a", "--alg", "p256", "--bogus"}, "unknown flag: --bogus"},
		{"sign missing in", []string{"key", "sign", "9a"}, `required flag(s) "in" not set`},
		{"challenge missing hex", []string{"key", "challenge", "9a"}, `required flag(s) "challenge-hex" not set`},
		{"import missing alg", []string{"key", "import", "9a", "--in", "key.pem"}, `required flag(s) "alg" not set`},
	}
	for _, test := range tests {
		t.Run(test.name+"/text", func(t *testing.T) {
			cli, stdout, stderr := newTestCLI(t, nil, bytes.NewReader(nil))
			err := executeCLI(cli, test.args...)
			if code := exitCodeOf(t, err); code != 1 {
				t.Fatalf("exit code = %d, want 1 (err %v)", code, err)
			}
			if stdout.Len() != 0 {
				t.Fatalf("stdout must stay empty on usage error, got %q", stdout.String())
			}
			diagnostics := stderr.String()
			for _, want := range []string{"Error: " + test.wantMessage, "Hint:"} {
				if !strings.Contains(diagnostics, want) {
					t.Fatalf("stderr must contain %q, got %q", want, diagnostics)
				}
			}
		})
		t.Run(test.name+"/json", func(t *testing.T) {
			cli, stdout, stderr := newTestCLI(t, nil, bytes.NewReader(nil))
			args := append(append([]string(nil), test.args...), "--json")
			err := executeCLI(cli, args...)
			if code := exitCodeOf(t, err); code != 1 {
				t.Fatalf("exit code = %d, want 1 (err %v)", code, err)
			}
			envelope := decodeErrorEnvelope(t, stdout, stderr)
			if envelope.Error.Code != "usage-error" {
				t.Fatalf("expected usage-error, got %+v", envelope.Error)
			}
			if !strings.Contains(envelope.Error.Message, test.wantMessage) {
				t.Fatalf("expected message containing %q, got %+v", test.wantMessage, envelope.Error)
			}
			if stderr.Len() != 0 {
				t.Fatalf("stderr must stay empty with --json, got %q", stderr.String())
			}
		})
	}
}

// The --json flag must select the stdout envelope wherever it stands, even
// after an unknown flag that aborts flag parsing before --json is bound.
func TestCobraUnknownFlagJSONPositionDoesNotMatter(t *testing.T) {
	for _, args := range [][]string{
		{"key", "generate", "9a", "--alg", "p256", "--json", "--bogus"},
		{"key", "generate", "9a", "--alg", "p256", "--bogus", "--json"},
	} {
		cli, stdout, stderr := newTestCLI(t, nil, bytes.NewReader(nil))
		err := executeCLI(cli, args...)
		if code := exitCodeOf(t, err); code != 1 {
			t.Fatalf("args %v: exit code = %d, want 1 (err %v)", args, code, err)
		}
		envelope := decodeErrorEnvelope(t, stdout, stderr)
		if envelope.Error.Code != "usage-error" {
			t.Fatalf("args %v: expected usage-error, got %+v", args, envelope.Error)
		}
		if !strings.Contains(envelope.Error.Message, "unknown flag: --bogus") {
			t.Fatalf("args %v: expected unknown flag message, got %+v", args, envelope.Error)
		}
	}
}

func decodeErrorEnvelope(t *testing.T, stdout *bytes.Buffer, stderr *bytes.Buffer) struct {
	Error *app.CLIError `json:"error"`
} {
	t.Helper()
	var envelope struct {
		Error *app.CLIError `json:"error"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &envelope); err != nil {
		t.Fatalf("unmarshal JSON error envelope: %v (stdout %q stderr %q)", err, stdout.String(), stderr.String())
	}
	if envelope.Error == nil {
		t.Fatalf("expected JSON error envelope on stdout, got %q (stderr %q)", stdout.String(), stderr.String())
	}
	return envelope
}
