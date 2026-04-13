package testtrace

import (
	"os"
	"testing"

	"github.com/PeculiarVentures/piv-go/emulator"
)

// RequireMatchFile normalizes an APDU log, compares it with a reference file,
// and fails the test when they differ. It returns the normalized log lines.
func RequireMatchFile(t testing.TB, path string, actual []string) []string {
	t.Helper()

	normalized := emulator.NormalizeTraceLines(actual)
	if len(normalized) != len(actual) {
		t.Fatalf("unexpected APDU log lines: %+v", actual)
	}

	traceBytes, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read trace: %v", err)
	}
	comparison := emulator.CompareTraceText(string(traceBytes), normalized)
	if !comparison.Match {
		t.Fatalf("unexpected APDU trace diff: %s", comparison)
	}

	return normalized
}
