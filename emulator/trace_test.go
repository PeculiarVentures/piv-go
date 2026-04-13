package emulator

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestExtractTraceLinesFromMarkdown(t *testing.T) {
	text := strings.Join([]string{
		"# Report",
		"timestamp APDU -> 00 a4 04 00",
		"APDU <- 90 00",
		"not a trace line",
	}, "\n")

	comparison := CompareTraceLines(
		[]string{
			"APDU -> 00 A4 04 00",
			"APDU <- 90 00",
		},
		ExtractTraceLines(text),
	)
	if !comparison.Match {
		t.Fatalf("unexpected extracted trace: %s", comparison)
	}
}

func TestCompareTraceLinesReportsDifferences(t *testing.T) {
	comparison := CompareTraceLines(
		[]string{"APDU -> 00 A4 04 00", "APDU <- 90 00"},
		[]string{"APDU -> 00 A4 04 00", "APDU <- 6A 82"},
	)
	if comparison.Match {
		t.Fatal("expected a mismatch")
	}
	if got := comparison.String(); !strings.Contains(got, "line 2") {
		t.Fatalf("unexpected diff summary: %s", got)
	}
}

func TestTraceWriteTextFile(t *testing.T) {
	trace := NewTrace()
	trace.Log("->", []byte{0x00, 0xA4, 0x04, 0x00})
	trace.Log("<-", []byte{0x90, 0x00})

	path := filepath.Join(t.TempDir(), "trace.txt")
	if err := trace.WriteTextFile(path); err != nil {
		t.Fatalf("write trace file: %v", err)
	}

	contents, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read trace file: %v", err)
	}
	if !strings.Contains(string(contents), "APDU -> 00 a4 04 00") {
		t.Fatalf("unexpected trace file contents: %s", contents)
	}
}

func TestTraceWriteTextFileUppercaseOption(t *testing.T) {
	trace := NewTrace(WithUppercaseTrace())
	trace.Log("->", []byte{0x00, 0xA4, 0x04, 0x00})
	trace.Log("<-", []byte{0x90, 0x00})

	path := filepath.Join(t.TempDir(), "trace_upper.txt")
	if err := trace.WriteTextFile(path); err != nil {
		t.Fatalf("write trace file: %v", err)
	}

	contents, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read trace file: %v", err)
	}
	if !strings.Contains(string(contents), "APDU -> 00 A4 04 00") {
		t.Fatalf("unexpected trace file contents: %s", contents)
	}
}
