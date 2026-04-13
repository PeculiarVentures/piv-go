package emulator

import (
	"fmt"
	"io"
	"os"
	"strings"
)

// TraceEntry describes one APDU request or response.
type TraceEntry struct {
	Direction string
	Payload   []byte
}

// Trace stores APDU requests and responses in transmission order.
type Trace struct {
	entries   []TraceEntry
	uppercase bool
}

// TraceOption configures trace formatting behavior.
type TraceOption func(*Trace)

// WithUppercaseTrace enables uppercase APDU payload formatting.
func WithUppercaseTrace() TraceOption {
	return func(t *Trace) {
		t.uppercase = true
	}
}

// TraceDifference describes one mismatch between expected and actual trace lines.
type TraceDifference struct {
	Line     int
	Expected string
	Actual   string
}

// TraceComparison summarizes the result of comparing two normalized APDU traces.
type TraceComparison struct {
	Match       bool
	Differences []TraceDifference
}

// NewTrace creates an empty APDU trace collector.
// By default, trace payload bytes are formatted in lowercase.
func NewTrace(opts ...TraceOption) *Trace {
	t := &Trace{}
	for _, opt := range opts {
		opt(t)
	}
	return t
}

// Log appends one APDU request or response to the trace.
func (t *Trace) Log(direction string, payload []byte) {
	t.entries = append(t.entries, TraceEntry{
		Direction: direction,
		Payload:   append([]byte(nil), payload...),
	})
}

// Entries returns a copy of the collected trace entries.
func (t *Trace) Entries() []TraceEntry {
	entries := make([]TraceEntry, len(t.entries))
	for index, entry := range t.entries {
		entries[index] = TraceEntry{
			Direction: entry.Direction,
			Payload:   append([]byte(nil), entry.Payload...),
		}
	}
	return entries
}

// Lines returns the trace as normalized APDU log lines.
func (t *Trace) Lines() []string {
	format := "APDU %s % x"
	if t.uppercase {
		format = "APDU %s % X"
	}
	lines := make([]string, 0, len(t.entries))
	for _, entry := range t.entries {
		lines = append(lines, fmt.Sprintf(format, entry.Direction, entry.Payload))
	}
	return lines
}

// Text returns the normalized APDU log text.
func (t *Trace) Text() string {
	return strings.Join(t.Lines(), "\n")
}

// Reset clears all collected trace entries.
func (t *Trace) Reset() {
	t.entries = nil
}

// WriteText writes the normalized APDU log text to the provided writer.
func (t *Trace) WriteText(writer io.Writer) error {
	if _, err := io.WriteString(writer, t.Text()); err != nil {
		return err
	}
	_, err := io.WriteString(writer, "\n")
	return err
}

// WriteTextFile writes the normalized APDU log text to a file.
func (t *Trace) WriteTextFile(path string) error {
	file, err := os.Create(path)
	if err != nil {
		return err
	}
	defer func() {
		_ = file.Close()
	}()
	return t.WriteText(file)
}

// NormalizeTraceLine canonicalizes one APDU log line for comparison.
func NormalizeTraceLine(line string) string {
	index := strings.Index(strings.ToUpper(line), "APDU ")
	if index == -1 {
		return ""
	}
	normalized := strings.ToUpper(strings.Join(strings.Fields(line[index:]), " "))
	if strings.HasPrefix(normalized, "APDU -> ") || strings.HasPrefix(normalized, "APDU <- ") {
		return normalized
	}
	return ""
}

// NormalizeTraceLines canonicalizes and filters a slice of APDU log lines.
func NormalizeTraceLines(lines []string) []string {
	normalized := make([]string, 0, len(lines))
	for _, line := range lines {
		if normalizedLine := NormalizeTraceLine(line); normalizedLine != "" {
			normalized = append(normalized, normalizedLine)
		}
	}
	return normalized
}

// ExtractTraceLines extracts normalized APDU log lines from free-form text.
func ExtractTraceLines(text string) []string {
	return NormalizeTraceLines(strings.Split(text, "\n"))
}

// CompareTraceLines compares two APDU traces line by line after normalization.
func CompareTraceLines(expected []string, actual []string) TraceComparison {
	normalizedExpected := NormalizeTraceLines(expected)
	normalizedActual := NormalizeTraceLines(actual)
	maxLines := len(normalizedExpected)
	if len(normalizedActual) > maxLines {
		maxLines = len(normalizedActual)
	}

	differences := make([]TraceDifference, 0)
	for index := 0; index < maxLines; index++ {
		var expectedLine string
		if index < len(normalizedExpected) {
			expectedLine = normalizedExpected[index]
		}
		var actualLine string
		if index < len(normalizedActual) {
			actualLine = normalizedActual[index]
		}
		if expectedLine == actualLine {
			continue
		}
		differences = append(differences, TraceDifference{Line: index + 1, Expected: expectedLine, Actual: actualLine})
	}

	return TraceComparison{Match: len(differences) == 0, Differences: differences}
}

// CompareTraceText compares a reference text blob with an actual APDU log.
func CompareTraceText(referenceText string, actual []string) TraceComparison {
	return CompareTraceLines(ExtractTraceLines(referenceText), actual)
}

// String returns a concise diff summary suitable for test failures.
func (c TraceComparison) String() string {
	if c.Match {
		return "trace matches"
	}
	parts := make([]string, 0, 4)
	for index, difference := range c.Differences {
		if index == 3 {
			parts = append(parts, fmt.Sprintf("%d more differences", len(c.Differences)-index))
			break
		}
		parts = append(parts, fmt.Sprintf(
			"line %d: expected %s, got %s",
			difference.Line,
			displayTraceLine(difference.Expected),
			displayTraceLine(difference.Actual),
		))
	}
	return strings.Join(parts, "; ")
}

func displayTraceLine(line string) string {
	if line == "" {
		return "<none>"
	}
	return fmt.Sprintf("%q", line)
}
