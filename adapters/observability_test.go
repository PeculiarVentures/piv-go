package adapters

import "testing"

type stubLogProvider struct {
	lines []string
}

func (s stubLogProvider) APDULog() []string {
	return append([]string(nil), s.lines...)
}

func TestTraceCollectorCombinedModeRecordsOrderedLines(t *testing.T) {
	collector := NewTraceCollector(TraceModeCombined)
	collector.Observe(Event{Adapter: "safenet", Operation: "initialize-token", Message: "starting initialization"})
	collector.RecordAPDU("->", []byte{0x00, 0xA4})

	lines := collector.APDULog()
	if len(lines) != 2 {
		t.Fatalf("trace lines = %d, want 2", len(lines))
	}
	if lines[0] != "# safenet initialize-token: starting initialization" {
		t.Fatalf("unexpected event line: %q", lines[0])
	}
	if lines[1] != "APDU -> 00 a4" {
		t.Fatalf("unexpected APDU line: %q", lines[1])
	}
}

func TestSessionTraceLogMergesObserverAndAPDUSource(t *testing.T) {
	collector := NewTraceCollector(TraceModeAdapterOnly)
	session := &Session{
		Observer:      collector,
		APDULogSource: stubLogProvider{lines: []string{"APDU -> 00 a4"}},
	}
	session.Observe(LogLevelInfo, nil, "resolve-runtime", "selected standard path")

	lines := session.TraceLog()
	if len(lines) != 2 {
		t.Fatalf("trace lines = %d, want 2", len(lines))
	}
	if lines[0] != "# standard-piv resolve-runtime: selected standard path" {
		t.Fatalf("unexpected event line: %q", lines[0])
	}
	if lines[1] != "APDU -> 00 a4" {
		t.Fatalf("unexpected APDU line: %q", lines[1])
	}
}

func TestSessionTraceLogDoesNotDuplicateSharedCollector(t *testing.T) {
	collector := NewTraceCollector(TraceModeCombined)
	collector.RecordAPDU("<-", []byte{0x90, 0x00})
	session := &Session{Observer: collector, APDULogSource: collector}

	lines := session.TraceLog()
	if len(lines) != 1 {
		t.Fatalf("trace lines = %d, want 1", len(lines))
	}
	if lines[0] != "APDU <- 90 00" {
		t.Fatalf("unexpected APDU line: %q", lines[0])
	}
}
