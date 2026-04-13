package adapters

import (
	"bytes"
	"testing"

	"github.com/PeculiarVentures/piv-go/piv"
)

type stubCard struct{}

func (stubCard) Transmit([]byte) ([]byte, error) { return nil, nil }
func (stubCard) Begin() error                    { return nil }
func (stubCard) End() error                      { return nil }
func (stubCard) Close() error                    { return nil }

type stubProvider struct {
	lines []string
}

func (p stubProvider) APDULog() []string {
	return append([]string(nil), p.lines...)
}

func TestNewSessionAppliesOptionsAndCopiesManagementKey(t *testing.T) {
	key := []byte{0x01, 0x02, 0x03}
	provider := stubProvider{lines: []string{"APDU -> 00 a4"}}
	session := NewSession(
		piv.NewClient(stubCard{}),
		WithReaderName("Reader 1"),
		WithManagementCredentials(piv.AlgAES128, key),
		WithAPDULogSource(provider),
	)
	key[0] = 0xFF

	if session.ReaderName != "Reader 1" {
		t.Fatalf("ReaderName = %q, want Reader 1", session.ReaderName)
	}
	if session.ManagementAlgorithm != piv.AlgAES128 {
		t.Fatalf("ManagementAlgorithm = 0x%02X, want 0x%02X", session.ManagementAlgorithm, piv.AlgAES128)
	}
	if !bytes.Equal(session.ManagementKey, []byte{0x01, 0x02, 0x03}) {
		t.Fatalf("ManagementKey = % X, want 01 02 03", session.ManagementKey)
	}
	if got := session.APDULogSource.APDULog(); len(got) != 1 || got[0] != "APDU -> 00 a4" {
		t.Fatalf("APDULogSource = %v, want [APDU -> 00 a4]", got)
	}
}

func TestSessionCloneProducesIndependentManagementKeyCopy(t *testing.T) {
	trace := NewTraceCollector(TraceModeCombined)
	original := NewSession(
		piv.NewClient(stubCard{}),
		WithReaderName("Reader 1"),
		WithManagementCredentials(piv.AlgAES128, []byte{0x01, 0x02}),
		WithTraceCollector(trace),
	)
	clone := original.Clone(WithReaderName("Reader 2"))
	clone.ManagementKey[0] = 0xFF

	if original.ReaderName != "Reader 1" {
		t.Fatalf("original ReaderName = %q, want Reader 1", original.ReaderName)
	}
	if clone.ReaderName != "Reader 2" {
		t.Fatalf("clone ReaderName = %q, want Reader 2", clone.ReaderName)
	}
	if !bytes.Equal(original.ManagementKey, []byte{0x01, 0x02}) {
		t.Fatalf("original ManagementKey = % X, want 01 02", original.ManagementKey)
	}
	if clone.Observer != trace || clone.APDULogSource != trace {
		t.Fatal("clone should preserve the attached trace collector")
	}
}
