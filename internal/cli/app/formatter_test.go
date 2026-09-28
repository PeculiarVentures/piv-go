package app

import (
	"bytes"
	"strings"
	"testing"
)

// TestRenderSlotTableShowsUnknown covers the P2 regression where the text
// formatter rendered an unknown slot state as "empty". Unknown must render
// as "unknown" so operators do not mistake it for a confirmed empty slot.
func TestRenderSlotTableShowsUnknown(t *testing.T) {
	var unknown bytes.Buffer
	(&Formatter{}).renderSlotTable(&unknown, []SlotView{{
		Name: "9c", Hex: "9c",
		KeyPresent: false, KeyUnknown: true, KeyAlgorithm: "-",
		CertPresent: false, CertLabel: "-",
	}})
	if !strings.Contains(unknown.String(), "unknown") {
		t.Fatalf("unknown slot state must render as unknown, got %q", unknown.String())
	}
	for _, line := range strings.Split(unknown.String(), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 || fields[0] != "9c" {
			continue
		}
		if len(fields) < 4 || fields[2] != "unknown" {
			t.Fatalf("key column must render as unknown, got %q", line)
		}
	}

	var absent bytes.Buffer
	(&Formatter{}).renderSlotTable(&absent, []SlotView{{
		Name: "9c", Hex: "9c",
		KeyPresent: false, KeyUnknown: false, KeyAlgorithm: "-",
		CertPresent: false, CertLabel: "-",
	}})
	if !strings.Contains(absent.String(), "empty") {
		t.Fatalf("definitely-absent slot must still render as empty, got %q", absent.String())
	}
}
