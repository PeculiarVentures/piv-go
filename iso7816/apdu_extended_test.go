package iso7816

import (
	"bytes"
	"testing"
)

func TestCommandBytesShortFormUnchanged(t *testing.T) {
	cmd := &Command{Cla: 0x00, Ins: 0x47, P1: 0x00, P2: 0x9C, Data: []byte{0xAC, 0x03, 0x80, 0x01, 0x11}, Le: 256}
	want := []byte{0x00, 0x47, 0x00, 0x9C, 0x05, 0xAC, 0x03, 0x80, 0x01, 0x11, 0x00}
	if !bytes.Equal(cmd.Bytes(), want) {
		t.Fatalf("short APDU changed: got %X, want %X", cmd.Bytes(), want)
	}
}

func TestCommandBytesExtendedForm(t *testing.T) {
	data := bytes.Repeat([]byte{0xAB}, 300)
	cmd := &Command{Cla: 0x00, Ins: 0xFE, P1: 0x07, P2: 0x9C, Data: data, Le: -1}
	raw := cmd.Bytes()
	if len(raw) != 4+3+300 {
		t.Fatalf("unexpected extended length %d", len(raw))
	}
	if raw[4] != 0x00 || raw[5] != 0x01 || raw[6] != 0x2C {
		t.Fatalf("unexpected extended header: %X", raw[:7])
	}
	parsed, err := ParseCommand(raw)
	if err != nil {
		t.Fatalf("parse extended: %v", err)
	}
	if parsed.Ins != 0xFE || parsed.P1 != 0x07 || parsed.P2 != 0x9C || !bytes.Equal(parsed.Data, data) || parsed.Le != -1 {
		t.Fatalf("extended round-trip mismatch: %+v", parsed)
	}
}

func TestCommandBytesExtendedFormWithLe(t *testing.T) {
	data := bytes.Repeat([]byte{0xCD}, 260)
	cmd := &Command{Cla: 0x00, Ins: 0xFE, P1: 0x07, P2: 0x9C, Data: data, Le: 256}
	parsed, err := ParseCommand(cmd.Bytes())
	if err != nil {
		t.Fatalf("parse extended: %v", err)
	}
	if !bytes.Equal(parsed.Data, data) || parsed.Le != 256 {
		t.Fatalf("extended round-trip mismatch: data %d, Le %d", len(parsed.Data), parsed.Le)
	}
}

func TestParseCommandShortFormsUnchanged(t *testing.T) {
	parsed, err := ParseCommand([]byte{0x00, 0x20, 0x00, 0x80})
	if err != nil || parsed.Le != -1 || len(parsed.Data) != 0 {
		t.Fatalf("case 1 parse changed: %+v, %v", parsed, err)
	}
	parsed, err = ParseCommand([]byte{0x00, 0x47, 0x00, 0x9C, 0x05, 0xAC, 0x03, 0x80, 0x01, 0x11, 0x00})
	if err != nil || parsed.Le != 256 || len(parsed.Data) != 5 {
		t.Fatalf("case 4 parse changed: %+v, %v", parsed, err)
	}
}

func TestParseCommandExtendedCase2E(t *testing.T) {
	tests := []struct {
		name   string
		raw    []byte
		wantLe int
	}{
		{name: "Le 256", raw: []byte{0x00, 0xC0, 0x00, 0x00, 0x00, 0x01, 0x00}, wantLe: 256},
		{name: "Le 1", raw: []byte{0x00, 0xC0, 0x00, 0x00, 0x00, 0x00, 0x01}, wantLe: 1},
		{name: "Le 65536", raw: []byte{0x00, 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00}, wantLe: 65536},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			parsed, err := ParseCommand(test.raw)
			if err != nil {
				t.Fatalf("parse case 2E: %v", err)
			}
			if parsed.Le != test.wantLe {
				t.Fatalf("expected Le=%d, got %d", test.wantLe, parsed.Le)
			}
			if len(parsed.Data) != 0 {
				t.Fatalf("expected empty data, got %X", parsed.Data)
			}
		})
	}
}

func TestCommandBytesExtendedLe65536RoundTrip(t *testing.T) {
	data := bytes.Repeat([]byte{0xAB}, 300)
	cmd := &Command{Cla: 0x00, Ins: 0xFE, P1: 0x07, P2: 0x9C, Data: data, Le: 65536}
	raw := cmd.Bytes()
	if len(raw) < 2 || raw[len(raw)-2] != 0x00 || raw[len(raw)-1] != 0x00 {
		t.Fatalf("Le=65536 must be encoded as 00 00, got tail %X", raw[len(raw)-2:])
	}
	parsed, err := ParseCommand(raw)
	if err != nil {
		t.Fatalf("parse extended: %v", err)
	}
	if parsed.Le != 65536 {
		t.Fatalf("expected Le=65536, got %d", parsed.Le)
	}
	if !bytes.Equal(parsed.Data, data) {
		t.Fatal("extended data round-trip mismatch")
	}
	if parsed.Cla != cmd.Cla || parsed.Ins != cmd.Ins || parsed.P1 != cmd.P1 || parsed.P2 != cmd.P2 {
		t.Fatalf("header round-trip mismatch: %+v", parsed)
	}
}
