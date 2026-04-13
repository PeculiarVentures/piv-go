package iso7816

import (
	"bytes"
	"testing"
)

func TestCommandBytes_Case1(t *testing.T) {
	cmd := &Command{Cla: 0x00, Ins: 0xA4, P1: 0x04, P2: 0x00, Le: -1}
	got := cmd.Bytes()
	want := []byte{0x00, 0xA4, 0x04, 0x00}
	if !bytes.Equal(got, want) {
		t.Errorf("Case1: got %X, want %X", got, want)
	}
}

func TestCommandBytes_Case2(t *testing.T) {
	cmd := &Command{Cla: 0x00, Ins: 0xA4, P1: 0x04, P2: 0x00, Le: 256}
	got := cmd.Bytes()
	want := []byte{0x00, 0xA4, 0x04, 0x00, 0x00}
	if !bytes.Equal(got, want) {
		t.Errorf("Case2: got %X, want %X", got, want)
	}
}

func TestCommandBytes_Case3(t *testing.T) {
	data := []byte{0xA0, 0x00, 0x00}
	cmd := &Command{Cla: 0x00, Ins: 0xA4, P1: 0x04, P2: 0x00, Data: data, Le: -1}
	got := cmd.Bytes()
	want := []byte{0x00, 0xA4, 0x04, 0x00, 0x03, 0xA0, 0x00, 0x00}
	if !bytes.Equal(got, want) {
		t.Errorf("Case3: got %X, want %X", got, want)
	}
}

func TestCommandBytes_Case4(t *testing.T) {
	data := []byte{0xA0, 0x00}
	cmd := &Command{Cla: 0x00, Ins: 0xA4, P1: 0x04, P2: 0x00, Data: data, Le: 10}
	got := cmd.Bytes()
	want := []byte{0x00, 0xA4, 0x04, 0x00, 0x02, 0xA0, 0x00, 0x0A}
	if !bytes.Equal(got, want) {
		t.Errorf("Case4: got %X, want %X", got, want)
	}
}

func TestParseCommand_Case1(t *testing.T) {
	raw := []byte{0x00, 0xA4, 0x04, 0x00}
	cmd, err := ParseCommand(raw)
	if err != nil {
		t.Fatal(err)
	}
	if cmd.Cla != 0x00 || cmd.Ins != 0xA4 || cmd.P1 != 0x04 || cmd.P2 != 0x00 {
		t.Errorf("unexpected header: %X %X %X %X", cmd.Cla, cmd.Ins, cmd.P1, cmd.P2)
	}
	if cmd.Le != -1 {
		t.Errorf("expected Le=-1, got %d", cmd.Le)
	}
}

func TestParseCommand_Case2(t *testing.T) {
	raw := []byte{0x00, 0xA4, 0x04, 0x00, 0x00}
	cmd, err := ParseCommand(raw)
	if err != nil {
		t.Fatal(err)
	}
	if cmd.Le != 256 {
		t.Errorf("expected Le=256, got %d", cmd.Le)
	}
}

func TestParseCommand_TooShort(t *testing.T) {
	_, err := ParseCommand([]byte{0x00, 0xA4})
	if err == nil {
		t.Fatal("expected error for short command")
	}
}
