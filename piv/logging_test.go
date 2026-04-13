package piv

import (
	"bytes"
	"errors"
	"testing"
)

type stubCard struct {
	responses [][]byte
	err       error
	commands  [][]byte
	begin     int
	end       int
	close     int
}

func (c *stubCard) Transmit(command []byte) ([]byte, error) {
	c.commands = append(c.commands, append([]byte(nil), command...))
	if c.err != nil {
		return nil, c.err
	}
	if len(c.responses) == 0 {
		return nil, nil
	}
	response := append([]byte(nil), c.responses[0]...)
	c.responses = c.responses[1:]
	return response, nil
}

func (c *stubCard) Begin() error {
	c.begin++
	return nil
}

func (c *stubCard) End() error {
	c.end++
	return nil
}

func (c *stubCard) Close() error {
	c.close++
	return nil
}

type recordingLogger struct {
	events []APDUEvent
}

func (l *recordingLogger) LogAPDU(event APDUEvent) {
	l.events = append(l.events, event)
}

func TestWithAPDULoggerWrapsCardTraffic(t *testing.T) {
	inner := &stubCard{responses: [][]byte{{0x90, 0x00}}}
	logger := &recordingLogger{}
	card := WithAPDULogger(inner, logger)

	response, err := card.Transmit([]byte{0x00, 0xA4})
	if err != nil {
		t.Fatalf("Transmit() error = %v", err)
	}
	if len(response) != 2 || response[0] != 0x90 || response[1] != 0x00 {
		t.Fatalf("unexpected response: % X", response)
	}
	if len(logger.events) != 2 {
		t.Fatalf("logged events = %d, want 2", len(logger.events))
	}
	if logger.events[0].Direction != "->" || logger.events[1].Direction != "<-" {
		t.Fatalf("unexpected directions: %+v", logger.events)
	}
}

func TestWithAPDULoggerDoesNotLogFailedResponses(t *testing.T) {
	inner := &stubCard{err: errors.New("boom")}
	logger := &recordingLogger{}
	card := WithAPDULogger(inner, logger)

	if _, err := card.Transmit([]byte{0x00, 0xA4}); err == nil {
		t.Fatal("expected transmit error")
	}
	if len(logger.events) != 1 {
		t.Fatalf("logged events = %d, want 1", len(logger.events))
	}
	if logger.events[0].Direction != "->" {
		t.Fatalf("unexpected first direction: %q", logger.events[0].Direction)
	}
}

func TestWriterAPDULoggerUsesFormatter(t *testing.T) {
	var output bytes.Buffer
	logger := NewWriterAPDULogger(&output, APDUFormatterFunc(func(event APDUEvent) string {
		return event.Direction + ":custom"
	}))

	logger.LogAPDU(APDUEvent{Direction: "<-", Payload: []byte{0x90, 0x00}})

	if output.String() != "<-:custom\n" {
		t.Fatalf("unexpected output: %q", output.String())
	}
}
