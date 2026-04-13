package piv

import (
	"fmt"
	"io"
	"sync"
)

// APDUEvent describes one APDU request or response frame.
type APDUEvent struct {
	Direction string
	Payload   []byte
}

// APDULogger receives APDU request and response events from a card transport.
type APDULogger interface {
	LogAPDU(event APDUEvent)
}

// APDUFormatter formats one APDU event as a log line.
type APDUFormatter interface {
	FormatAPDU(event APDUEvent) string
}

// APDUFormatterFunc adapts a function to APDUFormatter.
type APDUFormatterFunc func(event APDUEvent) string

// FormatAPDU formats one APDU event through the function adapter.
func (f APDUFormatterFunc) FormatAPDU(event APDUEvent) string {
	return f(event)
}

// WriterAPDULogger writes formatted APDU lines to an io.Writer.
type WriterAPDULogger struct {
	mu        sync.Mutex
	writer    io.Writer
	formatter APDUFormatter
}

// NewWriterAPDULogger creates an APDU logger backed by an io.Writer.
func NewWriterAPDULogger(writer io.Writer, formatter APDUFormatter) *WriterAPDULogger {
	if formatter == nil {
		formatter = APDUFormatterFunc(defaultAPDUFormat)
	}
	return &WriterAPDULogger{writer: writer, formatter: formatter}
}

// LogAPDU writes one formatted APDU line to the configured writer.
func (l *WriterAPDULogger) LogAPDU(event APDUEvent) {
	if l == nil || l.writer == nil {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	_, _ = fmt.Fprintln(l.writer, l.formatter.FormatAPDU(event))
}

// LoggedCard wraps a transport card and emits APDU events to an attached logger.
type LoggedCard struct {
	inner  Card
	logger APDULogger
}

// WithAPDULogger wraps a card with instance-scoped APDU logging.
func WithAPDULogger(card Card, logger APDULogger) Card {
	if card == nil || logger == nil {
		return card
	}
	return &LoggedCard{inner: card, logger: logger}
}

// Transmit sends the APDU to the wrapped card and logs the request and response.
func (c *LoggedCard) Transmit(command []byte) ([]byte, error) {
	if c == nil || c.inner == nil {
		return nil, fmt.Errorf("piv: logged card transport is required")
	}
	c.logger.LogAPDU(APDUEvent{Direction: "->", Payload: append([]byte(nil), command...)})
	response, err := c.inner.Transmit(command)
	if err != nil {
		return nil, err
	}
	c.logger.LogAPDU(APDUEvent{Direction: "<-", Payload: append([]byte(nil), response...)})
	return response, nil
}

// Begin starts a transaction on the wrapped card.
func (c *LoggedCard) Begin() error {
	if c == nil || c.inner == nil {
		return fmt.Errorf("piv: logged card transport is required")
	}
	return c.inner.Begin()
}

// End ends a transaction on the wrapped card.
func (c *LoggedCard) End() error {
	if c == nil || c.inner == nil {
		return fmt.Errorf("piv: logged card transport is required")
	}
	return c.inner.End()
}

// Close closes the wrapped card.
func (c *LoggedCard) Close() error {
	if c == nil || c.inner == nil {
		return fmt.Errorf("piv: logged card transport is required")
	}
	return c.inner.Close()
}

func defaultAPDUFormat(event APDUEvent) string {
	return fmt.Sprintf("APDU %s % x", event.Direction, event.Payload)
}
