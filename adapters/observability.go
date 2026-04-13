package adapters

import (
	"fmt"
	"reflect"
	"sync"

	"github.com/PeculiarVentures/piv-go/piv"
)

// LogLevel describes the severity of one adapter-level event.
type LogLevel string

const (
	// LogLevelInfo describes a high-level operational event.
	LogLevelInfo LogLevel = "info"
	// LogLevelDebug describes a detailed diagnostic event.
	LogLevelDebug LogLevel = "debug"
)

// Event describes one adapter-level operational log entry.
type Event struct {
	Level     LogLevel
	Adapter   string
	Operation string
	Message   string
}

// Observer receives adapter-level operational events.
type Observer interface {
	Observe(event Event)
}

// ObserverFunc adapts a function to the Observer interface.
type ObserverFunc func(event Event)

// Observe delivers one event through the function adapter.
func (f ObserverFunc) Observe(event Event) {
	f(event)
}

// TraceMode controls which signal types a TraceCollector records.
type TraceMode string

const (
	// TraceModeAdapterOnly records adapter-level operational events only.
	TraceModeAdapterOnly TraceMode = "adapter"
	// TraceModeAPDUOnly records APDU request and response frames only.
	TraceModeAPDUOnly TraceMode = "apdu"
	// TraceModeCombined records both adapter-level events and APDU frames.
	TraceModeCombined TraceMode = "combined"
)

// TraceCollector accumulates operational events and APDU frames in memory.
type TraceCollector struct {
	mu         sync.Mutex
	mode       TraceMode
	lines      []string
	eventLines []string
}

// NewTraceCollector creates an in-memory trace collector for the selected mode.
func NewTraceCollector(mode TraceMode) *TraceCollector {
	if mode == "" {
		mode = TraceModeCombined
	}
	return &TraceCollector{mode: mode}
}

// Observe records one adapter-level event when the collector is configured to do so.
func (c *TraceCollector) Observe(event Event) {
	if c == nil || !c.recordsAdapterEvents() {
		return
	}
	line := formatEventLine(event)
	c.mu.Lock()
	defer c.mu.Unlock()
	c.lines = append(c.lines, line)
	c.eventLines = append(c.eventLines, line)
}

// RecordAPDU records one APDU frame when the collector is configured to do so.
func (c *TraceCollector) RecordAPDU(direction string, payload []byte) {
	if c == nil || !c.recordsAPDUFrames() {
		return
	}
	line := fmt.Sprintf("APDU %s % x", direction, payload)
	c.mu.Lock()
	defer c.mu.Unlock()
	c.lines = append(c.lines, line)
}

// LogAPDU records one APDU event so the collector can be attached directly to a card transport.
func (c *TraceCollector) LogAPDU(event piv.APDUEvent) {
	if c == nil {
		return
	}
	c.RecordAPDU(event.Direction, event.Payload)
}

// APDULog returns the collected trace lines.
func (c *TraceCollector) APDULog() []string {
	if c == nil {
		return nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	lines := make([]string, len(c.lines))
	copy(lines, c.lines)
	return lines
}

// EventLog returns only the adapter-level event lines.
func (c *TraceCollector) EventLog() []string {
	if c == nil {
		return nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	lines := make([]string, len(c.eventLines))
	copy(lines, c.eventLines)
	return lines
}

// Observe records one adapter-level event when an observer is configured.
func (s *Session) Observe(level LogLevel, adapter Adapter, operation string, format string, args ...interface{}) {
	if s == nil || s.Observer == nil {
		return
	}
	s.Observer.Observe(Event{
		Level:     level,
		Adapter:   adapterName(adapter),
		Operation: operation,
		Message:   fmt.Sprintf(format, args...),
	})
}

// TraceLog returns the most complete trace currently attached to the session.
func (s *Session) TraceLog() []string {
	if s == nil {
		return nil
	}
	if provider, ok := s.Observer.(APDULogProvider); ok {
		lines := provider.APDULog()
		if s.APDULogSource == nil || sameLogProvider(provider, s.APDULogSource) {
			return lines
		}
		merged := append([]string(nil), lines...)
		merged = append(merged, s.APDULogSource.APDULog()...)
		return merged
	}
	if s.APDULogSource == nil {
		return nil
	}
	return s.APDULogSource.APDULog()
}

func adapterName(adapter Adapter) string {
	if adapter == nil {
		return "standard-piv"
	}
	return adapter.Name()
}

func formatEventLine(event Event) string {
	prefix := fmt.Sprintf("# %s", event.Adapter)
	if event.Operation != "" {
		prefix += " " + event.Operation
	}
	if event.Level == LogLevelDebug {
		prefix += " [debug]"
	}
	return prefix + ": " + event.Message
}

func sameLogProvider(left any, right any) bool {
	leftValue := reflect.ValueOf(left)
	rightValue := reflect.ValueOf(right)
	if !leftValue.IsValid() || !rightValue.IsValid() || leftValue.Type() != rightValue.Type() {
		return false
	}
	switch leftValue.Kind() {
	case reflect.Chan, reflect.Func, reflect.Map, reflect.Pointer, reflect.Slice, reflect.UnsafePointer:
		return leftValue.Pointer() == rightValue.Pointer()
	default:
		return false
	}
}

func (c *TraceCollector) recordsAdapterEvents() bool {
	return c.mode == TraceModeAdapterOnly || c.mode == TraceModeCombined
}

func (c *TraceCollector) recordsAPDUFrames() bool {
	return c.mode == TraceModeAPDUOnly || c.mode == TraceModeCombined
}
