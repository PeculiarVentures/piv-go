package emulator

import (
	"errors"
	"fmt"

	"github.com/PeculiarVentures/piv-go/iso7816"
)

// ErrUnhandled reports that a matched handler chose not to handle a command.
var ErrUnhandled = errors.New("emulator: handler did not handle command")

// MatchFunc reports whether a handler applies to an APDU command.
type MatchFunc func(command []byte) bool

// HandlerFunc processes one APDU command and returns a raw APDU response.
type HandlerFunc func(card *Card, command []byte) ([]byte, error)

type commandHandler struct {
	match  MatchFunc
	handle HandlerFunc
}

// Card is a programmable smart card double that supports static responses,
// response queues, APDU handlers, and APDU tracing.
type Card struct {
	// Responses maps APDU INS bytes to raw response data.
	Responses map[byte][]byte

	// ResponseQueues maps APDU INS bytes to a queue of responses for chaining tests.
	ResponseQueues map[byte][][]byte

	// TransmittedCommands records all commands sent via Transmit.
	TransmittedCommands [][]byte

	// Closed indicates whether Close was called.
	Closed bool

	// InTransaction indicates whether a transaction is active.
	InTransaction bool

	trace    *Trace
	handlers []commandHandler
}

// NewCard creates a new programmable card with an empty APDU trace.
func NewCard() *Card {
	return &Card{
		Responses:      make(map[byte][]byte),
		ResponseQueues: make(map[byte][][]byte),
		trace:          NewTrace(),
	}
}

// BuildResponse constructs a raw APDU response with the supplied payload and
// status word.
func BuildResponse(data []byte, sw uint16) []byte {
	response := make([]byte, len(data)+2)
	copy(response, data)
	response[len(data)] = byte(sw >> 8)
	response[len(data)+1] = byte(sw)
	return response
}

// BuildSuccessResponse constructs a success APDU response with status 9000.
func BuildSuccessResponse(data []byte) []byte {
	return BuildResponse(data, uint16(iso7816.SwSuccess))
}

// MatchINS matches APDU commands by INS byte.
func MatchINS(ins byte) MatchFunc {
	return func(command []byte) bool {
		return len(command) > 1 && command[1] == ins
	}
}

// MatchPrefix matches APDU commands by a raw byte prefix.
func MatchPrefix(prefix []byte) MatchFunc {
	prefixCopy := append([]byte(nil), prefix...)
	return func(command []byte) bool {
		if len(command) < len(prefixCopy) {
			return false
		}
		for index := range prefixCopy {
			if command[index] != prefixCopy[index] {
				return false
			}
		}
		return true
	}
}

// Trace returns the configured APDU trace collector.
func (c *Card) Trace() *Trace {
	return c.trace
}

// SetTrace replaces the APDU trace collector used by the card. Passing nil
// disables trace collection.
func (c *Card) SetTrace(trace *Trace) {
	c.trace = trace
}

// APDULog returns the collected APDU log lines.
func (c *Card) APDULog() []string {
	if c.trace == nil {
		return nil
	}
	return c.trace.Lines()
}

// RegisterHandler registers a custom APDU handler.
func (c *Card) RegisterHandler(match MatchFunc, handle HandlerFunc) {
	c.handlers = append(c.handlers, commandHandler{match: match, handle: handle})
}

// RegisterINSHandler registers a handler for one INS byte.
func (c *Card) RegisterINSHandler(ins byte, handle HandlerFunc) {
	c.RegisterHandler(MatchINS(ins), handle)
}

// RegisterPrefixHandler registers a handler for one APDU prefix.
func (c *Card) RegisterPrefixHandler(prefix []byte, handle HandlerFunc) {
	c.RegisterHandler(MatchPrefix(prefix), handle)
}

// SetResponse configures a response for a given INS byte.
func (c *Card) SetResponse(ins byte, data []byte, sw uint16) {
	c.Responses[ins] = BuildResponse(data, sw)
}

// SetSuccessResponse configures a success response with data for a given INS byte.
func (c *Card) SetSuccessResponse(ins byte, data []byte) {
	c.SetResponse(ins, data, uint16(iso7816.SwSuccess))
}

// EnqueueResponse adds a response to the queue for a given INS byte.
func (c *Card) EnqueueResponse(ins byte, data []byte, sw uint16) {
	c.ResponseQueues[ins] = append(c.ResponseQueues[ins], BuildResponse(data, sw))
}

// Transmit records the command, runs handlers, and returns a raw APDU response.
func (c *Card) Transmit(command []byte) ([]byte, error) {
	commandCopy := append([]byte(nil), command...)
	c.TransmittedCommands = append(c.TransmittedCommands, commandCopy)
	if c.trace != nil {
		c.trace.Log("->", commandCopy)
	}
	if len(commandCopy) < 4 {
		return nil, fmt.Errorf("emulator: command too short")
	}

	response, err := c.respond(commandCopy)
	if err != nil {
		return nil, err
	}
	if c.trace != nil {
		c.trace.Log("<-", response)
	}
	return append([]byte(nil), response...), nil
}

func (c *Card) respond(command []byte) ([]byte, error) {
	for _, handler := range c.handlers {
		if handler.match == nil || !handler.match(command) {
			continue
		}
		response, err := handler.handle(c, append([]byte(nil), command...))
		if errors.Is(err, ErrUnhandled) {
			continue
		}
		if err != nil {
			return nil, err
		}
		if response == nil {
			return nil, fmt.Errorf("emulator: handler returned nil response")
		}
		return response, nil
	}

	ins := command[1]
	if queue := c.ResponseQueues[ins]; len(queue) > 0 {
		response := append([]byte(nil), queue[0]...)
		c.ResponseQueues[ins] = queue[1:]
		return response, nil
	}
	if response, ok := c.Responses[ins]; ok {
		return append([]byte(nil), response...), nil
	}
	return BuildResponse(nil, uint16(iso7816.SwInsNotSupported)), nil
}

// Begin starts a mock transaction.
func (c *Card) Begin() error {
	c.InTransaction = true
	return nil
}

// End ends a mock transaction.
func (c *Card) End() error {
	c.InTransaction = false
	return nil
}

// Close marks the mock card as closed.
func (c *Card) Close() error {
	c.Closed = true
	return nil
}
