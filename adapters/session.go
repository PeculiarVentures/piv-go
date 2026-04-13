package adapters

import (
	"fmt"

	"github.com/PeculiarVentures/piv-go/piv"
)

// APDULogProvider exposes collected APDU trace lines for an execution source.
type APDULogProvider interface {
	APDULog() []string
}

// Session carries the runtime context for adapter capability calls.
//
// It keeps the explicit execution state for one token interaction chain. It is
// not a generic value bag like context.Context. Callers should prefer
// constructing sessions via NewSession and deriving adjusted copies via Clone.
type Session struct {
	Client              *piv.Client
	APDULogSource       APDULogProvider
	Observer            Observer
	ReaderName          string
	ManagementAlgorithm byte
	ManagementKey       []byte
}

// SessionOption applies one explicit session configuration change.
type SessionOption func(session *Session)

// NewSession creates one execution session for the provided client.
func NewSession(client *piv.Client, options ...SessionOption) *Session {
	session := &Session{Client: client}
	applySessionOptions(session, options...)
	return session
}

// Clone creates a copy of the session and applies additional options.
func (s *Session) Clone(options ...SessionOption) *Session {
	if s == nil {
		return nil
	}
	clone := &Session{
		Client:              s.Client,
		APDULogSource:       s.APDULogSource,
		Observer:            s.Observer,
		ReaderName:          s.ReaderName,
		ManagementAlgorithm: s.ManagementAlgorithm,
		ManagementKey:       append([]byte(nil), s.ManagementKey...),
	}
	applySessionOptions(clone, options...)
	return clone
}

// WithReaderName sets the reader identity for a session.
func WithReaderName(readerName string) SessionOption {
	return func(session *Session) {
		session.ReaderName = readerName
	}
}

// WithManagementCredentials sets the management key algorithm and key material.
func WithManagementCredentials(algorithm byte, key []byte) SessionOption {
	return func(session *Session) {
		session.ManagementAlgorithm = algorithm
		session.ManagementKey = append([]byte(nil), key...)
	}
}

// WithObserver sets the adapter-level event observer.
func WithObserver(observer Observer) SessionOption {
	return func(session *Session) {
		session.Observer = observer
	}
}

// WithAPDULogSource sets the APDU log source for a session.
func WithAPDULogSource(source APDULogProvider) SessionOption {
	return func(session *Session) {
		session.APDULogSource = source
	}
}

// WithTraceCollector attaches one collector as both the observer and APDU source.
func WithTraceCollector(collector *TraceCollector) SessionOption {
	return func(session *Session) {
		session.Observer = collector
		session.APDULogSource = collector
	}
}

// Runtime binds a session to the adapter chosen for its reader.
type Runtime struct {
	Session *Session
	Adapter Adapter
}

// NewRuntime creates a runtime from an already prepared session and adapter.
func NewRuntime(session *Session, adapter Adapter) *Runtime {
	return &Runtime{Session: session, Adapter: adapter}
}

// AuthenticateManagementKey authenticates the session's configured management
// credentials using the supplied adapter for algorithm resolution when needed.
func (s *Session) AuthenticateManagementKey(adapter Adapter) error {
	if err := requireSessionClient(s); err != nil {
		return err
	}
	if len(s.ManagementKey) == 0 {
		return fmt.Errorf("adapters: management key is required")
	}
	if s.ManagementAlgorithm == 0 {
		s.Observe(LogLevelDebug, adapter, "authenticate-management-key", "resolving management key algorithm from key material")
		algorithm, err := ResolveManagementKeyAlgorithm(s, adapter, s.ManagementKey)
		if err != nil {
			return err
		}
		s.ManagementAlgorithm = algorithm
		s.Observe(LogLevelDebug, adapter, "authenticate-management-key", "resolved management key algorithm 0x%02X", algorithm)
	}
	s.Observe(LogLevelInfo, adapter, "authenticate-management-key", "authenticating management key")
	return s.Client.AuthenticateManagementKeyWithAlgorithm(s.ManagementAlgorithm, s.ManagementKey)
}

// AuthenticateManagementKey authenticates the runtime session with its bound adapter.
func (r *Runtime) AuthenticateManagementKey() error {
	if r == nil || r.Session == nil {
		return fmt.Errorf("adapters: session is required")
	}
	return r.Session.AuthenticateManagementKey(r.Adapter)
}

func applySessionOptions(session *Session, options ...SessionOption) {
	for _, option := range options {
		if option != nil {
			option(session)
		}
	}
}
