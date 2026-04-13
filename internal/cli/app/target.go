package app

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"

	"github.com/PeculiarVentures/piv-go/adapters"
	adaptersall "github.com/PeculiarVentures/piv-go/adapters/all"
	"github.com/PeculiarVentures/piv-go/pcsc"
	"github.com/PeculiarVentures/piv-go/piv"
)

// CardContext abstracts the PC/SC context for production and tests.
type CardContext interface {
	ListReaders() ([]string, error)
	Connect(reader string) (piv.Card, error)
	Release() error
}

// CardContextFactory creates card contexts.
type CardContextFactory interface {
	NewContext() (CardContext, error)
}

type realCardContextFactory struct{}

type pcscContextAdapter struct {
	inner *pcsc.Context
}

func (realCardContextFactory) NewContext() (CardContext, error) {
	context, err := pcsc.NewContext()
	if err != nil {
		return nil, err
	}
	return &pcscContextAdapter{inner: context}, nil
}

func (a *pcscContextAdapter) ListReaders() ([]string, error) {
	return a.inner.ListReaders()
}

func (a *pcscContextAdapter) Connect(reader string) (piv.Card, error) {
	return a.inner.Connect(reader)
}

func (a *pcscContextAdapter) Release() error {
	return a.inner.Release()
}

// ResolvedTarget contains the runtime bound to one selected reader.
type ResolvedTarget struct {
	Summary   TargetSummary
	Session   *adapters.Session
	Runtime   *adapters.Runtime
	collector *adapters.TraceCollector
	closeFn   func() error
}

// Close releases the selected card and the underlying reader context.
func (t *ResolvedTarget) Close() error {
	if t == nil || t.closeFn == nil {
		return nil
	}
	return t.closeFn()
}

// TraceLines returns the collected APDU or operation trace.
func (t *ResolvedTarget) TraceLines() []string {
	if t == nil || t.Session == nil {
		return nil
	}
	return t.Session.TraceLog()
}

// TargetResolver selects readers, opens sessions, and resolves adapters.
type TargetResolver struct {
	factory  CardContextFactory
	registry *adapters.Registry
	input    io.Reader
	stderr   io.Writer
}

// NewTargetResolver creates a resolver backed by the provided context factory.
func NewTargetResolver(factory CardContextFactory, registry *adapters.Registry, input io.Reader, stderr io.Writer) *TargetResolver {
	if factory == nil {
		factory = realCardContextFactory{}
	}
	if registry == nil {
		registry = adaptersall.NewRegistry()
	}
	return &TargetResolver{factory: factory, registry: registry, input: input, stderr: stderr}
}

// Discover enumerates visible readers and safely probes them for PIV readiness.
func (r *TargetResolver) Discover(ctx context.Context) ([]DeviceInfo, error) {
	cardContext, err := r.factory.NewContext()
	if err != nil {
		return nil, err
	}
	defer func() {
		_ = cardContext.Release()
	}()

	readers, err := callWithContext(ctx, cardContext.ListReaders)
	if err != nil {
		return nil, err
	}
	sort.Strings(readers)
	devices := make([]DeviceInfo, 0, len(readers))
	for _, reader := range readers {
		devices = append(devices, r.probeReader(ctx, cardContext, reader))
	}
	return devices, nil
}

// Resolve selects one reader, connects to it, and returns a runtime.
func (r *TargetResolver) Resolve(ctx context.Context, options GlobalOptions) (*ResolvedTarget, error) {
	cardContext, err := r.factory.NewContext()
	if err != nil {
		return nil, err
	}
	keepContext := false
	defer func() {
		if !keepContext {
			_ = cardContext.Release()
		}
	}()

	readers, err := callWithContext(ctx, cardContext.ListReaders)
	if err != nil {
		return nil, err
	}
	sort.Strings(readers)
	if len(readers) == 0 {
		return nil, TargetError("no-reader", "no PC/SC readers are available", "connect a reader and rerun piv devices")
	}

	selectionOrigin := options.ReaderOrigin
	selectedReader := options.Reader
	if selectedReader != "" {
		if !containsString(readers, selectedReader) {
			return nil, TargetError("reader-not-found", fmt.Sprintf("reader %q was not found", selectedReader), "rerun piv devices to list available readers")
		}
	} else {
		readyReaders := make([]string, 0)
		for _, reader := range readers {
			probe := r.probeReader(ctx, cardContext, reader)
			if probe.PIVReady {
				readyReaders = append(readyReaders, reader)
			}
		}
		switch len(readyReaders) {
		case 0:
			return nil, TargetError("no-target", "no PIV token is available", "insert a token and rerun piv devices")
		case 1:
			selectedReader = readyReaders[0]
			selectionOrigin = "auto"
		default:
			if options.NonInteractive {
				return nil, TargetError("ambiguous-target", "multiple PIV tokens are available and no default reader is configured", "rerun with --reader <name> or set one with piv config set default-reader <name>")
			}
			selectedReader, err = r.promptReaderChoice(readyReaders)
			if err != nil {
				return nil, err
			}
			selectionOrigin = "prompt"
		}
	}

	target, err := r.openTarget(ctx, cardContext, selectedReader, selectionOrigin, options)
	if err != nil {
		return nil, err
	}
	keepContext = true
	return target, nil
}

func (r *TargetResolver) openTarget(ctx context.Context, cardContext CardContext, reader string, selectionOrigin string, options GlobalOptions) (*ResolvedTarget, error) {
	card, err := callWithContext(ctx, func() (piv.Card, error) {
		return cardContext.Connect(reader)
	})
	if err != nil {
		return nil, TargetError("reader-unavailable", fmt.Sprintf("unable to open reader %q", reader), "rerun piv devices or choose another reader")
	}

	var collector *adapters.TraceCollector
	wrappedCard := card
	sessionOptions := []adapters.SessionOption{adapters.WithReaderName(reader)}
	switch options.Trace {
	case TraceAPDU:
		collector = adapters.NewTraceCollector(adapters.TraceModeAPDUOnly)
		wrappedCard = piv.WithAPDULogger(card, collector)
		sessionOptions = append(sessionOptions, adapters.WithAPDULogSource(collector))
	case TraceOps:
		collector = adapters.NewTraceCollector(adapters.TraceModeAdapterOnly)
		sessionOptions = append(sessionOptions, adapters.WithObserver(collector))
	case TraceAll:
		collector = adapters.NewTraceCollector(adapters.TraceModeCombined)
		wrappedCard = piv.WithAPDULogger(card, collector)
		sessionOptions = append(sessionOptions, adapters.WithTraceCollector(collector))
	}

	client := piv.NewClient(wrappedCard)
	session := adapters.NewSession(client, sessionOptions...)
	if err := runWithContext(ctx, client.Select); err != nil {
		_ = card.Close()
		return nil, TargetError("token-not-ready", fmt.Sprintf("reader %q does not contain a ready PIV token", reader), "rerun piv doctor or choose another reader")
	}

	runtime, err := r.resolveRuntime(session, options)
	if err != nil {
		_ = card.Close()
		return nil, err
	}

	return &ResolvedTarget{
		Summary: TargetSummary{
			Reader:    reader,
			Adapter:   adapterName(runtime.Adapter),
			Selection: selectionOrigin,
		},
		Session:   session,
		Runtime:   runtime,
		collector: collector,
		closeFn: func() error {
			closeErr := card.Close()
			releaseErr := cardContext.Release()
			if closeErr != nil {
				return closeErr
			}
			return releaseErr
		},
	}, nil
}

func (r *TargetResolver) resolveRuntime(session *adapters.Session, options GlobalOptions) (*adapters.Runtime, error) {
	adapter := strings.ToLower(strings.TrimSpace(options.Adapter))
	switch adapter {
	case "", "auto":
		return r.registry.ResolveRuntime(session)
	case "standard":
		return adapters.NewRuntime(session, nil), nil
	case "safenet", "yubikey":
		return r.registry.ResolveRuntimeByKey(session, adapter)
	default:
		return nil, UsageError(fmt.Sprintf("unsupported adapter %q", options.Adapter), "use auto, standard, safenet, or yubikey")
	}
}

func (r *TargetResolver) probeReader(ctx context.Context, cardContext CardContext, reader string) DeviceInfo {
	device := DeviceInfo{Reader: reader, Status: "unavailable"}
	card, err := callWithContext(ctx, func() (piv.Card, error) {
		return cardContext.Connect(reader)
	})
	if err != nil {
		device.Message = "reader is present but no card session is available"
		return device
	}
	device.CardPresent = true
	defer func() {
		_ = card.Close()
	}()

	client := piv.NewClient(card)
	if err := runWithContext(ctx, client.Select); err != nil {
		device.Status = "card-present"
		device.Message = "PIV application is not selectable"
		return device
	}
	device.PIVReady = true
	device.Status = "ready"
	device.Adapter = adapterName(r.registry.Resolve(reader))
	return device
}

func (r *TargetResolver) promptReaderChoice(readers []string) (string, error) {
	reader := bufio.NewReader(r.input)
	for {
		if r.stderr != nil {
			_, _ = fmt.Fprintln(r.stderr, "Multiple PIV tokens are available:")
			for index, item := range readers {
				_, _ = fmt.Fprintf(r.stderr, "  %d. %s\n", index+1, item)
			}
			_, _ = fmt.Fprint(r.stderr, "Select a reader by number: ")
		}
		line, err := reader.ReadString('\n')
		if err != nil && err != io.EOF {
			return "", IOError("unable to read the selected reader", "rerun with --reader <name> or --non-interactive", err)
		}
		choice, parseErr := strconv.Atoi(strings.TrimSpace(line))
		if parseErr == nil && choice >= 1 && choice <= len(readers) {
			return readers[choice-1], nil
		}
		if err == io.EOF {
			return "", RefusedError("reader selection is required", "rerun with --reader <name> or --non-interactive")
		}
	}
}

func adapterName(adapter adapters.Adapter) string {
	if adapter == nil {
		return "standard"
	}
	return adapter.Name()
}

func containsString(values []string, candidate string) bool {
	for _, value := range values {
		if value == candidate {
			return true
		}
	}
	return false
}

func callWithContext[T any](ctx context.Context, fn func() (T, error)) (T, error) {
	type result struct {
		value T
		err   error
	}
	channel := make(chan result, 1)
	go func() {
		value, err := fn()
		channel <- result{value: value, err: err}
	}()
	select {
	case <-ctx.Done():
		var zero T
		return zero, ctx.Err()
	case result := <-channel:
		return result.value, result.err
	}
}

func runWithContext(ctx context.Context, fn func() error) error {
	_, err := callWithContext(ctx, func() (struct{}, error) {
		return struct{}{}, fn()
	})
	return err
}
