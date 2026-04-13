package adapters

import (
	"fmt"
	"sync"
)

// Registry stores adapter registrations and resolves adapters for reader names.
type Registry struct {
	mu            sync.RWMutex
	adapters      []Adapter
	adaptersByKey map[string]Adapter
}

// NewRegistry creates an empty adapter registry.
func NewRegistry() *Registry {
	return &Registry{adaptersByKey: make(map[string]Adapter)}
}

// Register adds an adapter to the registry.
func (r *Registry) Register(adapter Adapter) {
	if adapter == nil {
		panic("adapters: register nil adapter")
	}
	if adapter.Name() == "" {
		panic("adapters: register adapter with empty name")
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	if _, exists := r.adaptersByKey[adapter.Name()]; exists {
		panic(fmt.Sprintf("adapters: adapter %q already registered", adapter.Name()))
	}
	r.adapters = append(r.adapters, adapter)
	r.adaptersByKey[adapter.Name()] = adapter
}

// Lookup returns the explicitly registered adapter for a stable key.
func (r *Registry) Lookup(key string) Adapter {
	if r == nil {
		return nil
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.adaptersByKey[key]
}

// Resolve returns the first registered adapter matching the specified reader name.
func (r *Registry) Resolve(readerName string) Adapter {
	for _, adapter := range r.registeredAdapters() {
		if adapter.MatchReader(readerName) {
			return adapter
		}
	}
	return nil
}

// ResolveRuntime resolves the adapter for the session reader and binds it to a runtime.
func (r *Registry) ResolveRuntime(session *Session) (*Runtime, error) {
	if r == nil {
		return nil, ErrRegistryRequired
	}
	if err := requireSessionReaderName(session); err != nil {
		return nil, err
	}
	adapter := r.Resolve(session.ReaderName)
	runtime := NewRuntime(session, adapter)
	if adapter == nil {
		session.Observe(LogLevelInfo, nil, "resolve-runtime", "no adapter matched reader %q", session.ReaderName)
		return runtime, nil
	}
	session.Observe(LogLevelInfo, adapter, "resolve-runtime", "selected adapter for reader %q", session.ReaderName)
	return runtime, nil
}

// ResolveRuntimeByKey binds a session to an explicitly selected adapter key.
func (r *Registry) ResolveRuntimeByKey(session *Session, key string) (*Runtime, error) {
	if r == nil {
		return nil, ErrRegistryRequired
	}
	if err := requireSession(session); err != nil {
		return nil, err
	}
	adapter := r.Lookup(key)
	if adapter == nil {
		return nil, fmt.Errorf("adapters: adapter %q is not registered", key)
	}
	runtime := NewRuntime(session, adapter)
	session.Observe(LogLevelInfo, adapter, "resolve-runtime", "selected adapter by explicit key %q", key)
	return runtime, nil
}

func (r *Registry) registeredAdapters() []Adapter {
	r.mu.RLock()
	defer r.mu.RUnlock()

	adapters := make([]Adapter, len(r.adapters))
	copy(adapters, r.adapters)
	return adapters
}
