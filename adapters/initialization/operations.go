package initialization

import (
	"fmt"

	"github.com/PeculiarVentures/piv-go/adapters"
)

// DescribeInitialization resolves the adapter for the session and returns its
// initialization requirements.
func DescribeInitialization(registry *adapters.Registry, session *adapters.Session) (adapters.InitializationRequirements, error) {
	if registry == nil {
		return adapters.InitializationRequirements{}, adapters.ErrRegistryRequired
	}
	runtime, err := registry.ResolveRuntime(session)
	if err != nil {
		return adapters.InitializationRequirements{}, err
	}
	return DescribeInitializationWithRuntime(runtime)
}

// DescribeInitializationWithRuntime returns initialization requirements for an already resolved runtime.
func DescribeInitializationWithRuntime(runtime *adapters.Runtime) (adapters.InitializationRequirements, error) {
	if err := requireRuntime(runtime); err != nil {
		return adapters.InitializationRequirements{}, err
	}
	if runtime.Adapter == nil {
		runtime.Session.Observe(adapters.LogLevelInfo, nil, "describe-initialization", "no adapter matched selected reader")
		return adapters.InitializationRequirements{}, adapters.ErrUnsupportedToken
	}

	initAdapter, ok := runtime.Adapter.(adapters.InitializationAdapter)
	if !ok {
		runtime.Session.Observe(adapters.LogLevelInfo, runtime.Adapter, "describe-initialization", "adapter does not implement token initialization")
		return adapters.InitializationRequirements{}, adapters.ErrInitializationNotSupported
	}

	runtime.Session.Observe(adapters.LogLevelDebug, runtime.Adapter, "describe-initialization", "reading adapter initialization requirements")
	return initAdapter.DescribeInitialization(runtime.Session)
}

// InitializeToken resolves the adapter for the session and executes its
// vendor-specific initialization flow.
func InitializeToken(registry *adapters.Registry, session *adapters.Session, params adapters.InitializeTokenParams) (*adapters.InitializationResult, error) {
	if err := params.Validate(); err != nil {
		return nil, err
	}
	if registry == nil {
		return nil, adapters.ErrRegistryRequired
	}
	runtime, err := registry.ResolveRuntime(session)
	if err != nil {
		return nil, err
	}
	return InitializeTokenWithRuntime(runtime, params)
}

// InitializeTokenWithRuntime executes token initialization for an already resolved runtime.
func InitializeTokenWithRuntime(runtime *adapters.Runtime, params adapters.InitializeTokenParams) (*adapters.InitializationResult, error) {
	if err := requireRuntime(runtime); err != nil {
		return nil, err
	}
	if runtime.Adapter == nil {
		runtime.Session.Observe(adapters.LogLevelInfo, nil, "initialize-token", "no adapter matched selected reader")
		return nil, adapters.ErrUnsupportedToken
	}

	initAdapter, ok := runtime.Adapter.(adapters.InitializationAdapter)
	if !ok {
		runtime.Session.Observe(adapters.LogLevelInfo, runtime.Adapter, "initialize-token", "adapter does not implement token initialization")
		return nil, adapters.ErrInitializationNotSupported
	}

	runtime.Session.Observe(adapters.LogLevelInfo, runtime.Adapter, "initialize-token", "starting adapter initialization flow")
	return initAdapter.InitializeToken(runtime.Session, params)
}

func requireRuntime(runtime *adapters.Runtime) error {
	if runtime == nil || runtime.Session == nil {
		return fmt.Errorf("adapters: session is required")
	}
	return nil
}
