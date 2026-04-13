package all

import (
	"github.com/PeculiarVentures/piv-go/adapters"
	"github.com/PeculiarVentures/piv-go/adapters/safenet"
	"github.com/PeculiarVentures/piv-go/adapters/yubikey"
)

// Register registers the built-in adapters in a caller-provided registry.
func Register(registry *adapters.Registry) {
	safenet.Register(registry)
	yubikey.Register(registry)
}

// NewRegistry creates a registry preloaded with the built-in adapters.
func NewRegistry() *adapters.Registry {
	registry := adapters.NewRegistry()
	Register(registry)
	return registry
}
