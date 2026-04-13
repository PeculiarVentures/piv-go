package adapters

import (
	"fmt"
	"time"
)

// InitializationAdapter defines vendor-specific token initialization behavior.
//
// Implementations expose the required inputs for initialization and execute the
// vendor-specific flow for preparing a token for first use.
type InitializationAdapter interface {
	// DescribeInitialization returns the initialization requirements for the
	// selected token.
	DescribeInitialization(session *Session) (InitializationRequirements, error)
	// InitializeToken executes the vendor-specific initialization flow.
	InitializeToken(session *Session, params InitializeTokenParams) (*InitializationResult, error)
}

// InitializationRequirements describes the high-level operations supported by a
// token initialization flow.
type InitializationRequirements struct {
	// SupportsClearContainers reports whether the flow can clear vendor and PIV
	// containers.
	SupportsClearContainers bool
	// SupportsProvisionIdentity reports whether the flow can provision identity
	// objects such as CHUID.
	SupportsProvisionIdentity bool

	// Fields describes non-credential inputs UI or API callers should collect.
	Fields []InitializationField
}

// InitializationField describes one input required by an initialization flow.
type InitializationField struct {
	// Name is the stable programmatic field name.
	Name string
	// Label is a human-readable field label.
	Label string
	// Description explains how the value is used.
	Description string
	// Secret reports whether the field should be masked.
	Secret bool
	// Required reports whether the field must be provided.
	Required bool
}

// InitializeTokenParams contains one high-level token initialization request.
type InitializeTokenParams struct {
	// ClearContainers enables vendor and PIV container cleanup.
	ClearContainers bool
	// ProvisionIdentity enables identity provisioning inside the adapter.
	ProvisionIdentity bool
	// InitializedAt overrides the logical initialization time used for generated
	// identity objects. When zero, time.Now().UTC() is used.
	InitializedAt time.Time
}

// InitializationResult summarizes the operations executed by initialization.
type InitializationResult struct {
	// ManagementAuthenticated reports whether management authentication
	// completed successfully.
	ManagementAuthenticated bool
	// ContainersCleared lists the containers that were cleared.
	ContainersCleared []string
	// ObjectsWritten lists identity or vendor objects written during the flow.
	ObjectsWritten []string
	// PINChanged reports whether the PIN changed during initialization.
	PINChanged bool
	// PUKChanged reports whether the PUK changed during initialization.
	PUKChanged bool
	// Steps lists the high-level initialization steps that ran.
	Steps []string
	// Notes contains additional human-readable notes from the adapter.
	Notes []string
	// APDULog contains collected trace lines, including APDU frames and optional
	// adapter-level comment lines when a session observer is attached.
	APDULog []string
}

var (
	// ErrInitializationNotSupported reports that the resolved adapter does not
	// implement token initialization.
	ErrInitializationNotSupported = fmt.Errorf("adapters: initialization is not supported by this token")
	// ErrUnsupportedToken reports that no adapter matched the selected reader.
	ErrUnsupportedToken = fmt.Errorf("adapters: no adapter found for the specified reader")
	// ErrRegistryRequired reports that runtime resolution requires an explicit registry.
	ErrRegistryRequired = fmt.Errorf("adapters: registry is required")
)

// Validate performs generic consistency checks for initialization parameters.
func (p InitializeTokenParams) Validate() error {
	if !p.ClearContainers && !p.ProvisionIdentity {
		return fmt.Errorf("adapters: initialization requires at least one enabled operation")
	}
	if !p.ProvisionIdentity && !p.InitializedAt.IsZero() {
		return fmt.Errorf("adapters: InitializedAt requires ProvisionIdentity")
	}
	return nil
}

// DefaultInitializationRequirementsFromFields constructs requirements from a
// field declaration list for simple adapters.
func DefaultInitializationRequirementsFromFields(fields []InitializationField) InitializationRequirements {
	return InitializationRequirements{Fields: fields}
}
