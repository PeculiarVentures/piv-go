package adapters

import "github.com/PeculiarVentures/piv-go/piv"

// CapabilitySupport describes how an operation is available on a token.
type CapabilitySupport string

const (
	// CapabilityStandard indicates the operation is available through the standard PIV path.
	CapabilityStandard CapabilitySupport = "standard"
	// CapabilityVendor indicates the operation is available through a vendor adapter.
	CapabilityVendor CapabilitySupport = "vendor"
	// CapabilityUnsupported indicates the operation is not available through the current library and adapter set.
	CapabilityUnsupported CapabilitySupport = "unsupported"
)

// CapabilityID identifies one user-facing token capability.
type CapabilityID string

const (
	CapabilityVerifyPIN              CapabilityID = "verify-pin"
	CapabilityAuthenticateManagement CapabilityID = "authenticate-management-key"
	CapabilityInitializeToken        CapabilityID = "initialize-token"
	CapabilityGenerateKey            CapabilityID = "generate-key"
	CapabilityDeleteKey              CapabilityID = "delete-key"
	CapabilityReadCertificate        CapabilityID = "read-certificate"
	CapabilityWriteCertificate       CapabilityID = "write-certificate"
	CapabilityDeleteCertificate      CapabilityID = "delete-certificate"
	CapabilityReadSerialNumber       CapabilityID = "read-serial-number"
	CapabilityReadTokenLabel         CapabilityID = "read-token-label"
	CapabilityInspectSlots           CapabilityID = "inspect-slots"
	CapabilityPINStatus              CapabilityID = "pin-status"
	CapabilityPUKStatus              CapabilityID = "puk-status"
	CapabilityChangePIN              CapabilityID = "change-pin"
	CapabilityChangePUK              CapabilityID = "change-puk"
	CapabilityUnblockPIN             CapabilityID = "unblock-pin"
	CapabilityChangeManagementKey    CapabilityID = "change-management-key"
	CapabilityManagementKeyStatus    CapabilityID = "management-key-status"
	CapabilityResetSlot              CapabilityID = "reset-slot"
	CapabilityResetToken             CapabilityID = "reset-token"
)

// Capability describes support for a user-facing token operation.
type Capability struct {
	ID      CapabilityID
	Label   string
	Support CapabilitySupport
	Notes   string
}

// CapabilityReport describes the supported operations for a token.
type CapabilityReport struct {
	AdapterName string
	Items       []Capability
}

// CapabilityReporter allows adapters to override the generic support model.
type CapabilityReporter interface {
	Capabilities() CapabilityReport
}

// ReportCapabilities returns the capability report for the selected adapter.
func ReportCapabilities(adapter Adapter) CapabilityReport {
	if reporter, ok := adapter.(CapabilityReporter); ok {
		return reporter.Capabilities()
	}
	return defaultCapabilityReport(adapter)
}

func capabilitySupport(adapter Adapter, keyGen bool, keyDelete bool, certificate bool) CapabilitySupport {
	switch {
	case keyGen:
		if _, ok := adapter.(KeyGenerationAdapter); ok {
			return CapabilityVendor
		}
		return CapabilityStandard
	case keyDelete:
		if _, ok := adapter.(KeyDeletionAdapter); ok {
			return CapabilityVendor
		}
		return CapabilityUnsupported
	case certificate:
		if _, ok := adapter.(CertificateAdapter); ok {
			return CapabilityVendor
		}
		return CapabilityStandard
	default:
		return CapabilityUnsupported
	}
}

func supportForSlotInspection(adapter Adapter) CapabilitySupport {
	if _, ok := adapter.(SlotInspector); ok {
		return CapabilityVendor
	}
	return CapabilityStandard
}

func supportForManagementKeyChange(adapter Adapter) CapabilitySupport {
	if credentialAdapter, ok := adapter.(CredentialAdapter); ok {
		_ = credentialAdapter
		return CapabilityVendor
	}
	return CapabilityUnsupported
}

func supportForManagementKeyStatus(adapter Adapter) CapabilitySupport {
	if _, ok := adapter.(ManagementKeyStatusAdapter); ok {
		return CapabilityVendor
	}
	return CapabilityUnsupported
}

func supportForSerialNumber(adapter Adapter) CapabilitySupport {
	if _, ok := adapter.(SerialNumberAdapter); ok {
		return CapabilityVendor
	}
	return CapabilityUnsupported
}

func supportForTokenLabel(adapter Adapter) CapabilitySupport {
	if _, ok := adapter.(LabelAdapter); ok {
		return CapabilityVendor
	}
	return CapabilityUnsupported
}

func supportForSlotReset(adapter Adapter) CapabilitySupport {
	type slotResetCapable interface {
		ResetSlot(session *Session, slot piv.Slot) error
	}
	if _, ok := adapter.(slotResetCapable); ok {
		return CapabilityVendor
	}
	return CapabilityUnsupported
}

func supportForInitialization(adapter Adapter) CapabilitySupport {
	if initAdapter, ok := adapter.(InitializationAdapter); ok {
		_ = initAdapter
		return CapabilityVendor
	}
	return CapabilityUnsupported
}
