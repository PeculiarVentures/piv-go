package adapters

import "fmt"

// CapabilityOverride overrides the default support or notes for a capability ID.
type CapabilityOverride struct {
	Support CapabilitySupport
	Notes   string
}

// NewCapabilityReport builds a capability report from the shared defaults and a
// targeted set of per-capability overrides.
func NewCapabilityReport(adapter Adapter, overrides map[CapabilityID]CapabilityOverride) CapabilityReport {
	report := defaultCapabilityReport(adapter)
	if len(overrides) == 0 {
		return report
	}

	indices := make(map[CapabilityID]int, len(report.Items))
	for index, item := range report.Items {
		indices[item.ID] = index
	}

	for id, override := range overrides {
		index, ok := indices[id]
		if !ok {
			panic(fmt.Sprintf("adapters: unknown capability override %q", id))
		}
		if override.Support != "" {
			report.Items[index].Support = override.Support
		}
		if override.Notes != "" {
			report.Items[index].Notes = override.Notes
		}
	}

	return report
}

func defaultCapabilityReport(adapter Adapter) CapabilityReport {
	adapterName := "standard-piv"
	if adapter != nil {
		adapterName = adapter.Name()
	}

	items := []Capability{
		{ID: CapabilityVerifyPIN, Label: "Verify PIN", Support: CapabilityStandard},
		{ID: CapabilityAuthenticateManagement, Label: "Authenticate Management Key", Support: CapabilityStandard},
		{ID: CapabilityInitializeToken, Label: "Initialize Token", Support: supportForInitialization(adapter)},
		{ID: CapabilityGenerateKey, Label: "Generate Key", Support: capabilitySupport(adapter, true, false, false)},
		{ID: CapabilityDeleteKey, Label: "Delete Key", Support: capabilitySupport(adapter, false, true, false)},
		{ID: CapabilityReadCertificate, Label: "Read Certificate", Support: capabilitySupport(adapter, false, false, true)},
		{ID: CapabilityWriteCertificate, Label: "Write Certificate", Support: capabilitySupport(adapter, false, false, true)},
		{ID: CapabilityDeleteCertificate, Label: "Delete Certificate", Support: capabilitySupport(adapter, false, false, true)},
		{ID: CapabilityReadSerialNumber, Label: "Read Serial Number", Support: supportForSerialNumber(adapter)},
		{ID: CapabilityReadTokenLabel, Label: "Read Token Label", Support: supportForTokenLabel(adapter)},
		{ID: CapabilityInspectSlots, Label: "Inspect Slots", Support: supportForSlotInspection(adapter)},
		{ID: CapabilityPINStatus, Label: "PIN Status", Support: CapabilityStandard},
		{ID: CapabilityPUKStatus, Label: "PUK Status", Support: CapabilityStandard},
		{ID: CapabilityChangePIN, Label: "Change PIN", Support: CapabilityStandard},
		{ID: CapabilityChangePUK, Label: "Change PUK", Support: CapabilityStandard},
		{ID: CapabilityUnblockPIN, Label: "Unblock PIN", Support: CapabilityStandard},
		{ID: CapabilityChangeManagementKey, Label: "Change Management Key", Support: supportForManagementKeyChange(adapter)},
		{ID: CapabilityResetSlot, Label: "Reset Slot", Support: supportForSlotReset(adapter)},
		{ID: CapabilityResetToken, Label: "Reset Token", Support: supportForTokenReset(adapter), Notes: "requires PIN and PUK to be blocked"},
	}

	return CapabilityReport{AdapterName: adapterName, Items: items}
}

func supportForTokenReset(adapter Adapter) CapabilitySupport {
	type tokenResetCapable interface {
		ResetToken(session *Session, params ResetTokenParams) error
	}
	if _, ok := adapter.(tokenResetCapable); ok {
		return CapabilityVendor
	}
	return CapabilityStandard
}
