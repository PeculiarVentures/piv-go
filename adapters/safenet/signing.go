package safenet

import "github.com/PeculiarVentures/piv-go/adapters"

// SigningCapabilities returns an explicit unknown result until a SafeNet
// model/firmware signing path has a documented or qualified parameter matrix.
// Existing lifecycle capabilities, a reader label, or a certificate alone do
// not establish signing support. This method uses only the supplied snapshot;
// it performs no token access or implicit PIN verification.
func (a *Adapter) SigningCapabilities(device adapters.SigningDevice) adapters.SigningCapabilityReport {
	device.Evidence = append([]adapters.SigningEvidence(nil), device.Evidence...)
	return adapters.SigningCapabilityReport{
		AdapterName: a.Name(),
		Device:      device,
		Fallback: adapters.SigningDecision{
			Support: adapters.SigningUnknown,
			Reason:  adapters.SigningReasonQualificationPending,
			Detail:  "the SafeNet model and firmware signing parameter matrix has not been qualified",
		},
	}
}

var _ adapters.SigningCapabilityReporter = (*Adapter)(nil)
