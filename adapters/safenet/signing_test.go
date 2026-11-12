package safenet

import (
	"reflect"
	"testing"

	"github.com/PeculiarVentures/piv-go/adapters"
	"github.com/PeculiarVentures/piv-go/emulator"
	"github.com/PeculiarVentures/piv-go/piv"
)

func TestSigningCapabilitiesRemainUnknownWithoutQualification(t *testing.T) {
	adapter := NewAdapter()
	card := emulator.NewCard()
	runtime := adapters.NewRuntime(adapters.NewSession(piv.NewClient(card)), adapter)
	coarse := adapters.ReportCapabilities(adapter)
	for _, device := range []adapters.SigningDevice{
		{},
		{Model: "SafeNet eToken 5110", Firmware: "1.0.0"},
		{Model: "SafeNet eToken", Firmware: "5.7.0", PIVVersion: "5.7.0"},
	} {
		report := adapters.ReportSigningCapabilities(runtime.Adapter, device)
		if report.AdapterName != "safenet" || report.Fallback.Support != adapters.SigningUnknown || report.Fallback.Reason != adapters.SigningReason("qualification-pending") || len(report.Profiles) != 0 {
			t.Fatalf("unqualified SafeNet device acquired signing support: %+v", report)
		}
	}
	device := adapters.SigningDevice{Evidence: []adapters.SigningEvidence{{Source: "caller-cache"}}}
	report := adapter.SigningCapabilities(device)
	report.Device.Evidence[0].Source = "changed report"
	if device.Evidence[0].Source != "caller-cache" {
		t.Fatal("report aliases the caller's evidence")
	}
	if len(card.TransmittedCommands) != 0 {
		t.Fatalf("signing discovery sent %d APDUs", len(card.TransmittedCommands))
	}
	if !reflect.DeepEqual(coarse, adapters.ReportCapabilities(adapter)) {
		t.Fatal("signing discovery changed coarse capabilities")
	}
}
