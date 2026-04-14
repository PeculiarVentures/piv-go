package adapters_test

import (
	"testing"

	"github.com/PeculiarVentures/piv-go/adapters"
	"github.com/PeculiarVentures/piv-go/adapters/safenet"
	"github.com/PeculiarVentures/piv-go/adapters/yubikey"
)

func TestReportCapabilitiesWithoutAdapterUsesDefaults(t *testing.T) {
	report := adapters.ReportCapabilities(nil)

	if report.AdapterName != "standard-piv" {
		t.Fatalf("unexpected adapter name: %s", report.AdapterName)
	}
	if capabilityByID(report, adapters.CapabilityVerifyPIN).Support != adapters.CapabilityStandard {
		t.Fatal("verify-pin should be standard by default")
	}
	if capabilityByID(report, adapters.CapabilityDeleteKey).Support != adapters.CapabilityUnsupported {
		t.Fatal("delete-key should be unsupported by default")
	}
	if capabilityByID(report, adapters.CapabilityChangeManagementKey).Support != adapters.CapabilityUnsupported {
		t.Fatal("change-management-key should be unsupported by default")
	}
	if capabilityByID(report, adapters.CapabilityManagementKeyStatus).Support != adapters.CapabilityUnsupported {
		t.Fatal("management-key-status should be unsupported by default")
	}
	if capabilityByID(report, adapters.CapabilityInitializeToken).Support != adapters.CapabilityUnsupported {
		t.Fatal("initialize-token should be unsupported by default")
	}
}

func TestSafeNetCapabilitiesOverrideDefaults(t *testing.T) {
	report := adapters.ReportCapabilities(safenet.NewAdapter())

	if capabilityByID(report, adapters.CapabilityGenerateKey).Support != adapters.CapabilityVendor {
		t.Fatal("SafeNet generate-key should be vendor-backed")
	}
	if capabilityByID(report, adapters.CapabilityChangePIN).Support != adapters.CapabilityStandard {
		t.Fatal("SafeNet change-pin should remain standard")
	}
	if capabilityByID(report, adapters.CapabilityPUKStatus).Support != adapters.CapabilityVendor {
		t.Fatal("SafeNet puk-status should be vendor-backed")
	}
	if capabilityByID(report, adapters.CapabilityChangeManagementKey).Support != adapters.CapabilityVendor {
		t.Fatal("SafeNet management key change should be vendor-backed")
	}
	if capabilityByID(report, adapters.CapabilityManagementKeyStatus).Support != adapters.CapabilityVendor {
		t.Fatal("SafeNet management key status should be vendor-backed")
	}
	if capabilityByID(report, adapters.CapabilityInitializeToken).Support != adapters.CapabilityVendor {
		t.Fatal("SafeNet initialize-token should be vendor-backed")
	}
}

func TestYubiKeyCapabilitiesOverrideDefaults(t *testing.T) {
	report := adapters.ReportCapabilities(yubikey.NewAdapter())

	if capabilityByID(report, adapters.CapabilityDeleteKey).Support != adapters.CapabilityVendor {
		t.Fatal("YubiKey delete-key should be vendor-backed")
	}
	if capabilityByID(report, adapters.CapabilityInspectSlots).Support != adapters.CapabilityVendor {
		t.Fatal("YubiKey inspect-slots should be vendor-backed")
	}
	if capabilityByID(report, adapters.CapabilityChangeManagementKey).Support != adapters.CapabilityVendor {
		t.Fatal("YubiKey management key change should be vendor-backed")
	}
	if capabilityByID(report, adapters.CapabilityManagementKeyStatus).Support != adapters.CapabilityVendor {
		t.Fatal("YubiKey management key status should be vendor-backed")
	}
	if capabilityByID(report, adapters.CapabilityResetToken).Support != adapters.CapabilityVendor {
		t.Fatal("YubiKey reset-token should be vendor-backed")
	}
	if capabilityByID(report, adapters.CapabilityInitializeToken).Support != adapters.CapabilityUnsupported {
		t.Fatal("YubiKey initialize-token should be unsupported")
	}
}

func TestVendorCapabilityReportsPreserveDefaultCatalogShape(t *testing.T) {
	defaultReport := adapters.ReportCapabilities(nil)
	for _, adapter := range []adapters.Adapter{safenet.NewAdapter(), yubikey.NewAdapter()} {
		report := adapters.ReportCapabilities(adapter)
		if len(report.Items) != len(defaultReport.Items) {
			t.Fatalf("unexpected capability count for %s: got %d want %d", adapter.Name(), len(report.Items), len(defaultReport.Items))
		}
		for index, item := range report.Items {
			defaultItem := defaultReport.Items[index]
			if item.ID != defaultItem.ID {
				t.Fatalf("unexpected capability ID order for %s at %d: got %s want %s", adapter.Name(), index, item.ID, defaultItem.ID)
			}
			if item.Label != defaultItem.Label {
				t.Fatalf("unexpected capability label for %s/%s: got %s want %s", adapter.Name(), item.ID, item.Label, defaultItem.Label)
			}
		}
	}
}

func TestNewCapabilityReportRejectsUnknownOverrideID(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("expected panic for unknown capability override")
		}
	}()

	_ = adapters.NewCapabilityReport(nil, map[adapters.CapabilityID]adapters.CapabilityOverride{
		adapters.CapabilityID("missing-capability"): {Support: adapters.CapabilityVendor},
	})
}

func capabilityByID(report adapters.CapabilityReport, id adapters.CapabilityID) adapters.Capability {
	for _, item := range report.Items {
		if item.ID == id {
			return item
		}
	}
	return adapters.Capability{}
}
