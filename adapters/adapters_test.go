package adapters_test

import (
	"testing"

	adaptercore "github.com/PeculiarVentures/piv-go/adapters"
	adapterall "github.com/PeculiarVentures/piv-go/adapters/all"
	"github.com/PeculiarVentures/piv-go/iso7816"
	"github.com/PeculiarVentures/piv-go/piv"

	"github.com/PeculiarVentures/piv-go/emulator"
)

type testAdapter struct {
	name    string
	matches func(readerName string) bool
}

func (a testAdapter) Name() string {
	return a.name
}

func (a testAdapter) MatchReader(readerName string) bool {
	return a.matches(readerName)
}

func TestRegistriesAreIsolated(t *testing.T) {
	custom := adaptercore.NewRegistry()
	other := adaptercore.NewRegistry()
	custom.Register(testAdapter{name: "custom", matches: func(readerName string) bool { return readerName == "custom-reader" }})

	if adapter := other.Lookup("custom"); adapter != nil {
		t.Fatalf("independent registry unexpectedly looked up %q", adapter.Name())
	}
	if adapter := other.Resolve("custom-reader"); adapter != nil {
		t.Fatalf("independent registry unexpectedly resolved %q", adapter.Name())
	}

	adapter := custom.Resolve("custom-reader")
	if adapter == nil {
		t.Fatal("expected adapter match in custom registry")
	}
	if got := adapter.Name(); got != "custom" {
		t.Fatalf("custom registry resolved %q, want custom", got)
	}
	if adapter := custom.Lookup("custom"); adapter == nil || adapter.Name() != "custom" {
		t.Fatalf("custom registry lookup = %#v, want custom", adapter)
	}
}

func TestRegistryRegisterRejectsDuplicateAdapterNames(t *testing.T) {
	registry := adaptercore.NewRegistry()
	registry.Register(testAdapter{name: "duplicate", matches: func(string) bool { return false }})

	defer func() {
		recovered := recover()
		if recovered == nil {
			t.Fatal("expected duplicate adapter registration to panic")
		}
	}()

	registry.Register(testAdapter{name: "duplicate", matches: func(string) bool { return true }})
}

func TestRegistryResolveReturnsNilWhenRegistryHasNoMatch(t *testing.T) {
	registry := adaptercore.NewRegistry()

	if adapter := registry.Resolve("Unknown Reader"); adapter != nil {
		t.Fatalf("Resolve returned unexpected adapter %q", adapter.Name())
	}
}

func TestRegistryResolveUsesRegistrationOrder(t *testing.T) {
	registry := adaptercore.NewRegistry()

	registry.Register(testAdapter{name: "first", matches: func(string) bool { return true }})
	registry.Register(testAdapter{name: "second", matches: func(string) bool { return true }})

	adapter := registry.Resolve("any reader")
	if adapter == nil {
		t.Fatal("expected adapter match")
	}
	if got := adapter.Name(); got != "first" {
		t.Fatalf("Resolve returned %q, want first", got)
	}
}

func TestRegistryResolvePrefersFirstConflictingMatchReader(t *testing.T) {
	registry := adaptercore.NewRegistry()

	registry.Register(testAdapter{name: "safenet-like", matches: func(readerName string) bool { return readerName == "shared" }})
	registry.Register(testAdapter{name: "generic", matches: func(readerName string) bool { return readerName == "shared" }})

	adapter := registry.Resolve("shared")
	if adapter == nil {
		t.Fatal("expected adapter match")
	}
	if got := adapter.Name(); got != "safenet-like" {
		t.Fatalf("Resolve returned %q, want safenet-like", got)
	}
}

func TestSessionAuthenticateManagementKeySuccess(t *testing.T) {
	mock := emulator.NewCard()
	challenge := []byte{0x10, 0x32, 0x54, 0x76, 0x98, 0xBA, 0xDC, 0xFE, 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF}
	challengeResp := iso7816.EncodeTLV(0x7C, iso7816.EncodeTLV(0x81, challenge))
	mock.EnqueueResponse(0x87, challengeResp, uint16(iso7816.SwSuccess))
	mock.EnqueueResponse(0x87, nil, uint16(iso7816.SwSuccess))

	session := &adaptercore.Session{
		Client:              piv.NewClient(mock),
		ManagementAlgorithm: piv.AlgAES128,
		ManagementKey:       []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08},
	}

	if err := session.AuthenticateManagementKey(nil); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestSessionAuthenticateManagementKeyRequiresClient(t *testing.T) {
	session := &adaptercore.Session{ManagementAlgorithm: piv.AlgAES128, ManagementKey: []byte{0x01}}
	if err := session.AuthenticateManagementKey(nil); err == nil {
		t.Fatal("expected error when session client is missing")
	}
}

func TestRegistryResolveRuntimeBindsResolvedAdapter(t *testing.T) {
	registry := adaptercore.NewRegistry()
	registry.Register(testAdapter{name: "custom", matches: func(readerName string) bool { return readerName == "custom-reader" }})

	runtime, err := registry.ResolveRuntime(&adaptercore.Session{ReaderName: "custom-reader"})
	if err != nil {
		t.Fatalf("ResolveRuntime() error = %v", err)
	}
	if runtime.Adapter == nil || runtime.Adapter.Name() != "custom" {
		t.Fatalf("ResolveRuntime() adapter = %#v, want custom", runtime.Adapter)
	}
}

func TestRegistryResolveRuntimeRecordsAdapterSelection(t *testing.T) {
	registry := adaptercore.NewRegistry()
	registry.Register(testAdapter{name: "custom", matches: func(readerName string) bool { return readerName == "custom-reader" }})
	trace := adaptercore.NewTraceCollector(adaptercore.TraceModeAdapterOnly)

	_, err := registry.ResolveRuntime(&adaptercore.Session{ReaderName: "custom-reader", Observer: trace, APDULogSource: trace})
	if err != nil {
		t.Fatalf("ResolveRuntime() error = %v", err)
	}

	lines := trace.APDULog()
	if len(lines) != 1 {
		t.Fatalf("trace lines = %d, want 1", len(lines))
	}
	if lines[0] != `# custom resolve-runtime: selected adapter for reader "custom-reader"` {
		t.Fatalf("unexpected trace line: %q", lines[0])
	}
}

func TestRegistryResolveRuntimeByKeyBindsExplicitAdapter(t *testing.T) {
	registry := adaptercore.NewRegistry()
	registry.Register(testAdapter{name: "custom", matches: func(string) bool { return false }})
	trace := adaptercore.NewTraceCollector(adaptercore.TraceModeAdapterOnly)

	runtime, err := registry.ResolveRuntimeByKey(&adaptercore.Session{Observer: trace, APDULogSource: trace}, "custom")
	if err != nil {
		t.Fatalf("ResolveRuntimeByKey() error = %v", err)
	}
	if runtime.Adapter == nil || runtime.Adapter.Name() != "custom" {
		t.Fatalf("ResolveRuntimeByKey() adapter = %#v, want custom", runtime.Adapter)
	}
	lines := trace.APDULog()
	if len(lines) != 1 {
		t.Fatalf("trace lines = %d, want 1", len(lines))
	}
	if lines[0] != `# custom resolve-runtime: selected adapter by explicit key "custom"` {
		t.Fatalf("unexpected trace line: %q", lines[0])
	}
}

func TestBuiltInRegistryResolvesBundledAdapters(t *testing.T) {
	registry := adapterall.NewRegistry()
	if safeNet := registry.Lookup("safenet"); safeNet == nil || safeNet.Name() != "safenet" {
		t.Fatalf("SafeNet registry lookup = %#v, want safenet adapter", safeNet)
	}
	if yubiKey := registry.Lookup("yubikey"); yubiKey == nil || yubiKey.Name() != "yubikey" {
		t.Fatalf("YubiKey registry lookup = %#v, want yubikey adapter", yubiKey)
	}

	safeNet := registry.Resolve("SafeNet eToken Fusion")
	if safeNet == nil || safeNet.Name() != "safenet" {
		t.Fatalf("SafeNet registry resolution = %#v, want safenet adapter", safeNet)
	}

	yubiKey := registry.Resolve("Yubico YubiKey OTP+FIDO+CCID")
	if yubiKey == nil || yubiKey.Name() != "yubikey" {
		t.Fatalf("YubiKey registry resolution = %#v, want yubikey adapter", yubiKey)
	}
}
