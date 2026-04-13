package safenet

import (
	"encoding/hex"
	"strings"
	"testing"
	"time"

	"github.com/PeculiarVentures/piv-go/adapters"
	"github.com/PeculiarVentures/piv-go/emulator"
	"github.com/PeculiarVentures/piv-go/internal/testtrace"
	"github.com/PeculiarVentures/piv-go/iso7816"
	"github.com/PeculiarVentures/piv-go/piv"
)

func TestDescribeInitializationReportsSafeNetRequirements(t *testing.T) {
	requirements, err := NewAdapter().DescribeInitialization(&adapters.Session{ReaderName: "SafeNet eToken Fusion"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !requirements.SupportsProvisionIdentity {
		t.Fatal("expected provision identity support")
	}
	if !requirements.SupportsClearContainers {
		t.Fatal("expected container clearing support")
	}
	if len(requirements.Fields) != 0 {
		t.Fatalf("expected no public initialization fields, got %d", len(requirements.Fields))
	}
}

func TestBuildSafeNetCHUIDUsesTenYearExpiry(t *testing.T) {
	initializedAt := time.Date(2026, time.April, 1, 11, 50, 43, 0, time.UTC)
	payload, err := buildSafeNetCHUID("SafeNet eToken Fusion", initializedAt)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	expiry := readCHUIDExpiry(t, payload)
	if expiry != "20360401" {
		t.Fatalf("unexpected CHUID expiry: %s", expiry)
	}
}

func TestInitializeTokenWithEmulatorSessionProducesTraceAlignedAPDULog(t *testing.T) {
	initializedAt := time.Date(2026, time.April, 1, 11, 50, 43, 0, time.UTC)
	card := NewInitializationEmulatorCard()
	result, err := NewAdapter().InitializeToken(
		&adapters.Session{
			Client:        piv.NewClient(card),
			APDULogSource: card,
			ReaderName:    "SafeNet eToken Fusion",
		},
		adapters.InitializeTokenParams{
			ClearContainers:   true,
			ProvisionIdentity: true,
			InitializedAt:     initializedAt,
		},
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	wantSteps := []string{
		"select-piv",
		"enumerate-structure",
		"authenticate-management",
		"provision-identity",
		"clear-containers",
	}
	if len(result.Steps) != len(wantSteps) {
		t.Fatalf("unexpected steps: %+v", result.Steps)
	}
	for index, step := range wantSteps {
		if result.Steps[index] != step {
			t.Fatalf("unexpected step at %d: got %s want %s", index, result.Steps[index], step)
		}
	}
	if !result.ManagementAuthenticated {
		t.Fatal("expected management authentication to succeed")
	}
	if len(result.ContainersCleared) == 0 {
		t.Fatal("expected cleared containers to be reported")
	}
	if len(result.APDULog) == 0 {
		t.Fatal("expected APDU log to be populated")
	}
	normalizedLog := testtrace.RequireMatchFile(t, "testdata/initialize_token_apdu_trace.txt", result.APDULog)

	chuidCommand := findLogLineWithPrefix(normalizedLog, "APDU -> 00 DB 3F FF 42 5C 03 FF F3 02 ")
	if chuidCommand == "" {
		t.Fatal("expected CHUID PUT DATA command in APDU log")
	}
	commandBytes := decodeAPDULine(t, chuidCommand)
	tag, value, err := decodeSafeNetPutDataCommand(commandBytes)
	if err != nil {
		t.Fatalf("decode CHUID command: %v", err)
	}
	if tag != safeNetCHUIDAlias {
		t.Fatalf("unexpected CHUID tag: %06X", tag)
	}
	if expiry := readCHUIDExpiry(t, value); expiry != "20360401" {
		t.Fatalf("unexpected CHUID expiry: %s", expiry)
	}
}

func TestInitializeTokenRealCardRejectsUnsupportedSession(t *testing.T) {
	mockCard := emulator.NewCard()
	session := &adapters.Session{Client: piv.NewClient(mockCard), ReaderName: "SafeNet eToken Fusion"}
	_, err := NewAdapter().InitializeToken(session, adapters.InitializeTokenParams{ClearContainers: true})
	if err == nil {
		t.Fatal("expected an error from real-card initialization with mock card")
	}
	if len(mockCard.TransmittedCommands) == 0 {
		t.Fatal("expected initialization to use the provided client")
	}
}

func TestInitializeTokenIncludesObserverCommentsInResultTrace(t *testing.T) {
	initializedAt := time.Date(2026, time.April, 1, 11, 50, 43, 0, time.UTC)
	card := NewInitializationEmulatorCard()
	trace := adapters.NewTraceCollector(adapters.TraceModeAdapterOnly)

	result, err := NewAdapter().InitializeToken(
		&adapters.Session{
			Client:        piv.NewClient(card),
			Observer:      trace,
			APDULogSource: trace,
			ReaderName:    "SafeNet eToken Fusion",
		},
		adapters.InitializeTokenParams{
			ClearContainers:   true,
			ProvisionIdentity: true,
			InitializedAt:     initializedAt,
		},
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(result.APDULog) == 0 {
		t.Fatal("expected trace lines in initialization result")
	}
	if !containsLineWithPrefix(result.APDULog, "# safenet initialize-token: starting SafeNet initialization") {
		t.Fatalf("missing initialization start trace in %v", result.APDULog)
	}
	if !containsLineWithPrefix(result.APDULog, "# safenet initialize-token: completed SafeNet initialization") {
		t.Fatalf("missing initialization completion trace in %v", result.APDULog)
	}
}

func readCHUIDExpiry(t *testing.T, payload []byte) string {
	t.Helper()
	tlv, rest, err := iso7816.ParseTLV(payload)
	if err != nil {
		t.Fatalf("parse CHUID outer TLV: %v", err)
	}
	if len(rest) != 0 {
		t.Fatalf("unexpected trailing CHUID data: %X", rest)
	}
	inner, err := iso7816.ParseAllTLV(tlv.Value)
	if err != nil {
		t.Fatalf("parse CHUID inner TLVs: %v", err)
	}
	expiry := iso7816.FindTag(inner, 0x35)
	if expiry == nil {
		t.Fatal("expected CHUID expiry tag 35")
	}
	return string(expiry.Value)
}

func findLogLineWithPrefix(logLines []string, prefix string) string {
	upperPrefix := strings.ToUpper(prefix)
	for _, line := range logLines {
		if strings.HasPrefix(strings.ToUpper(line), upperPrefix) {
			return line
		}
	}
	return ""
}

func containsLineWithPrefix(logLines []string, prefix string) bool {
	return findLogLineWithPrefix(logLines, prefix) != ""
}

func decodeAPDULine(t *testing.T, line string) []byte {
	t.Helper()
	parts := strings.SplitN(line, " ", 3)
	if len(parts) != 3 {
		t.Fatalf("unexpected APDU log line: %s", line)
	}
	payload := strings.ReplaceAll(parts[2], " ", "")
	decoded, err := hex.DecodeString(payload)
	if err != nil {
		t.Fatalf("decode APDU payload %q: %v", payload, err)
	}
	return decoded
}
