package safenet

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/PeculiarVentures/piv-go/adapters"
	"github.com/PeculiarVentures/piv-go/emulator"
	"github.com/PeculiarVentures/piv-go/internal/testtrace"
	"github.com/PeculiarVentures/piv-go/iso7816"
	"github.com/PeculiarVentures/piv-go/piv"
)

func TestInitializationEmulatorMissingPublicObjectStatuses(t *testing.T) {
	for _, tc := range []struct {
		tag uint
		sw  uint16
	}{
		{tag: 0x5FC105, sw: iso7816.SwWrongData},
		{tag: 0x5FC10A, sw: iso7816.SwWrongData},
		{tag: 0x5FC10B, sw: iso7816.SwWrongData},
		{tag: 0x5FC101, sw: iso7816.SwWrongData},
		{tag: 0xFFF305, sw: iso7816.SwWrongData},
		{tag: 0xFFF30A, sw: iso7816.SwWrongData},
		{tag: 0xFFF30B, sw: iso7816.SwWrongData},
		{tag: 0xFFF301, sw: iso7816.SwWrongData},
		{tag: 0xFFF302, sw: iso7816.SwWrongData},
		{tag: 0x5FC102, sw: iso7816.SwFileNotFound},
		{tag: 0x5FC107, sw: iso7816.SwFileNotFound},
		{tag: 0x5FC10D, sw: iso7816.SwFileNotFound},
		{tag: 0xFFF30D, sw: iso7816.SwFileNotFound},
		{tag: 0xFF900A, sw: iso7816.SwFileNotFound},
		{tag: 0xFF900C, sw: iso7816.SwFileNotFound},
		{tag: 0xFF900D, sw: iso7816.SwFileNotFound},
		{tag: 0xFF900E, sw: iso7816.SwFileNotFound},
	} {
		t.Run(fmt.Sprintf("%X", tc.tag), func(t *testing.T) {
			_, err := piv.NewClient(NewInitializationEmulatorCard()).GetData(tc.tag)
			if !iso7816.IsStatus(err, tc.sw) {
				t.Fatalf("raw GET DATA %X = %v, want status %04X", tc.tag, err, tc.sw)
			}
		})
	}
}

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
	wantCardAuthContainers := []string{"FF900E/7F48", "FF900E/7F49", "FFF301/53"}
	if len(result.ContainersCleared) < len(wantCardAuthContainers) ||
		!slices.Equal(result.ContainersCleared[:len(wantCardAuthContainers)], wantCardAuthContainers) {
		t.Fatalf("cleared containers = %v, want prefix %v", result.ContainersCleared, wantCardAuthContainers)
	}

	// The captured DF35 and DF34 responses omit the Card Authentication tags.
	// Check the direct writes after CHUID readback and compare the rest to the capture.
	wantCardAuthTrace := []string{
		"APDU -> 00 DB 3F FF 08 5C 03 FF 90 0E 7F 48 00 00",
		"APDU <- 90 00",
		"APDU -> 00 DB 3F FF 08 5C 03 FF 90 0E 7F 49 00 00",
		"APDU <- 90 00",
		"APDU -> 00 DB 3F FF 07 5C 03 FF F3 01 53 00 00",
		"APDU <- 90 00",
	}
	chuidReadBack := slices.IndexFunc(result.APDULog, func(line string) bool {
		return emulator.NormalizeTraceLine(line) == "APDU -> 00 CB 3F FF 05 5C 03 FF F3 02 00"
	})
	cardAuthStart := chuidReadBack + 2
	cardAuthEnd := cardAuthStart + len(wantCardAuthTrace)
	if chuidReadBack < 0 || cardAuthEnd > len(result.APDULog) {
		t.Fatal("expected CHUID readback followed by Card Authentication clearing")
	}
	if got := emulator.NormalizeTraceLines(result.APDULog[cardAuthStart:cardAuthEnd]); !slices.Equal(got, wantCardAuthTrace) {
		t.Fatalf("Card Authentication trace = %v, want %v", got, wantCardAuthTrace)
	}
	capturedLog := slices.Concat(result.APDULog[:cardAuthStart], result.APDULog[cardAuthEnd:])
	normalizedLog := testtrace.RequireMatchFile(t, "testdata/initialize_token_apdu_trace.txt", capturedLog)

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

// Identity-only provisioning is the safe recovery path when passive reads
// cannot prove whether an older SafeNet token has hidden private keys. It must
// never clear generation, mirror, or standard PIV storage.
func TestInitializeTokenIdentityOnlyPreservesExistingContainers(t *testing.T) {
	card := NewInitializationEmulatorCard()
	client := piv.NewClient(card)
	standardTag, err := piv.ObjectIDForSlot(piv.SlotAuthentication)
	if err != nil {
		t.Fatal(err)
	}
	objects := map[uint][]byte{
		safeNetGenerationTagsBySlot[piv.SlotAuthentication]: iso7816.EncodeTLV(0x7F48, []byte{0xAA, 0x55}),
		safeNetMirrorTagsBySlot[piv.SlotAuthentication]:     iso7816.EncodeTLV(0x53, iso7816.EncodeTLV(0x72, []byte{0x11})),
		standardTag: iso7816.EncodeTLV(0x53, iso7816.EncodeTLV(0x7F49, []byte{0x42})),
	}
	for tag, value := range objects {
		if err := client.PutData(tag, value); err != nil {
			t.Fatalf("seed object %06X: %v", tag, err)
		}
	}
	session := &adapters.Session{Client: client, ReaderName: "SafeNet eToken Fusion"}
	if _, err := NewAdapter().CHUID(session); !iso7816.IsStatus(err, iso7816.SwFileNotFound) {
		t.Fatalf("clean-card CHUID probe = %v, want definitive not-found", err)
	}
	cardAuth, err := NewAdapter().DescribeSlot(session, piv.SlotCardAuth)
	if err != nil || cardAuth.KeyState != adapters.SlotStateUnknown || cardAuth.CertState != adapters.SlotStateAbsent {
		t.Fatalf("clean-card card-auth probe = %+v, %v; want unobservable key and absent certificate", cardAuth, err)
	}
	initialCommands := len(card.TransmittedCommands)
	result, err := NewAdapter().InitializeToken(session, adapters.InitializeTokenParams{
		ClearContainers: false, ProvisionIdentity: true,
		InitializedAt: time.Date(2026, time.April, 1, 11, 50, 43, 0, time.UTC),
	})
	if err != nil {
		t.Fatalf("identity-only initialization: %v", err)
	}
	if !result.ManagementAuthenticated || len(result.ContainersCleared) != 0 {
		t.Fatalf("identity-only result cleared containers: %+v", result)
	}
	for _, step := range result.Steps {
		if step == "clear-containers" {
			t.Fatalf("identity-only flow ran container cleanup: %+v", result.Steps)
		}
	}
	for _, raw := range card.TransmittedCommands[initialCommands:] {
		if !isPutDataCommand(raw) {
			continue
		}
		tag, _, err := decodeSafeNetPutDataCommand(raw)
		if err != nil {
			t.Fatal(err)
		}
		if tag != safeNetCHUIDAlias {
			t.Fatalf("identity-only flow wrote object %06X, want only CHUID alias", tag)
		}
	}
	for tag, want := range objects {
		got, err := client.GetData(tag)
		if err != nil || !bytes.Equal(got, want) {
			t.Fatalf("object %06X changed: got %X, want %X, error %v", tag, got, want, err)
		}
	}
	chuid, err := NewAdapter().CHUID(session)
	if err != nil || len(chuid) == 0 {
		t.Fatalf("provisioned CHUID unavailable: %X, %v", chuid, err)
	}
	if expiry := readCHUIDExpiry(t, chuid); expiry != "20360401" {
		t.Fatalf("CHUID expiry = %q, want 20360401", expiry)
	}
}

func TestInitializeTokenStopsWhenCardAuthenticationClearFails(t *testing.T) {
	card := emulator.NewCard()
	mirrorWrite := []byte{0x00, 0xDB, 0x3F, 0xFF, 0x07, 0x5C, 0x03, 0xFF, 0xF3, 0x01, 0x53, 0x00, 0x00}
	card.RegisterPrefixHandler(mirrorWrite, func(_ *emulator.Card, _ []byte) ([]byte, error) {
		return emulator.BuildResponse(nil, iso7816.SwWrongData), nil
	})
	state := safeNetInitializationEmulator{
		generationTags: []uint{0xFF900A},
		mirrorTags:     []uint{0xFFF305},
		objects:        make(map[uint][]byte),
		challenge:      safeNetEmulatorChallenge,
	}
	state.install(card)
	session := &adapters.Session{Client: piv.NewClient(card), ReaderName: "SafeNet eToken Fusion"}

	result, err := NewAdapter().InitializeToken(session, adapters.InitializeTokenParams{ClearContainers: true})
	if !iso7816.IsStatus(err, iso7816.SwWrongData) || result != nil {
		t.Fatalf("initialization = %+v, %v, want card status 6A80", result, err)
	}
	if lastCommand := card.TransmittedCommands[len(card.TransmittedCommands)-1]; !bytes.Equal(lastCommand, mirrorWrite) {
		t.Fatalf("initialization stopped after %X, want Card Authentication mirror write %X", lastCommand, mirrorWrite)
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
