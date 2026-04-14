package app

import (
	"bytes"
	"strings"
	"testing"

	"github.com/PeculiarVentures/piv-go/adapters"
)

type fakeAdapter struct {
	name string
}

func (a fakeAdapter) Name() string {
	return a.name
}

func (a fakeAdapter) MatchReader(readerName string) bool {
	return false
}

func TestFormatSerial_YubiKey(t *testing.T) {
	adapter := fakeAdapter{name: "yubikey"}
	serial := []byte{0x01, 0x98, 0x24, 0x66}
	got := formatSerial(adapter, serial)
	want := "26748006"
	if got != want {
		t.Fatalf("unexpected serial formatting for yubikey: got %q, want %q", got, want)
	}
}

func TestFormatSerial_SafeNet(t *testing.T) {
	adapter := fakeAdapter{name: "safenet"}
	serial := []byte("548TPK73")
	got := formatSerial(adapter, serial)
	want := "548TPK73"
	if got != want {
		t.Fatalf("unexpected serial formatting for safenet: got %q, want %q", got, want)
	}
}

func TestSanitizeDisplayBytes_RemovesInvalidUtf8(t *testing.T) {
	got := sanitizeDisplayBytes([]byte{'A', 0x00, 'B', 0xFF, 'C'})
	want := "ABC"
	if got != want {
		t.Fatalf("unexpected sanitized display bytes: got %q, want %q", got, want)
	}
}

func TestRenderInfo_ShowsChuid(t *testing.T) {
	result := InfoResult{
		Label:  "IDPrime PIV #548TPK73",
		Serial: "548TPK73",
		CHUID: adapters.CHUID{
			FASCN:      "AABBCCDD",
			GUID:       "11223344556677889900AABBCCDDEEFF",
			Expiration: "20360401",
		},
	}
	buf := bytes.Buffer{}
	(&Formatter{}).renderInfo(&buf, TargetSummary{Reader: "SafeNet eToken Fusion", Adapter: "safenet"}, result)
	got := buf.String()
	if !strings.Contains(got, "FASC-N: AABBCCDD") || !strings.Contains(got, "GUID: 11223344556677889900AABBCCDDEEFF") || !strings.Contains(got, "Expiration: 20360401") {
		t.Fatalf("expected CHUID components in output, got %q", got)
	}
}

func TestRenderInfo_ShowsMGMRetriesUnknown(t *testing.T) {
	result := InfoResult{
		Credentials: CredentialsView{
			MGM: CredentialStatus{Supported: true, RetriesRemaining: adapters.UnknownRetries},
		},
	}
	buf := bytes.Buffer{}
	(&Formatter{}).renderInfo(&buf, TargetSummary{Reader: "SafeNet eToken Fusion", Adapter: "safenet"}, result)
	got := buf.String()
	if !strings.Contains(got, "MGM retries remaining: unknown") {
		t.Fatalf("expected MGM unknown retries output, got %q", got)
	}
}

func TestRenderInfo_ShowsMGMRetriesUnlimited(t *testing.T) {
	result := InfoResult{
		Credentials: CredentialsView{
			MGM: CredentialStatus{Supported: true, RetriesRemaining: adapters.UnlimitedRetries},
		},
	}
	buf := bytes.Buffer{}
	(&Formatter{}).renderInfo(&buf, TargetSummary{Reader: "Yubico YubiKey OTP+FIDO+CCID", Adapter: "yubikey"}, result)
	got := buf.String()
	if !strings.Contains(got, "MGM retries remaining: unlimited") {
		t.Fatalf("expected MGM unlimited retries output, got %q", got)
	}
}
