package app

import (
	"bytes"
	"crypto/elliptic"
	"strings"
	"testing"

	"github.com/PeculiarVentures/piv-go/adapters"
	"github.com/PeculiarVentures/piv-go/adapters/safenet"
	"github.com/PeculiarVentures/piv-go/adapters/yubikey"
	"github.com/PeculiarVentures/piv-go/emulator"
	"github.com/PeculiarVentures/piv-go/iso7816"
	"github.com/PeculiarVentures/piv-go/piv"
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

// Initialization describes observable profile content, separately from
// private-key certainty. A saved public template counts as profile content;
// a successful but unobservable read without public artifacts does not.
func TestDeriveTokenStateUsesObservablePublicProfileContent(t *testing.T) {
	point := elliptic.Marshal(elliptic.P256(), elliptic.P256().Params().Gx, elliptic.P256().Params().Gy)
	object := iso7816.EncodeTLV(0x53, iso7816.EncodeTLV(0x7F49, iso7816.EncodeTLV(0x86, point)))
	objectID, err := piv.ObjectIDForSlot(piv.SlotAuthentication)
	if err != nil {
		t.Fatal(err)
	}
	query := iso7816.EncodeTLV(0x5C, iso7816.EncodeTag(objectID))
	for _, adapter := range []adapters.Adapter{yubikey.NewAdapter(), safenet.NewAdapter()} {
		for _, content := range []struct {
			name    string
			present bool
		}{
			{"saved template", true},
			{"no public artifacts", false},
		} {
			t.Run(adapter.Name()+"/"+content.name, func(t *testing.T) {
				card := emulator.NewCard()
				card.SetSuccessResponse(0xA4, nil)
				card.RegisterINSHandler(0xCB, func(_ *emulator.Card, raw []byte) ([]byte, error) {
					command, err := iso7816.ParseCommand(raw)
					if err != nil {
						return nil, err
					}
					if content.present && bytes.Equal(command.Data, query) {
						return emulator.BuildSuccessResponse(object), nil
					}
					return emulator.BuildResponse(nil, iso7816.SwFileNotFound), nil
				})
				runtime := adapters.NewRuntime(adapters.NewSession(piv.NewClient(card)), adapter)
				slot, err := describeSlot(runtime, piv.SlotAuthentication)
				if err != nil {
					t.Fatal(err)
				}
				if slot.KeyPresent || !slot.KeyUnknown || slot.CertPresent {
					t.Fatalf("passive public profile must not prove private key: %+v", slot)
				}
				wantSource := adapters.PublicKeySource("")
				if content.present {
					wantSource = adapters.PublicKeySourceStoredTemplate
				}
				if slot.PublicKeySource != wantSource {
					t.Fatalf("public source = %q, want %q", slot.PublicKeySource, wantSource)
				}
				state := deriveTokenState(runtime, []SlotView{slot}, adapters.ReportCapabilities(adapter))
				if (state == "initialized") != content.present {
					t.Fatalf("token state = %q for public content present=%v", state, content.present)
				}
			})
		}
	}
}
