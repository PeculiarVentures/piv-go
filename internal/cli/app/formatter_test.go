package app

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"strings"
	"testing"

	"github.com/PeculiarVentures/piv-go/adapters"
	"github.com/PeculiarVentures/piv-go/adapters/yubikey"
	"github.com/PeculiarVentures/piv-go/emulator"
	"github.com/PeculiarVentures/piv-go/iso7816"
	"github.com/PeculiarVentures/piv-go/piv"
)

// TestRenderSlotTableShowsUnknown covers the P2 regression where the text
// formatter rendered an unknown slot state as "empty". Unknown must render
// as "unknown" so operators do not mistake it for a confirmed empty slot.
func TestRenderSlotTableShowsUnknown(t *testing.T) {
	var unknown bytes.Buffer
	(&Formatter{}).renderSlotTable(&unknown, []SlotView{{
		Name: "9c", Hex: "9c",
		KeyPresent: false, KeyUnknown: true, KeyAlgorithm: "-",
		CertPresent: false, CertLabel: "-",
	}})
	if !strings.Contains(unknown.String(), "unknown") {
		t.Fatalf("unknown slot state must render as unknown, got %q", unknown.String())
	}
	for _, line := range strings.Split(unknown.String(), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 || fields[0] != "9c" {
			continue
		}
		if len(fields) < 4 || fields[2] != "unknown" {
			t.Fatalf("key column must render as unknown, got %q", line)
		}
	}

	var absent bytes.Buffer
	(&Formatter{}).renderSlotTable(&absent, []SlotView{{
		Name: "9c", Hex: "9c",
		KeyPresent: false, KeyUnknown: false, KeyAlgorithm: "-",
		CertPresent: false, CertLabel: "-",
	}})
	if !strings.Contains(absent.String(), "empty") {
		t.Fatalf("definitely-absent slot must still render as empty, got %q", absent.String())
	}
}

func TestSlotViewPublicKeySourceInJSONAndText(t *testing.T) {
	card := emulator.NewCard()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	card.SetSuccessResponse(0xCB, iso7816.EncodeTLV(0x53, iso7816.EncodeTLV(0x70, mustNEOSelfSignedCert(t, key, &key.PublicKey, "Inspection"))))
	slot, err := describeSlot(adapters.NewRuntime(adapters.NewSession(piv.NewClient(card)), yubikey.NewAdapter()), piv.SlotAuthentication)
	if err != nil {
		t.Fatal(err)
	}
	if slot.PublicKeySource != adapters.PublicKeySourceCertificate || slot.KeyPresent || !slot.KeyUnknown || slot.KeyAlgorithm != "eccp256" {
		t.Fatalf("CLI mapping lost public provenance or private uncertainty: %+v", slot)
	}
	data, err := json.Marshal(slot)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(data, []byte(`"public_key_source":"certificate"`)) || !bytes.Contains(data, []byte(`"key_unknown":true`)) {
		t.Fatalf("JSON lost public provenance or private uncertainty: %s", data)
	}
	var text bytes.Buffer
	(&Formatter{}).renderSlotTable(&text, []SlotView{slot})
	if !strings.Contains(text.String(), "PUBLIC KEY") || !strings.Contains(text.String(), "SOURCE") || !strings.Contains(text.String(), "unknown") || !strings.Contains(text.String(), "eccp256") || !strings.Contains(text.String(), "certificate") {
		t.Fatalf("text must show private state and public source independently: %q", text.String())
	}
	data, err = json.Marshal(SlotView{})
	if err != nil || bytes.Contains(data, []byte("public_key_source")) {
		t.Fatalf("missing public key must omit source: %s err=%v", data, err)
	}
}
