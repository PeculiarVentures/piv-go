package adapters

import (
	"encoding/hex"
	"strings"
	"testing"

	"github.com/PeculiarVentures/piv-go/iso7816"
)

func TestParseCHUIDFormatsGUIDAndExpiration(t *testing.T) {
	fascn := []byte{0x12, 0x34, 0x56, 0x78}
	guid := []byte{0xB0, 0x58, 0x76, 0x14, 0xBD, 0x20, 0xBD, 0x4A, 0x65, 0xE1, 0xC8, 0x35, 0xD9, 0xB4, 0x19, 0x95}
	expiration := []byte("20360401")
	payload := append(iso7816.EncodeTLV(0x30, fascn), iso7816.EncodeTLV(0x34, guid)...)
	payload = append(payload, iso7816.EncodeTLV(0x35, expiration)...)
	data := iso7816.EncodeTLV(0x53, payload)

	result, err := parseCHUID(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if want := strings.ToUpper(hex.EncodeToString(fascn)); result.FASCN != want {
		t.Fatalf("unexpected FASCN: got %q want %q", result.FASCN, want)
	}
	if want := "B0587614-BD20-BD4A-65E1-C835D9B41995"; result.GUID != want {
		t.Fatalf("unexpected GUID: got %q want %q", result.GUID, want)
	}
	if result.Expiration != "2036-04-01" {
		t.Fatalf("unexpected expiration: got %q want %q", result.Expiration, "2036-04-01")
	}
}

func TestParseCHUIDPreservesNonCanonicalGUID(t *testing.T) {
	guid := []byte{0x01, 0x02, 0x03}
	data := iso7816.EncodeTLV(0x53, iso7816.EncodeTLV(0x34, guid))

	result, err := parseCHUID(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.GUID != strings.ToUpper(hex.EncodeToString(guid)) {
		t.Fatalf("unexpected GUID fallback: got %q want %q", result.GUID, strings.ToUpper(hex.EncodeToString(guid)))
	}
}
