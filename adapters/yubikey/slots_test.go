package yubikey

import (
	"bytes"
	"crypto/elliptic"
	"testing"

	"github.com/PeculiarVentures/piv-go/adapters"
	internalutil "github.com/PeculiarVentures/piv-go/internal"
	"github.com/PeculiarVentures/piv-go/iso7816"
	"github.com/PeculiarVentures/piv-go/piv"

	"github.com/PeculiarVentures/piv-go/emulator"
)

func newSlotDescriptionSession(mock *emulator.Card) *adapters.Session {
	return &adapters.Session{Client: piv.NewClient(mock), ReaderName: "Yubico YubiKey OTP+FIDO+CCID"}
}

// TestYubiKeyAdapterDescribeSlotRetiredSlot covers a retired key management
// slot (0x82): the standard description reads the 0x5FC10D object and the
// YubiKey metadata marks key presence, exposes the public key and supplies
// normalized metadata.
func TestYubiKeyAdapterDescribeSlotRetiredSlot(t *testing.T) {
	certificateDER := mustCreateYubiKeyTestCertificate(t)
	point := internalutil.MustEncodeUncompressedPoint(elliptic.P256(), elliptic.P256().Params().Gx, elliptic.P256().Params().Gy)
	publicKeyObject := iso7816.EncodeTLV(0x53, iso7816.EncodeTLV(0x7F49, iso7816.EncodeTLV(0x86, point)))
	certificateObject := iso7816.EncodeTLV(0x53, append(append(iso7816.EncodeTLV(0x70, certificateDER), iso7816.EncodeTLV(0x71, []byte{0x00})...), iso7816.EncodeTLV(0xFE, nil)...))
	retiredSlot := piv.Slot(0x82)

	mock := emulator.NewCard()
	mock.EnqueueResponse(0xCB, publicKeyObject, uint16(iso7816.SwSuccess))
	mock.EnqueueResponse(0xCB, certificateObject, uint16(iso7816.SwSuccess))
	mock.SetSuccessResponse(0xF7, encodeSlotMetadataTLV(piv.AlgECCP256, false, point))

	description, err := NewAdapter().DescribeSlot(newSlotDescriptionSession(mock), retiredSlot)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !description.KeyPresent || description.KeyUnknown {
		t.Fatalf("metadata key must mark the key present: %+v", description)
	}
	if description.KeyAlgorithm != "eccp256" || description.PublicKey == nil {
		t.Fatalf("metadata key must expose the public key and algorithm: %+v", description)
	}
	if description.KeyError != nil {
		t.Fatalf("present key must not carry KeyError: %v", description.KeyError)
	}
	if !description.CertPresent || description.CertLabel != "CN=YubiKey Slot" {
		t.Fatalf("stored certificate must be reported present: %+v", description)
	}
	if !bytes.Equal(description.CertDER, certificateDER) {
		t.Fatalf("CertDER = %X, want %X", description.CertDER, certificateDER)
	}
	if description.CertError != nil {
		t.Fatalf("parsed certificate must not carry CertError: %v", description.CertError)
	}
	if description.Metadata == nil {
		t.Fatalf("available metadata must be exposed: %+v", description)
	}
	if description.Metadata.Slot != retiredSlot || description.Metadata.Algorithm != adapters.KeyAlgorithmECCP256 {
		t.Fatalf("unexpected normalized metadata: %+v", *description.Metadata)
	}

	// Both standard reads must target the retired object 0x5FC10D, not a
	// tag-0 fallback. The object identifier is the 3-byte BER-TLV tag
	// 5F C1 0D, so the 5C TLV carries length 0x03.
	wantObject := []byte{0x5C, 0x03, 0x5F, 0xC1, 0x0D}
	seen := 0
	for _, raw := range mock.TransmittedCommands {
		if len(raw) < 2 || raw[1] != 0xCB {
			continue
		}
		parsed, err := iso7816.ParseCommand(raw)
		if err != nil {
			t.Fatalf("parse GET DATA command: %v", err)
		}
		if !bytes.HasPrefix(parsed.Data, wantObject) {
			t.Fatalf("GET DATA payload = % X, want prefix % X", parsed.Data, wantObject)
		}
		seen++
	}
	if seen != 2 {
		t.Fatalf("expected one key and one certificate read of 0x5FC10D, got %d", seen)
	}
}

// TestYubiKeyAdapterDescribeSlotMetadataUnavailableKeepsUnknown covers a
// metadata-less token such as the YubiKey NEO (GET METADATA 6D00) with an
// empty standard view: the key state must stay unknown.
func TestYubiKeyAdapterDescribeSlotMetadataUnavailableKeepsUnknown(t *testing.T) {
	mock := emulator.NewCard()
	mock.SetResponse(0xF7, nil, uint16(iso7816.SwInsNotSupported))
	mock.SetResponse(0xCB, nil, uint16(iso7816.SwFileNotFound))

	description, err := NewAdapter().DescribeSlot(newSlotDescriptionSession(mock), piv.SlotAuthentication)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if description.KeyPresent {
		t.Fatalf("empty slot must not report a key: %+v", description)
	}
	if !description.KeyUnknown {
		t.Fatalf("metadata-less token with an empty view must stay unknown: %+v", description)
	}
	if description.Metadata != nil {
		t.Fatalf("unavailable metadata must not be exposed: %+v", description)
	}
}

// TestYubiKeyAdapterDescribeSlotReadsEachSourceOnce is the one-pass invariant
// from review issue #6: a single DescribeSlot call performs exactly one GET
// METADATA, one key object read and one certificate object read. The
// certificate object read used to be duplicated after the metadata merge.
func TestYubiKeyAdapterDescribeSlotReadsEachSourceOnce(t *testing.T) {
	point := internalutil.MustEncodeUncompressedPoint(elliptic.P256(), elliptic.P256().Params().Gx, elliptic.P256().Params().Gy)
	publicKeyObject := iso7816.EncodeTLV(0x53, iso7816.EncodeTLV(0x7F49, iso7816.EncodeTLV(0x86, point)))

	mock := emulator.NewCard()
	mock.EnqueueResponse(0xCB, publicKeyObject, uint16(iso7816.SwSuccess))
	mock.EnqueueResponse(0xCB, nil, uint16(iso7816.SwFileNotFound))
	mock.SetSuccessResponse(0xF7, encodeSlotMetadataTLV(piv.AlgECCP256, false, point))

	if _, err := NewAdapter().DescribeSlot(newSlotDescriptionSession(mock), piv.SlotSignature); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	insCounts := map[byte]int{}
	for _, raw := range mock.TransmittedCommands {
		if len(raw) > 1 {
			insCounts[raw[1]]++
		}
	}
	if insCounts[0xF7] != 1 {
		t.Fatalf("expected exactly one GET METADATA (0xF7), got %d: % X", insCounts[0xF7], mock.TransmittedCommands)
	}
	// One GET DATA for the public key and one for the certificate, both
	// against the same slot object. A third GET DATA would be the removed
	// duplicate certificate read.
	if insCounts[0xCB] != 2 {
		t.Fatalf("expected exactly two GET DATA (0xCB) reads, got %d: % X", insCounts[0xCB], mock.TransmittedCommands)
	}
}
