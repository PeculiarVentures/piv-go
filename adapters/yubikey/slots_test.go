package yubikey

import (
	"bytes"
	"crypto/ecdsa"
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
	object := iso7816.EncodeTLV(0x53, append(iso7816.EncodeTLV(0x7F49, iso7816.EncodeTLV(0x86, point)), iso7816.EncodeTLV(0x70, certificateDER)...))
	retiredSlot := piv.Slot(0x82)

	mock := emulator.NewCard()
	mock.SetSuccessResponse(0xCB, object)
	x, y := elliptic.P256().ScalarBaseMult([]byte{2})
	metadataPoint := internalutil.MustEncodeUncompressedPoint(elliptic.P256(), x, y)
	mock.SetSuccessResponse(0xF7, encodeSlotMetadataTLV(piv.AlgECCP256, false, metadataPoint))

	description, err := NewAdapter().DescribeSlot(newSlotDescriptionSession(mock), retiredSlot)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !description.KeyPresent || description.KeyUnknown {
		t.Fatalf("metadata key must mark the key present: %+v", description)
	}
	if description.KeyAlgorithm != "eccp256" || description.PublicKey == nil || description.PublicKeySource != adapters.PublicKeySourceMetadata {
		t.Fatalf("metadata key must expose the public key and algorithm: %+v", description)
	}
	key := description.PublicKey.(*ecdsa.PublicKey)
	if key.X.Cmp(x) != 0 || key.Y.Cmp(y) != 0 {
		t.Fatal("metadata must take precedence over both saved template and certificate")
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
	if seen != 1 {
		t.Fatalf("expected one read of 0x5FC10D, got %d", seen)
	}
}

// A readable 7F49 is public material, but a transient metadata failure
// cannot prove private-key presence. Firmware without GET METADATA retains
// the established public-object fallback instead of reporting a read error.
func TestYubiKeyDescribeSlotPublicObjectWithMetadataFailure(t *testing.T) {
	point := internalutil.MustEncodeUncompressedPoint(elliptic.P256(), elliptic.P256().Params().Gx, elliptic.P256().Params().Gy)
	stored := iso7816.EncodeTLV(0x53, iso7816.EncodeTLV(0x7F49, iso7816.EncodeTLV(0x86, point)))
	for _, tc := range []struct {
		name       string
		metadataSW uint16
		wantState  adapters.SlotState
		wantError  bool
		wantReason adapters.KeyUnknownReason
	}{
		{"transient security failure", uint16(iso7816.SwSecurityNotSatisfied), adapters.SlotStateError, true, ""},
		{"NEO unsupported metadata", uint16(iso7816.SwInsNotSupported), adapters.SlotStateUnknown, false, adapters.KeyUnknownReasonUnobservable},
		{"unsupported class", uint16(iso7816.SwClaNotSupported), adapters.SlotStateUnknown, false, adapters.KeyUnknownReasonUnobservable},
	} {
		t.Run(tc.name, func(t *testing.T) {
			card := emulator.NewCard()
			card.SetSuccessResponse(0xCB, stored)
			card.SetResponse(0xF7, nil, tc.metadataSW)
			d, err := NewAdapter().DescribeSlot(newSlotDescriptionSession(card), piv.SlotAuthentication)
			if err != nil {
				t.Fatal(err)
			}
			if d.KeyState != tc.wantState || (d.KeyError != nil) != tc.wantError || d.KeyUnknownReason != tc.wantReason || d.PublicKey == nil || d.PublicKeySource != adapters.PublicKeySourceStoredTemplate || d.CertState != adapters.SlotStateAbsent {
				t.Fatalf("slot description = %+v, want key=%s error=%v and retained public object", d, tc.wantState, tc.wantError)
			}
			if tc.wantError && !iso7816.IsStatus(d.KeyError, tc.metadataSW) {
				t.Fatalf("KeyError = %v, want metadata status %04X", d.KeyError, tc.metadataSW)
			}
			if len(card.TransmittedCommands) != 2 {
				t.Fatalf("APDU count = %d, want one GET DATA and one GET METADATA", len(card.TransmittedCommands))
			}
		})
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
	if !description.KeyUnknown || description.KeyUnknownReason != adapters.KeyUnknownReasonUnobservable || description.KeyError != nil {
		t.Fatalf("metadata-less token with an empty view must be unobservable without a read error: %+v", description)
	}
	if description.Metadata != nil {
		t.Fatalf("unavailable metadata must not be exposed: %+v", description)
	}
}

// TestYubiKeyAdapterDescribeSlotReadsEachSourceOnce is the one-pass invariant
// from review issue #6: a single DescribeSlot call performs exactly one GET
// METADATA and one shared key/certificate object read.
func TestYubiKeyAdapterDescribeSlotReadsEachSourceOnce(t *testing.T) {
	point := internalutil.MustEncodeUncompressedPoint(elliptic.P256(), elliptic.P256().Params().Gx, elliptic.P256().Params().Gy)
	publicKeyObject := iso7816.EncodeTLV(0x53, iso7816.EncodeTLV(0x7F49, iso7816.EncodeTLV(0x86, point)))

	mock := emulator.NewCard()
	mock.SetSuccessResponse(0xCB, publicKeyObject)
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
	if insCounts[0xCB] != 1 {
		t.Fatalf("expected exactly one GET DATA (0xCB) read, got %d: % X", insCounts[0xCB], mock.TransmittedCommands)
	}
}

func TestYubiKeyDescribeSlotMetadataAbsenceOverridesStaleStoredKey(t *testing.T) {
	point := internalutil.MustEncodeUncompressedPoint(elliptic.P256(), elliptic.P256().Params().Gx, elliptic.P256().Params().Gy)
	stored := iso7816.EncodeTLV(0x53, iso7816.EncodeTLV(0x7F49, iso7816.EncodeTLV(0x86, point)))
	card := emulator.NewCard()
	card.SetSuccessResponse(0xCB, stored)
	card.SetResponse(0xF7, nil, uint16(iso7816.SwReferencedDataNotFound))
	d, err := NewAdapter().DescribeSlot(newSlotDescriptionSession(card), piv.SlotSignature)
	if err != nil {
		t.Fatal(err)
	}
	if d.KeyState != adapters.SlotStateAbsent || d.KeyPresent || d.PublicKey == nil || d.PublicKeySource != adapters.PublicKeySourceStoredTemplate || d.KeyUnknownReason != "" {
		t.Fatalf("metadata absence must win over stale public storage: %+v", d)
	}
}

func TestYubiKeyDescribeSlotMetadataWithoutPublicKeyPreservesCertificateKey(t *testing.T) {
	card := emulator.NewCard()
	card.SetSuccessResponse(0xCB, iso7816.EncodeTLV(0x53, iso7816.EncodeTLV(0x70, mustCreateYubiKeyTestCertificate(t))))
	card.SetSuccessResponse(0xF7, encodeSlotMetadataTLV(piv.AlgECCP256, false, nil))
	d, err := NewAdapter().DescribeSlot(newSlotDescriptionSession(card), piv.SlotAuthentication)
	if err != nil {
		t.Fatal(err)
	}
	if d.KeyState != adapters.SlotStatePresent || d.CertState != adapters.SlotStatePresent || d.PublicKey == nil || d.PublicKeySource != adapters.PublicKeySourceCertificate {
		t.Fatalf("successful metadata must prove key while preserving certificate public key: %+v", d)
	}
}

func TestYubiKeyDescribeSlotCertificateOnlyWithoutMetadataKeepsPublicKey(t *testing.T) {
	card := emulator.NewCard()
	card.SetSuccessResponse(0xCB, iso7816.EncodeTLV(0x53, iso7816.EncodeTLV(0x70, mustCreateYubiKeyTestCertificate(t))))
	card.SetResponse(0xF7, nil, uint16(iso7816.SwInsNotSupported))
	d, err := NewAdapter().DescribeSlot(newSlotDescriptionSession(card), piv.SlotAuthentication)
	if err != nil {
		t.Fatal(err)
	}
	if d.KeyState != adapters.SlotStateUnknown || d.KeyUnknownReason != adapters.KeyUnknownReasonUnobservable || d.CertState != adapters.SlotStatePresent || d.PublicKey == nil || d.PublicKeySource != adapters.PublicKeySourceCertificate {
		t.Fatalf("certificate provides public key but not private-key proof: %+v", d)
	}
}

func TestYubiKeyDescribeSlotMalformedObjectStaysErrorWithoutMetadata(t *testing.T) {
	card := emulator.NewCard()
	card.SetSuccessResponse(0xCB, []byte{0x54, 0x00})
	card.SetResponse(0xF7, nil, uint16(iso7816.SwInsNotSupported))
	d, err := NewAdapter().DescribeSlot(newSlotDescriptionSession(card), piv.SlotAuthentication)
	if err != nil {
		t.Fatal(err)
	}
	if d.KeyState != adapters.SlotStateError || d.CertState != adapters.SlotStateError || d.KeyError == nil || d.CertError == nil || d.KeyUnknownReason != "" {
		t.Fatalf("malformed object must remain an error: %+v", d)
	}
}

func TestYubiKeyDescribeSlotMalformedMetadataKeepsCertificate(t *testing.T) {
	card := emulator.NewCard()
	card.SetSuccessResponse(0xCB, iso7816.EncodeTLV(0x53, iso7816.EncodeTLV(0x70, mustCreateYubiKeyTestCertificate(t))))
	card.SetSuccessResponse(0xF7, []byte{0x01})
	d, err := NewAdapter().DescribeSlot(newSlotDescriptionSession(card), piv.SlotAuthentication)
	if err != nil {
		t.Fatal(err)
	}
	if d.KeyState != adapters.SlotStateError || d.KeyError == nil || d.KeyUnknownReason != "" || d.CertState != adapters.SlotStatePresent || d.PublicKeySource != adapters.PublicKeySourceCertificate || d.Metadata != nil {
		t.Fatalf("malformed metadata must remain a key error beside certificate observation: %+v", d)
	}
}
