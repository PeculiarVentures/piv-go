package yubikey

import (
	"bytes"
	"strings"
	"testing"

	"github.com/PeculiarVentures/piv-go/adapters"
	"github.com/PeculiarVentures/piv-go/internal/testtrace"
	"github.com/PeculiarVentures/piv-go/iso7816"
	"github.com/PeculiarVentures/piv-go/piv"

	"github.com/PeculiarVentures/piv-go/emulator"
)

func encodeYubiKey6SlotMetadata(t *testing.T, algorithm byte, publicKeyInner []byte) []byte {
	t.Helper()
	data := iso7816.EncodeTLV(yubiKeyMetadataTagAlgorithm, []byte{algorithm})
	data = append(data, iso7816.EncodeTLV(yubiKeyMetadataTagPolicy, []byte{0x02, 0x01})...)
	data = append(data, iso7816.EncodeTLV(yubiKeyMetadataTagOrigin, []byte{yubiKeyOriginGenerated})...)
	data = append(data, iso7816.EncodeTLV(yubiKeyMetadataTagPublicKey, publicKeyInner)...)
	return data
}

func TestYubiKeyAdapterReadPublicKeyX25519Opaque(t *testing.T) {
	raw := bytes.Repeat([]byte{0xA5}, 32)
	mock := emulator.NewCard()
	mock.SetSuccessResponse(0xF7, encodeYubiKey6SlotMetadata(t, piv.AlgX25519, iso7816.EncodeTLV(0x86, raw)))

	got, err := NewAdapter().ReadPublicKey(newAttestationSession(mock), piv.SlotSignature)
	if err != nil {
		t.Fatalf("ReadPublicKey() error = %v", err)
	}
	opaque, ok := got.(*piv.OpaquePublicKey)
	if !ok {
		t.Fatalf("expected *piv.OpaquePublicKey, got %T", got)
	}
	if opaque.Algorithm != piv.AlgX25519 {
		t.Fatalf("opaque algorithm = 0x%02X, want 0x%02X", opaque.Algorithm, piv.AlgX25519)
	}
	if !bytes.Equal(opaque.Raw, raw) {
		t.Fatal("opaque raw bytes must round-trip verbatim")
	}
	testtrace.RequireMatchFile(t, "testdata/slot_metadata_x25519_apdu_trace.txt", mock.APDULog())
}

func TestYubiKeyAdapterReadPublicKeyMLDSA44Opaque(t *testing.T) {
	raw := bytes.Repeat([]byte{0x5A}, 1312)
	mock := emulator.NewCard()
	mock.SetSuccessResponse(0xF7, encodeYubiKey6SlotMetadata(t, piv.AlgMLDSA44, iso7816.EncodeTLV(0x87, raw)))

	got, err := NewAdapter().ReadPublicKey(newAttestationSession(mock), piv.SlotSignature)
	if err != nil {
		t.Fatalf("ReadPublicKey() error = %v", err)
	}
	opaque, ok := got.(*piv.OpaquePublicKey)
	if !ok {
		t.Fatalf("expected *piv.OpaquePublicKey, got %T", got)
	}
	if opaque.Algorithm != piv.AlgMLDSA44 {
		t.Fatalf("opaque algorithm = 0x%02X, want 0x%02X", opaque.Algorithm, piv.AlgMLDSA44)
	}
	if !bytes.Equal(opaque.Raw, raw) {
		t.Fatal("opaque raw bytes must round-trip verbatim")
	}
	testtrace.RequireMatchFile(t, "testdata/slot_metadata_mldsa44_apdu_trace.txt", mock.APDULog())
}

func TestYubiKeyAdapterReadSlotMetadataBrokenTLVFails(t *testing.T) {
	mock := emulator.NewCard()
	mock.SetSuccessResponse(0xF7, []byte{0x01})

	if _, err := readSlotMetadata(piv.NewClient(mock), piv.SlotSignature); err == nil {
		t.Fatal("expected error for broken slot metadata TLV, got nil")
	}
}

func TestYubiKeyAdapterVersionReturnsPreviewRaw(t *testing.T) {
	mock := emulator.NewCard()
	mock.SetSuccessResponse(0xFD, []byte{0x00, 0x00, 0x01})

	version, err := NewAdapter().Version(newAttestationSession(mock))
	if err != nil {
		t.Fatalf("Version() error = %v", err)
	}
	if version != "0.0.1" {
		t.Fatalf("preview version must be returned raw, got %q", version)
	}
}

func TestYubiKeyAdapterGenerateImportGapWithoutAPDU(t *testing.T) {
	// ML-KEM generates on-card; only the ML-DSA import gap and the
	// ML-KEM-512 import gap (no standard library encapsulation key
	// derivation for the stored object) reject without an APDU.
	for _, algorithm := range []byte{piv.AlgMLDSA44, piv.AlgMLDSA65, piv.AlgMLDSA87} {
		mock := emulator.NewCard()
		if err := NewAdapter().ImportKey(newYubiKeyPolicySession(mock), piv.SlotSignature, algorithm, "not-a-key", 0x00, 0x00); err == nil || !strings.Contains(err.Error(), "not supported") {
			t.Fatalf("import 0x%02X: expected not-supported error, got %v", algorithm, err)
		}
		if len(mock.TransmittedCommands) != 0 {
			t.Fatalf("import 0x%02X: no APDU must be sent on rejection, got %d commands", algorithm, len(mock.TransmittedCommands))
		}
	}
	{
		mock := emulator.NewCard()
		if err := NewAdapter().ImportKey(newYubiKeyPolicySession(mock), piv.SlotSignature, piv.AlgMLKEM512, bytes.Repeat([]byte{0xD5}, piv.MLKEMSeedLength), 0x00, 0x00); err == nil || !strings.Contains(err.Error(), "not supported") {
			t.Fatalf("import ML-KEM-512: expected not-supported error, got %v", err)
		}
		if len(mock.TransmittedCommands) != 0 {
			t.Fatalf("import ML-KEM-512: no APDU must be sent on rejection, got %d commands", len(mock.TransmittedCommands))
		}
	}
}

func TestYubiKeyAdapterKeyMetadataRecognizesYubiKey6(t *testing.T) {
	raw := bytes.Repeat([]byte{0xA5}, 32)
	mock := emulator.NewCard()
	mock.SetSuccessResponse(0xF7, encodeYubiKey6SlotMetadata(t, piv.AlgX25519, iso7816.EncodeTLV(0x86, raw)))

	metadata, err := NewAdapter().KeyMetadata(newAttestationSession(mock), piv.SlotSignature)
	if err != nil {
		t.Fatalf("KeyMetadata() error = %v", err)
	}
	if metadata.Algorithm != adapters.KeyAlgorithmX25519 {
		t.Fatalf("KeyMetadata() algorithm = %q, want %q", metadata.Algorithm, adapters.KeyAlgorithmX25519)
	}
}
