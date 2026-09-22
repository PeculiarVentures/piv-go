package yubikey

import (
	"bytes"
	"crypto/x509"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/PeculiarVentures/piv-go/adapters"
	"github.com/PeculiarVentures/piv-go/internal/testtrace"
	"github.com/PeculiarVentures/piv-go/iso7816"
	"github.com/PeculiarVentures/piv-go/piv"

	"github.com/PeculiarVentures/piv-go/emulator"
)

// testAttestationDERHex is a canned self-signed P-256 attestation certificate
// (CN=YubiKey Attestation). It is fixed so APDU trace fixtures stay stable;
// the adapter returns it as raw DER without x509 verification.
const testAttestationDERHex = "3082013e3081e5a00302010202035fff01300a06082a8648ce3d040302301e311c301a06035504031313597562694b6579204174746573746174696f6e301e170d3234303130313030303030305a170d3334303130313030303030305a301e311c301a06035504031313597562694b6579204174746573746174696f6e3059301306072a8648ce3d020106082a8648ce3d0301070342000464d7a3073cccc1b552127b0ce7840a275b3ba1dbe08fa39f535c5a4a6b9b1833cb41e9bfdad3b1cc5e1ef2a65ec22827ca16469beb866ecf13be4318330c402da3123010300e0603551d0f0101ff040403020780300a06082a8648ce3d040302034800304502206d9c4f5c04a265f799c876e2e4e53ccf5cdaa69aa82d0d89f289727893117a7e022100bb95e431bfd523d4c9fe1c55380e1685b99d2ff2567b06c71e0370214448ae5a"

func testAttestationDER(t *testing.T) []byte {
	t.Helper()
	der, err := hex.DecodeString(testAttestationDERHex)
	if err != nil {
		t.Fatalf("decode canned attestation DER: %v", err)
	}
	if _, err := x509.ParseCertificate(der); err != nil {
		t.Fatalf("canned attestation DER is not a valid X.509 certificate: %v", err)
	}
	return der
}

func newAttestationSession(mock *emulator.Card) *adapters.Session {
	return &adapters.Session{
		Client:     piv.NewClient(mock),
		ReaderName: "Yubico YubiKey OTP+FIDO+CCID",
	}
}

func TestYubiKeyAdapterAttestKeyMatchesTrace(t *testing.T) {
	der := testAttestationDER(t)
	mock := emulator.NewCard()
	mock.SetSuccessResponse(0xFD, []byte{0x05, 0x07, 0x00})
	mock.SetSuccessResponse(0xF9, der)

	got, err := NewAdapter().AttestKey(newAttestationSession(mock), piv.SlotSignature)
	if err != nil {
		t.Fatalf("AttestKey() error = %v", err)
	}
	if !bytes.Equal(got, der) {
		t.Fatal("AttestKey() must return the raw DER attestation certificate")
	}

	attestCmd := findCommand(mock, 0xF9)
	if attestCmd == nil {
		t.Fatal("expected ATTEST KEY command")
	}
	if len(attestCmd) != 4 || attestCmd[0] != 0x00 || attestCmd[1] != 0xF9 || attestCmd[2] != byte(piv.SlotSignature) || attestCmd[3] != 0x00 {
		t.Fatalf("unexpected ATTEST KEY command, want 00 F9 9C 00, got %X", attestCmd)
	}
	testtrace.RequireMatchFile(t, "testdata/attest_key_apdu_trace.txt", mock.APDULog())
}

func TestYubiKeyAdapterAttestKeyValidatesSlots(t *testing.T) {
	der := testAttestationDER(t)
	valid := map[piv.Slot]bool{
		piv.SlotAuthentication: true,
		piv.SlotSignature:      true,
		piv.SlotKeyManagement:  true,
		piv.SlotCardAuth:       true,
	}
	for _, slot := range []piv.Slot{piv.SlotAuthentication, piv.SlotManagement, piv.SlotSignature, piv.SlotKeyManagement, piv.SlotCardAuth, SlotAttestation} {
		mock := emulator.NewCard()
		mock.SetSuccessResponse(0xFD, []byte{0x05, 0x07, 0x00})
		mock.SetSuccessResponse(0xF9, der)

		got, err := NewAdapter().AttestKey(newAttestationSession(mock), slot)
		if !valid[slot] {
			if err == nil || !strings.Contains(err.Error(), "attestation is not supported") {
				t.Fatalf("AttestKey(%s) expected unsupported slot error, got %v", slot, err)
			}
			if findCommand(mock, 0xF9) != nil {
				t.Fatalf("AttestKey(%s) must not send ATTEST KEY on validation failure", slot)
			}
			continue
		}
		if err != nil {
			t.Fatalf("AttestKey(%s) error = %v", slot, err)
		}
		if !bytes.Equal(got, der) {
			t.Fatalf("AttestKey(%s) must return the raw DER attestation certificate", slot)
		}
	}
}

func TestYubiKeyAdapterAttestKeyRequiresFirmware430(t *testing.T) {
	der := testAttestationDER(t)
	tests := []struct {
		version []byte
		wantErr bool
	}{
		{version: []byte{0x03, 0x09, 0x09}, wantErr: true},
		{version: []byte{0x04, 0x02, 0x09}, wantErr: true},
		{version: []byte{0x04, 0x03, 0x00}, wantErr: false},
		{version: []byte{0x04, 0x04, 0x00}, wantErr: false},
		{version: []byte{0x05, 0x07, 0x00}, wantErr: false},
	}
	for _, test := range tests {
		mock := emulator.NewCard()
		mock.SetSuccessResponse(0xFD, test.version)
		mock.SetSuccessResponse(0xF9, der)

		_, err := NewAdapter().AttestKey(newAttestationSession(mock), piv.SlotSignature)
		if test.wantErr {
			if err == nil || !strings.Contains(err.Error(), "requires 4.3.0 or later") {
				t.Fatalf("version %v expected firmware requirement error, got %v", test.version, err)
			}
			if findCommand(mock, 0xF9) != nil {
				t.Fatalf("version %v must not send ATTEST KEY below the minimum firmware", test.version)
			}
			continue
		}
		if err != nil {
			t.Fatalf("version %v unexpected error: %v", test.version, err)
		}
	}
}

func TestYubiKeyAdapterAttestationCertificateMatchesTrace(t *testing.T) {
	der := testAttestationDER(t)
	object := iso7816.EncodeTLV(0x53, append(append(iso7816.EncodeTLV(0x70, der), iso7816.EncodeTLV(0x71, []byte{0x00})...), iso7816.EncodeTLV(0xFE, nil)...))
	mock := emulator.NewCard()
	mock.SetSuccessResponse(0xCB, object)

	got, err := NewAdapter().AttestationCertificate(newAttestationSession(mock))
	if err != nil {
		t.Fatalf("AttestationCertificate() error = %v", err)
	}
	if !bytes.Equal(got, der) {
		t.Fatal("AttestationCertificate() must return the unwrapped DER certificate")
	}

	var getDataCmd []byte
	for _, command := range mock.TransmittedCommands {
		parsed, err := iso7816.ParseCommand(command)
		if err != nil {
			t.Fatalf("parse transmitted command: %v", err)
		}
		if parsed.Ins != 0xCB {
			continue
		}
		tlvs, err := iso7816.ParseAllTLV(parsed.Data)
		if err != nil {
			t.Fatalf("parse GET DATA payload: %v", err)
		}
		if tag := iso7816.FindTag(tlvs, 0x5C); tag != nil && bytes.Equal(tag.Value, iso7816.EncodeTag(yubiKeyObjectAttestation)) {
			getDataCmd = command
		}
	}
	if getDataCmd == nil {
		t.Fatal("expected GET DATA for attestation object 0x5FFF01")
	}
	testtrace.RequireMatchFile(t, "testdata/attestation_cert_apdu_trace.txt", mock.APDULog())
}

func TestYubiKeyAdapterReadCertificateServesAttestationSlot(t *testing.T) {
	der := testAttestationDER(t)
	object := iso7816.EncodeTLV(0x53, append(append(iso7816.EncodeTLV(0x70, der), iso7816.EncodeTLV(0x71, []byte{0x00})...), iso7816.EncodeTLV(0xFE, nil)...))
	mock := emulator.NewCard()
	mock.SetSuccessResponse(0xCB, object)

	got, err := NewAdapter().ReadCertificate(newAttestationSession(mock), SlotAttestation)
	if err != nil {
		t.Fatalf("ReadCertificate(attestation) error = %v", err)
	}
	if !bytes.Equal(got, der) {
		t.Fatal("ReadCertificate(attestation) must return the attestation certificate")
	}
}

func TestYubiKeyAdapterCapabilitiesIncludeAttestKey(t *testing.T) {
	report := NewAdapter().Capabilities()
	var got adapters.Capability
	for _, item := range report.Items {
		if item.ID == adapters.CapabilityAttestKey {
			got = item
			break
		}
	}
	if got.ID == "" {
		t.Fatal("expected Attest Key capability in YubiKey report")
	}
	if got.Support != adapters.CapabilityVendor {
		t.Fatalf("expected attest-key capability vendor support, got %s", got.Support)
	}

	defaultReport := adapters.ReportCapabilities(nil)
	for _, item := range defaultReport.Items {
		if item.ID == adapters.CapabilityAttestKey {
			got = item
			break
		}
	}
	if got.ID == "" {
		t.Fatal("expected Attest Key capability in default report")
	}
	if got.Support != adapters.CapabilityUnsupported {
		t.Fatalf("expected attest-key capability unsupported by default, got %s", got.Support)
	}
}

func TestAttestationVersionSupported(t *testing.T) {
	tests := []struct {
		version string
		want    bool
		wantErr bool
	}{
		{version: "5.7.0", want: true},
		{version: "4.3.0", want: true},
		{version: "4.3.1", want: true},
		{version: "4.4.0", want: true},
		{version: "4.2.9", want: false},
		{version: "3.9.9", want: false},
		{version: "bogus", wantErr: true},
		{version: "4.3", wantErr: true},
	}
	for _, test := range tests {
		got, err := attestationVersionSupported(test.version)
		if test.wantErr {
			if err == nil {
				t.Fatalf("version %q expected parse error", test.version)
			}
			continue
		}
		if err != nil {
			t.Fatalf("version %q unexpected error: %v", test.version, err)
		}
		if got != test.want {
			t.Fatalf("version %q support = %v, want %v", test.version, got, test.want)
		}
	}
}
