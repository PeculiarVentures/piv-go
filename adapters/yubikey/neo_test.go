package yubikey

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"strings"
	"testing"

	"github.com/PeculiarVentures/piv-go/adapters"
	"github.com/PeculiarVentures/piv-go/emulator"
	"github.com/PeculiarVentures/piv-go/iso7816"
	"github.com/PeculiarVentures/piv-go/piv"
)

// NEO profile: GET METADATA (0xF7) and other vendor instructions are left
// unstubbed, so the emulator answers 6D00 exactly like a YubiKey NEO
// without metadata support.

// TestNEOImportRSA2048UsesChainedShortAPDUs covers F1: an RSA-2048 IMPORT
// KEY payload (655 bytes) must go out as chained short APDUs, never as one
// extended-length command that NEO rejects with 6700.
func TestNEOImportRSA2048UsesChainedShortAPDUs(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	mock := emulator.NewCard()
	enqueueManagementAuth(mock)
	mock.SetSuccessResponse(InsImportKey, nil)
	mock.SetSuccessResponse(0xDB, nil)

	if err := NewAdapter().ImportKey(newYubiKeyPolicySession(mock), piv.SlotSignature, piv.AlgRSA2048, privateKey, 0x00, 0x00); err != nil {
		t.Fatalf("ImportKey() error = %v", err)
	}

	var importCmds [][]byte
	for _, raw := range mock.TransmittedCommands {
		if len(raw) < 2 || raw[1] != InsImportKey {
			continue
		}
		if len(raw) >= 5 && raw[4] == 0x00 {
			t.Fatalf("IMPORT KEY must use short APDUs, got extended-length header: %X", raw[:7])
		}
		importCmds = append(importCmds, raw)
	}
	if len(importCmds) < 2 {
		t.Fatalf("RSA-2048 import must use command chaining, got %d IMPORT KEY commands", len(importCmds))
	}
	for index, raw := range importCmds {
		parsed, err := iso7816.ParseCommand(raw)
		if err != nil {
			t.Fatalf("parse IMPORT KEY %d: %v", index, err)
		}
		if parsed.P1 != piv.AlgRSA2048 || parsed.P2 != byte(piv.SlotSignature) {
			t.Fatalf("unexpected IMPORT KEY header: %X", raw[:4])
		}
		if index < len(importCmds)-1 && parsed.Cla != 0x10 {
			t.Fatalf("intermediate chunk %d must use CLA 0x10, got %02X", index, parsed.Cla)
		}
	}
	final, err := iso7816.ParseCommand(importCmds[len(importCmds)-1])
	if err != nil {
		t.Fatalf("parse final IMPORT KEY: %v", err)
	}
	if final.Cla != 0x00 {
		t.Fatalf("final chunk must use CLA 0x00, got %02X", final.Cla)
	}

	// The stored public key object must round-trip through the fallback
	// read path without metadata. The RSA-2048 template PUT is itself
	// chained, so reassemble all PUT DATA payloads first.
	var putPayload []byte
	for _, raw := range mock.TransmittedCommands {
		if len(raw) < 2 || raw[1] != 0xDB {
			continue
		}
		parsed, err := iso7816.ParseCommand(raw)
		if err != nil {
			t.Fatalf("parse PUT DATA: %v", err)
		}
		putPayload = append(putPayload, parsed.Data...)
	}
	if putPayload == nil {
		t.Fatal("expected PUT DATA storing the imported public key")
	}
	tlvs, err := iso7816.ParseAllTLV(putPayload)
	if err != nil {
		t.Fatalf("parse PUT DATA payload: %v", err)
	}
	object := iso7816.FindTag(tlvs, 0x53)
	if object == nil {
		t.Fatalf("PUT DATA payload misses the 0x53 object: %X", putPayload)
	}
	stored := iso7816.EncodeTLV(0x53, object.Value)
	readBack := emulator.NewCard()
	readBack.SetSuccessResponse(0xCB, stored)
	got, err := NewAdapter().ReadPublicKey(newYubiKeyPolicySession(readBack), piv.SlotSignature)
	if err != nil {
		t.Fatalf("ReadPublicKey() without metadata error = %v", err)
	}
	gotRSA, ok := got.(*rsa.PublicKey)
	if !ok || gotRSA.N.Cmp(privateKey.PublicKey.N) != 0 {
		t.Fatalf("public key mismatch without metadata, got %T", got)
	}
}

// TestNEOReadPublicKeyFallsBackToCertificate covers F2a: without metadata,
// a slot object holding a certificate (no 7F49 template) serves the key
// from the certificate.
func TestNEOReadPublicKeyFallsBackToCertificate(t *testing.T) {
	certDER := mustCreateYubiKeyTestCertificate(t)
	certObj := iso7816.EncodeTLV(0x53, append(
		iso7816.EncodeTLV(0x70, certDER),
		append(iso7816.EncodeTLV(0x71, []byte{0x00}), iso7816.EncodeTLV(0xFE, nil)...)...,
	))
	mock := emulator.NewCard()
	mock.SetSuccessResponse(0xCB, certObj)

	trace := adapters.NewTraceCollector(adapters.TraceModeAdapterOnly)
	session := newYubiKeyPolicySession(mock)
	session.Observer = trace
	got, err := NewAdapter().ReadPublicKey(session, piv.SlotSignature)
	if err != nil {
		t.Fatalf("ReadPublicKey() with certificate error = %v", err)
	}
	gotECDSA, ok := got.(*ecdsa.PublicKey)
	if !ok {
		t.Fatalf("expected ECDSA public key from certificate, got %T", got)
	}
	want, err := parseTestCertificatePublicKey(t, certDER)
	if err != nil {
		t.Fatalf("parse test certificate: %v", err)
	}
	if gotECDSA.X.Cmp(want.X) != 0 || gotECDSA.Y.Cmp(want.Y) != 0 {
		t.Fatal("certificate public key mismatch")
	}
	found := false
	for _, line := range trace.EventLog() {
		if strings.Contains(line, "slot certificate") {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected certificate-fallback observe line, got %v", trace.EventLog())
	}
}

// TestNEOReadPublicKeyBothAbsentKeepsNotFound covers F2a/F3: without a
// public key object and without a certificate, the original read error is
// returned untouched (status preserved for the exit-5 mapping).
func TestNEOReadPublicKeyBothAbsentKeepsNotFound(t *testing.T) {
	mock := emulator.NewCard()
	mock.SetResponse(0xCB, nil, uint16(iso7816.SwFileNotFound))
	_, err := NewAdapter().ReadPublicKey(newYubiKeyPolicySession(mock), piv.SlotSignature)
	if err == nil {
		t.Fatal("expected error for absent key and certificate")
	}
	if !iso7816.IsStatus(err, iso7816.SwFileNotFound) {
		t.Fatalf("original status must survive the fallback, got %v", err)
	}
}

// TestNEODeleteKeyReportsExactUnsupportedString covers F5: MOVE KEY 6D00
// maps to the exact single-line unsupported string (with firmware version
// when readable, without it otherwise).
func TestNEODeleteKeyReportsExactUnsupportedString(t *testing.T) {
	newCard := func() *emulator.Card {
		mock := emulator.NewCard()
		enqueueManagementAuth(mock)
		mock.SetResponse(0xF6, nil, uint16(iso7816.SwInsNotSupported))
		return mock
	}
	t.Run("with version", func(t *testing.T) {
		mock := newCard()
		mock.SetSuccessResponse(0xFD, []byte{0x03, 0x04, 0x09})
		err := NewAdapter().DeleteKey(newYubiKeyPolicySession(mock), piv.SlotSignature)
		if err == nil {
			t.Fatal("expected unsupported error")
		}
		want := "delete YubiKey key from slot 9C: key deletion is not supported on firmware 3.4.9, requires 5.7.0 or later"
		if err.Error() != want {
			t.Fatalf("error = %q, want %q", err.Error(), want)
		}
	})
	t.Run("without version", func(t *testing.T) {
		mock := newCard()
		err := NewAdapter().DeleteKey(newYubiKeyPolicySession(mock), piv.SlotSignature)
		if err == nil {
			t.Fatal("expected unsupported error")
		}
		want := "delete YubiKey key from slot 9C: key deletion is not supported on this firmware, requires 5.7.0 or later"
		if err.Error() != want {
			t.Fatalf("error = %q, want %q", err.Error(), want)
		}
	})
}

// TestNEODescribeSlotEmptyAfterCertDelete covers F2b: after the shared
// slot object is cleared, inspection reports empty/empty with no stale
// key algorithm, and the degraded-view guidance is observed.
func TestNEODescribeSlotEmptyAfterCertDelete(t *testing.T) {
	cleared := emulator.NewCard()
	cleared.SetSuccessResponse(0xCB, iso7816.EncodeTLV(0x53, nil))
	trace := adapters.NewTraceCollector(adapters.TraceModeAdapterOnly)
	session := newYubiKeyPolicySession(cleared)
	session.Observer = trace
	description, err := NewAdapter().DescribeSlot(session, piv.SlotSignature)
	if err != nil {
		t.Fatalf("DescribeSlot() error = %v", err)
	}
	if description.KeyPresent {
		t.Fatalf("slot must report no key after clear, got %q", description.KeyAlgorithm)
	}
	if description.CertPresent {
		t.Fatal("slot must report no certificate after clear")
	}
	found := false
	for _, line := range trace.EventLog() {
		if strings.Contains(line, "NEO shares certificate and public-key object without GET METADATA") {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected degraded-view observe line, got %v", trace.EventLog())
	}
}

// TestNEODescribeSlotWithCertificateShowsCertOnly covers F2b: a slot
// object holding only a certificate reports key absent (no stale
// algorithm) and the certificate present.
func TestNEODescribeSlotWithCertificateShowsCertOnly(t *testing.T) {
	certDER := mustCreateYubiKeyTestCertificate(t)
	certObj := iso7816.EncodeTLV(0x53, append(
		iso7816.EncodeTLV(0x70, certDER),
		append(iso7816.EncodeTLV(0x71, []byte{0x00}), iso7816.EncodeTLV(0xFE, nil)...)...,
	))
	mock := emulator.NewCard()
	mock.SetSuccessResponse(0xCB, certObj)
	description, err := NewAdapter().DescribeSlot(newYubiKeyPolicySession(mock), piv.SlotSignature)
	if err != nil {
		t.Fatalf("DescribeSlot() error = %v", err)
	}
	if description.KeyPresent {
		t.Fatalf("slot must not report a key from the certificate object, got %q", description.KeyAlgorithm)
	}
	if !description.CertPresent {
		t.Fatal("slot must report the certificate present")
	}
}

func parseTestCertificatePublicKey(t *testing.T, certDER []byte) (*ecdsa.PublicKey, error) {
	t.Helper()
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, err
	}
	publicKey, ok := cert.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		t.Fatalf("expected ECDSA certificate key, got %T", cert.PublicKey)
	}
	return publicKey, nil
}
