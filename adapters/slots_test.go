package adapters_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"testing"
	"time"

	adaptercore "github.com/PeculiarVentures/piv-go/adapters"
	adapterslots "github.com/PeculiarVentures/piv-go/adapters/slots"
	internalutil "github.com/PeculiarVentures/piv-go/internal"
	"github.com/PeculiarVentures/piv-go/iso7816"
	"github.com/PeculiarVentures/piv-go/piv"

	"github.com/PeculiarVentures/piv-go/emulator"
)

func TestDescribeSlotUsesStandardPIVObjects(t *testing.T) {
	certificateDER := mustCreateTestCertificate(t)
	publicKeyObject := iso7816.EncodeTLV(0x53, iso7816.EncodeTLV(0x7F49, iso7816.EncodeTLV(0x86, internalutil.MustEncodeUncompressedPoint(elliptic.P256(), elliptic.P256().Params().Gx, elliptic.P256().Params().Gy))))
	certificateObject := iso7816.EncodeTLV(0x53, append(append(iso7816.EncodeTLV(0x70, certificateDER), iso7816.EncodeTLV(0x71, []byte{0x00})...), iso7816.EncodeTLV(0xFE, nil)...))

	mock := emulator.NewCard()
	mock.EnqueueResponse(0xCB, publicKeyObject, uint16(iso7816.SwSuccess))
	mock.EnqueueResponse(0xCB, certificateObject, uint16(iso7816.SwSuccess))

	runtime := adaptercore.NewRuntime(adaptercore.NewSession(piv.NewClient(mock)), nil)
	description, err := adapterslots.DescribeSlot(runtime, piv.SlotAuthentication)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !description.KeyPresent || description.KeyAlgorithm != "eccp256" {
		t.Fatalf("unexpected key description: %+v", description)
	}
	if description.PublicKey == nil {
		t.Fatalf("successful key read must expose the parsed public key: %+v", description)
	}
	if description.KeyError != nil {
		t.Fatalf("successful key read must not carry an error: %v", description.KeyError)
	}
	if !description.CertPresent || description.CertLabel != "CN=Test Slot" {
		t.Fatalf("unexpected certificate description: %+v", description)
	}
	if string(description.CertDER) != string(certificateDER) {
		t.Fatalf("CertDER = %X, want %X", description.CertDER, certificateDER)
	}
	if description.CertError != nil {
		t.Fatalf("parsed certificate must not carry an error: %v", description.CertError)
	}
}

func TestDescribeSlotDistinguishesAbsentFromUnknownKey(t *testing.T) {
	tests := []struct {
		name           string
		keySW          uint16
		wantKeyPresent bool
		wantKeyUnknown bool
	}{
		{name: "file not found is definitely absent", keySW: iso7816.SwFileNotFound, wantKeyPresent: false, wantKeyUnknown: false},
		{name: "referenced data not found is definitely absent", keySW: iso7816.SwReferencedDataNotFound, wantKeyPresent: false, wantKeyUnknown: false},
		{name: "ambiguous status is unknown", keySW: iso7816.SwUnknown, wantKeyPresent: false, wantKeyUnknown: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			mock := emulator.NewCard()
			mock.EnqueueResponse(0xCB, nil, test.keySW)
			mock.EnqueueResponse(0xCB, nil, uint16(iso7816.SwFileNotFound))

			runtime := adaptercore.NewRuntime(adaptercore.NewSession(piv.NewClient(mock)), nil)
			description, err := adapterslots.DescribeSlot(runtime, piv.SlotAuthentication)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if description.KeyPresent != test.wantKeyPresent || description.KeyUnknown != test.wantKeyUnknown {
				t.Fatalf("unexpected key state: got present=%v unknown=%v, want present=%v unknown=%v (%+v)",
					description.KeyPresent, description.KeyUnknown, test.wantKeyPresent, test.wantKeyUnknown, description)
			}
		})
	}
}

// TestDescribeSlotMalformedObjectIsUnknown covers the P2 regression where a
// 9000 response carrying a malformed object (no 0x53 tag) was treated as
// definitely absent. Only 6A82/6A88 statuses confirm absence; structure
// errors leave the state unknown.
func TestDescribeSlotMalformedObjectIsUnknown(t *testing.T) {
	mock := emulator.NewCard()
	mock.SetSuccessResponse(0xCB, []byte{0x54, 0x00})
	runtime := adaptercore.NewRuntime(adaptercore.NewSession(piv.NewClient(mock)), nil)
	description, err := adapterslots.DescribeSlot(runtime, piv.SlotAuthentication)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if description.KeyPresent {
		t.Fatalf("malformed object must not report a present key: %+v", description)
	}
	if !description.KeyUnknown {
		t.Fatalf("malformed object must be unknown, got present=%v unknown=%v", description.KeyPresent, description.KeyUnknown)
	}
}

func TestDescribeSlotExposesKeyError(t *testing.T) {
	mock := emulator.NewCard()
	mock.EnqueueResponse(0xCB, nil, uint16(iso7816.SwUnknown))
	mock.EnqueueResponse(0xCB, nil, uint16(iso7816.SwFileNotFound))

	runtime := adaptercore.NewRuntime(adaptercore.NewSession(piv.NewClient(mock)), nil)
	description, err := adapterslots.DescribeSlot(runtime, piv.SlotAuthentication)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if description.KeyPresent || !description.KeyUnknown {
		t.Fatalf("ambiguous key read must stay unknown: %+v", description)
	}
	if description.KeyError == nil {
		t.Fatalf("ambiguous key read must expose KeyError: %+v", description)
	}
	if description.PublicKey != nil {
		t.Fatalf("ambiguous key read must not expose a public key: %+v", description)
	}
}

// TestDescribeSlotCertificateUnknownOnReadError covers the review issue where
// a certificate read failure was swallowed and indistinguishable from an
// absent certificate.
func TestDescribeSlotCertificateUnknownOnReadError(t *testing.T) {
	mock := emulator.NewCard()
	mock.EnqueueResponse(0xCB, nil, uint16(iso7816.SwFileNotFound))
	mock.EnqueueResponse(0xCB, nil, uint16(iso7816.SwUnknown))

	runtime := adaptercore.NewRuntime(adaptercore.NewSession(piv.NewClient(mock)), nil)
	description, err := adapterslots.DescribeSlot(runtime, piv.SlotAuthentication)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if description.CertPresent {
		t.Fatalf("failed certificate read must not report present: %+v", description)
	}
	if !description.CertUnknown {
		t.Fatalf("ambiguous certificate read must be unknown: %+v", description)
	}
	if description.CertError == nil {
		t.Fatalf("ambiguous certificate read must expose CertError: %+v", description)
	}
	if description.KeyUnknown {
		t.Fatalf("definitive key absence must not be unknown: %+v", description)
	}
}

// TestDescribeSlotCertificateParseFailureKeepsDER verifies that a decoded but
// invalid certificate payload is reported as a parse failure with the raw
// bytes preserved, not as an absent certificate.
func TestDescribeSlotCertificateParseFailureKeepsDER(t *testing.T) {
	invalidDER := []byte{0x01, 0x02, 0x03, 0x04}
	certificateObject := iso7816.EncodeTLV(0x53, append(append(iso7816.EncodeTLV(0x70, invalidDER), iso7816.EncodeTLV(0x71, []byte{0x00})...), iso7816.EncodeTLV(0xFE, nil)...))

	mock := emulator.NewCard()
	mock.EnqueueResponse(0xCB, nil, uint16(iso7816.SwFileNotFound))
	mock.EnqueueResponse(0xCB, certificateObject, uint16(iso7816.SwSuccess))

	runtime := adaptercore.NewRuntime(adaptercore.NewSession(piv.NewClient(mock)), nil)
	description, err := adapterslots.DescribeSlot(runtime, piv.SlotAuthentication)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if description.CertPresent {
		t.Fatalf("invalid DER must not report a present certificate: %+v", description)
	}
	if description.CertUnknown {
		t.Fatalf("parse failure is not an unknown read: %+v", description)
	}
	if description.CertError == nil {
		t.Fatalf("parse failure must expose CertError: %+v", description)
	}
	if string(description.CertDER) != string(invalidDER) {
		t.Fatalf("CertDER = %X, want %X", description.CertDER, invalidDER)
	}
}

// TestDescribeSlotDefinitiveNotFoundHasNoErrors verifies that a 6A82/6A88
// status keeps the historical absent semantics without surfacing an error.
func TestDescribeSlotDefinitiveNotFoundHasNoErrors(t *testing.T) {
	for _, sw := range []uint16{iso7816.SwFileNotFound, iso7816.SwReferencedDataNotFound} {
		t.Run(fmt.Sprintf("%04X", sw), func(t *testing.T) {
			mock := emulator.NewCard()
			mock.SetResponse(0xCB, nil, sw)

			runtime := adaptercore.NewRuntime(adaptercore.NewSession(piv.NewClient(mock)), nil)
			description, err := adapterslots.DescribeSlot(runtime, piv.SlotAuthentication)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if description.KeyPresent || description.KeyUnknown || description.KeyError != nil {
				t.Fatalf("definitively absent key must have no state or error: %+v", description)
			}
			if description.CertPresent || description.CertUnknown || description.CertError != nil {
				t.Fatalf("definitively absent certificate must have no state or error: %+v", description)
			}
		})
	}
}

func mustCreateTestCertificate(t *testing.T) []byte {
	t.Helper()

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "Test Slot"},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}

	certificateDER, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	return certificateDER
}
