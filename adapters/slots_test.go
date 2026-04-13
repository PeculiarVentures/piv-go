package adapters_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
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
	if !description.CertPresent || description.CertLabel != "CN=Test Slot" {
		t.Fatalf("unexpected certificate description: %+v", description)
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
