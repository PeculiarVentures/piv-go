package piv

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"testing"

	internalutil "github.com/PeculiarVentures/piv-go/internal"
	"github.com/PeculiarVentures/piv-go/iso7816"

	"github.com/PeculiarVentures/piv-go/emulator"
)

func TestClient_ReadCertificate_Success(t *testing.T) {
	mock := emulator.NewCard()
	certBytes := []byte{0x30, 0x82, 0x01, 0x00}
	inner := iso7816.EncodeTLV(0x70, certBytes)
	inner = append(inner, iso7816.EncodeTLV(0x71, []byte{0x00})...)
	inner = append(inner, iso7816.EncodeTLV(0xFE, nil)...)
	mock.SetSuccessResponse(0xCB, iso7816.EncodeTLV(0x53, inner))

	client := NewClient(mock)
	cert, err := client.ReadCertificate(SlotAuthentication)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(cert) != string(certBytes) {
		t.Fatalf("ReadCertificate returned %X, want %X", cert, certBytes)
	}
}

func TestClient_ReadPublicKey_Success(t *testing.T) {
	mock := emulator.NewCard()
	point := internalutil.MustEncodeUncompressedPoint(elliptic.P256(), elliptic.P256().Params().Gx, elliptic.P256().Params().Gy)
	dataObj := iso7816.EncodeTLV(0x53, iso7816.EncodeTLV(0x7F49, iso7816.EncodeTLV(0x86, point)))
	mock.SetSuccessResponse(0xCB, dataObj)

	client := NewClient(mock)
	publicKey, err := client.ReadPublicKey(SlotAuthentication)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, ok := publicKey.(*ecdsa.PublicKey); !ok {
		t.Fatalf("expected ECDSA public key, got %T", publicKey)
	}
}

func TestClient_DeleteCertificate_Success(t *testing.T) {
	mock := emulator.NewCard()
	mock.SetSuccessResponse(0xDB, nil)

	client := NewClient(mock)
	if err := client.DeleteCertificate(SlotAuthentication); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(mock.TransmittedCommands) != 1 {
		t.Fatalf("expected 1 transmitted command, got %d", len(mock.TransmittedCommands))
	}
	if got := mock.TransmittedCommands[0][1]; got != 0xDB {
		t.Fatalf("expected PUT DATA command, got 0x%02X", got)
	}
}
