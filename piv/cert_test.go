package piv

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"errors"
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

// retiredSlotObjectTLVs maps retired key management slot to the encoded
// object tag carried in GET DATA / PUT DATA command data. The object
// identifier is the 3-byte BER-TLV tag 5F C1 xx, so the enclosing 5C TLV
// carries length 0x03.
func retiredSlotObjectTLVs() map[Slot][]byte {
	return map[Slot][]byte{
		0x82: {0x5C, 0x03, 0x5F, 0xC1, 0x0D},
		0x95: {0x5C, 0x03, 0x5F, 0xC1, 0x20},
	}
}

func requireSingleObjectCommand(t *testing.T, mock *emulator.Card, ins byte, wantData []byte) {
	t.Helper()
	if len(mock.TransmittedCommands) != 1 {
		t.Fatalf("expected 1 transmitted command, got %d: % X", len(mock.TransmittedCommands), mock.TransmittedCommands)
	}
	command, err := iso7816.ParseCommand(mock.TransmittedCommands[0])
	if err != nil {
		t.Fatalf("parse transmitted command: %v", err)
	}
	if command.Ins != ins {
		t.Fatalf("expected INS 0x%02X, got 0x%02X", ins, command.Ins)
	}
	if !bytes.HasPrefix(command.Data, wantData) {
		t.Fatalf("command data = % X, want prefix % X", command.Data, wantData)
	}
}

func TestClient_GetCertificate_RetiredSlotTargetsRetiredObject(t *testing.T) {
	certBytes := []byte{0x30, 0x03, 0x02, 0x01, 0x01}
	inner := iso7816.EncodeTLV(0x70, certBytes)
	inner = append(inner, iso7816.EncodeTLV(0x71, []byte{0x00})...)
	inner = append(inner, iso7816.EncodeTLV(0xFE, nil)...)

	mock := emulator.NewCard()
	mock.SetSuccessResponse(0xCB, iso7816.EncodeTLV(0x53, inner))

	cert, err := NewClient(mock).GetCertificate(0x82)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !bytes.Equal(cert, certBytes) {
		t.Fatalf("GetCertificate returned %X, want %X", cert, certBytes)
	}
	requireSingleObjectCommand(t, mock, 0xCB, retiredSlotObjectTLVs()[0x82])
}

func TestClient_PutCertificate_RetiredSlotTargetsRetiredObject(t *testing.T) {
	for slot, objectTLV := range retiredSlotObjectTLVs() {
		t.Run(slot.String(), func(t *testing.T) {
			mock := emulator.NewCard()
			mock.SetSuccessResponse(0xDB, nil)

			if err := NewClient(mock).PutCertificate(slot, []byte{0x30, 0x00}); err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			requireSingleObjectCommand(t, mock, 0xDB, objectTLV)
		})
	}
}

func TestClient_DeleteCertificate_RetiredSlotTargetsRetiredObject(t *testing.T) {
	for slot, objectTLV := range retiredSlotObjectTLVs() {
		t.Run(slot.String(), func(t *testing.T) {
			mock := emulator.NewCard()
			mock.SetSuccessResponse(0xDB, nil)

			if err := NewClient(mock).DeleteCertificate(slot); err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			requireSingleObjectCommand(t, mock, 0xDB, objectTLV)
		})
	}
}

// TestClient_CertificateOperationsRejectUnsupportedSlot verifies that an
// unmapped slot fails with ErrUnsupportedSlot before any APDU is transmitted:
// it must never fall back to object tag 0 (GET/PUT DATA 5C0100).
func TestClient_CertificateOperationsRejectUnsupportedSlot(t *testing.T) {
	operations := []struct {
		name string
		call func(client *Client) error
	}{
		{name: "GetCertificate", call: func(client *Client) error {
			_, err := client.GetCertificate(SlotManagement)
			return err
		}},
		{name: "PutCertificate", call: func(client *Client) error {
			return client.PutCertificate(SlotManagement, []byte{0x30, 0x00})
		}},
		{name: "DeleteCertificate", call: func(client *Client) error {
			return client.DeleteCertificate(SlotManagement)
		}},
	}
	for _, operation := range operations {
		t.Run(operation.name, func(t *testing.T) {
			mock := emulator.NewCard()
			err := operation.call(NewClient(mock))
			if !errors.Is(err, ErrUnsupportedSlot) {
				t.Fatalf("error = %v, want ErrUnsupportedSlot", err)
			}
			if len(mock.TransmittedCommands) != 0 {
				t.Fatalf("unsupported slot must not transmit a command, got % X", mock.TransmittedCommands)
			}
		})
	}
}
