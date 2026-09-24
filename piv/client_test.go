package piv

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"testing"

	internalutil "github.com/PeculiarVentures/piv-go/internal"
	"github.com/PeculiarVentures/piv-go/iso7816"

	"github.com/PeculiarVentures/piv-go/emulator"
)

func TestClient_Select_Success(t *testing.T) {
	mock := emulator.NewCard()
	mock.SetSuccessResponse(0xA4, nil)
	client := NewClient(mock)

	err := client.Select()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(mock.TransmittedCommands) != 1 {
		t.Fatalf("expected 1 command, got %d", len(mock.TransmittedCommands))
	}
}

func TestClient_Select_Error(t *testing.T) {
	mock := emulator.NewCard()
	mock.SetResponse(0xA4, nil, uint16(iso7816.SwFileNotFound))
	client := NewClient(mock)

	err := client.Select()
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestClient_VerifyPIN_Success(t *testing.T) {
	mock := emulator.NewCard()
	mock.SetSuccessResponse(0x20, nil)
	client := NewClient(mock)

	err := client.VerifyPIN("123456")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestClient_VerifyPIN_WrongPIN(t *testing.T) {
	mock := emulator.NewCard()
	mock.SetResponse(0x20, nil, 0x63C2)
	client := NewClient(mock)

	err := client.VerifyPIN("000000")
	if err == nil {
		t.Fatal("expected error for wrong PIN")
	}
}

func TestClient_GetData_Success(t *testing.T) {
	mock := emulator.NewCard()
	mock.SetSuccessResponse(0xCB, []byte{0x01, 0x02, 0x03})
	client := NewClient(mock)

	data, err := client.GetData(ObjectCHUID)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(data) != 3 {
		t.Errorf("expected 3 bytes, got %d", len(data))
	}
}

func TestKnownObjectsContainsNewAids(t *testing.T) {
	found := map[uint]bool{}
	for _, obj := range KnownObjects() {
		found[obj.Tag] = true
	}

	for _, tag := range []uint{ObjectPIVAuthKey, ObjectDigitalSigKey, ObjectKeyMgmtKey, ObjectCardAuthKey, ObjectFingerprint1, ObjectFingerprint2, ObjectPrintedInfo, ObjectFacialImage, ObjectSecurityObject} {
		if !found[tag] {
			t.Fatalf("expected known object tag %06X to be in KnownObjects", tag)
		}
	}
}

func TestClient_GetData_ResponseChaining(t *testing.T) {
	mock := emulator.NewCard()
	// First response: partial data with SW1=0x61 (more data), SW2=0x03
	mock.EnqueueResponse(0xCB, []byte{0x01, 0x02}, 0x6103)
	// GET RESPONSE (INS=0xC0): remaining data with success
	mock.EnqueueResponse(0xC0, []byte{0x03, 0x04, 0x05}, uint16(iso7816.SwSuccess))
	client := NewClient(mock)

	data, err := client.GetData(ObjectCHUID)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(data) != 5 {
		t.Errorf("expected 5 bytes, got %d", len(data))
	}
	expected := []byte{0x01, 0x02, 0x03, 0x04, 0x05}
	for i, b := range data {
		if b != expected[i] {
			t.Errorf("byte %d: expected %02X, got %02X", i, expected[i], b)
		}
	}
	if len(mock.TransmittedCommands) != 2 {
		t.Errorf("expected 2 transmitted commands, got %d", len(mock.TransmittedCommands))
	}
	// Second command should be GET RESPONSE (INS=0xC0)
	if mock.TransmittedCommands[1][1] != 0xC0 {
		t.Errorf("expected GET RESPONSE (INS=0xC0), got %02X", mock.TransmittedCommands[1][1])
	}
}

func TestClient_GetCertificate_Success(t *testing.T) {
	mock := emulator.NewCard()
	certBytes := []byte{0x30, 0x82, 0x01, 0x00}
	// Build the certificate object: 0x53 wrapping 0x70 + 0x71 + 0xFE
	inner := iso7816.EncodeTLV(0x70, certBytes)
	inner = append(inner, iso7816.EncodeTLV(0x71, []byte{0x00})...)
	inner = append(inner, iso7816.EncodeTLV(0xFE, nil)...)
	dataObj := iso7816.EncodeTLV(0x53, inner)
	mock.SetSuccessResponse(0xCB, dataObj)
	client := NewClient(mock)

	cert, err := client.GetCertificate(SlotAuthentication)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(cert) != len(certBytes) {
		t.Errorf("expected %d bytes, got %d", len(certBytes), len(cert))
	}
}

func TestClient_AuthenticateManagementKeyWithAlgorithm_Success(t *testing.T) {
	mock := emulator.NewCard()
	challenge := []byte{0x10, 0x32, 0x54, 0x76, 0x98, 0xBA, 0xDC, 0xFE, 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF}
	challengeResp := iso7816.EncodeTLV(0x7C, iso7816.EncodeTLV(0x81, challenge))
	mock.EnqueueResponse(0x87, challengeResp, uint16(iso7816.SwSuccess))
	mock.EnqueueResponse(0x87, nil, uint16(iso7816.SwSuccess))

	client := NewClient(mock)
	err := client.AuthenticateManagementKeyWithAlgorithm(AlgAES128, []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(mock.TransmittedCommands) != 2 {
		t.Fatalf("expected 2 commands, got %d", len(mock.TransmittedCommands))
	}
	if mock.TransmittedCommands[0][1] != 0x87 || mock.TransmittedCommands[1][1] != 0x87 {
		t.Fatalf("expected GENERAL AUTHENTICATE commands, got %X and %X", mock.TransmittedCommands[0][1], mock.TransmittedCommands[1][1])
	}
}

func TestClient_GenerateKeyPair_ECCP256_Success(t *testing.T) {
	mock := emulator.NewCard()
	point := internalutil.MustEncodeUncompressedPoint(elliptic.P256(), elliptic.P256().Params().Gx, elliptic.P256().Params().Gy)
	publicKeyResp := iso7816.EncodeTLV(0x7F49, iso7816.EncodeTLV(0x86, point))
	mock.SetSuccessResponse(0x47, publicKeyResp)

	client := NewClient(mock)
	publicKey, err := client.GenerateKeyPair(SlotAuthentication, AlgECCP256)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	ecdsaKey, ok := publicKey.(*ecdsa.PublicKey)
	if !ok {
		t.Fatalf("expected ECDSA public key, got %T", publicKey)
	}
	if ecdsaKey.Curve != elliptic.P256() {
		t.Fatalf("expected P-256 curve")
	}
	if len(mock.TransmittedCommands) != 1 {
		t.Fatalf("expected 1 command, got %d", len(mock.TransmittedCommands))
	}
	if mock.TransmittedCommands[0][1] != 0x47 {
		t.Fatalf("expected GENERATE ASYMMETRIC KEY PAIR, got %02X", mock.TransmittedCommands[0][1])
	}
}

func TestMockCard_DefaultResponse(t *testing.T) {
	mock := emulator.NewCard()
	resp, err := mock.Transmit([]byte{0x00, 0xFF, 0x00, 0x00})
	if err != nil {
		t.Fatal(err)
	}
	if len(resp) != 2 || resp[0] != 0x6D || resp[1] != 0x00 {
		t.Errorf("expected 6D00, got %X", resp)
	}
}

func TestMockCard_Transaction(t *testing.T) {
	mock := emulator.NewCard()
	if err := mock.Begin(); err != nil {
		t.Fatal(err)
	}
	if !mock.InTransaction {
		t.Error("expected InTransaction=true")
	}
	if err := mock.End(); err != nil {
		t.Fatal(err)
	}
	if mock.InTransaction {
		t.Error("expected InTransaction=false")
	}
}

func TestMockCard_Close(t *testing.T) {
	mock := emulator.NewCard()
	if err := mock.Close(); err != nil {
		t.Fatal(err)
	}
	if !mock.Closed {
		t.Error("expected Closed=true")
	}
}

func TestClient_SignRSA2048ChainsOversizedChallenge(t *testing.T) {
	// A host-padded 256-byte RSA challenge exceeds the short-APDU limit:
	// it must go out as chained short APDUs (CLA 0x10 intermediates),
	// never as one extended-length AUTHENTICATE that legacy firmware
	// rejects with 6700. The challenge padding itself is untouched.
	message := make([]byte, 256)
	for i := range message {
		message[i] = byte(i)
	}
	sig := make([]byte, 256)
	mock := emulator.NewCard()
	mock.SetSuccessResponse(0x87, iso7816.EncodeTLV(0x7C, iso7816.EncodeTLV(0x82, sig)))
	got, err := NewClient(mock).Sign(AlgRSA2048, SlotSignature, message, RSASignHashNone)
	if err != nil {
		t.Fatalf("Sign() error = %v", err)
	}
	if len(got) != len(sig) {
		t.Fatalf("signature length = %d, want %d", len(got), len(sig))
	}
	var payload []byte
	for index, raw := range mock.TransmittedCommands {
		if len(raw) < 2 || raw[1] != 0x87 {
			t.Fatalf("unexpected INS in %X", raw)
		}
		if len(raw) >= 5 && raw[4] == 0x00 {
			t.Fatalf("AUTHENTICATE must use short APDUs, got extended-length header: %X", raw[:7])
		}
		command, err := iso7816.ParseCommand(raw)
		if err != nil {
			t.Fatalf("parse command %d: %v", index, err)
		}
		if index < len(mock.TransmittedCommands)-1 && command.Cla != 0x10 {
			t.Fatalf("intermediate chunk %d must use CLA 0x10, got %02X", index, command.Cla)
		}
		payload = append(payload, command.Data...)
	}
	if len(mock.TransmittedCommands) < 2 {
		t.Fatalf("expected chained AUTHENTICATE, got %d commands", len(mock.TransmittedCommands))
	}
	outer, err := iso7816.ParseAllTLV(payload)
	if err != nil {
		t.Fatalf("parse outer: %v", err)
	}
	auth := iso7816.FindTag(outer, 0x7C)
	if auth == nil {
		t.Fatalf("0x7C not found in %X", payload)
	}
	inner, err := iso7816.ParseAllTLV(auth.Value)
	if err != nil {
		t.Fatalf("parse inner: %v", err)
	}
	challenge := iso7816.FindTag(inner, 0x81)
	if challenge == nil || string(challenge.Value) != string(message) {
		t.Fatal("0x81 challenge must carry the message verbatim")
	}
}

func TestClient_SignSmallChallengeStaysSingleAPDU(t *testing.T) {
	message := []byte{0x01, 0x02, 0x03}
	mock := emulator.NewCard()
	mock.SetSuccessResponse(0x87, iso7816.EncodeTLV(0x7C, iso7816.EncodeTLV(0x82, []byte{0xAA})))
	if _, err := NewClient(mock).Sign(AlgRSA2048, SlotSignature, message, RSASignHashNone); err != nil {
		t.Fatalf("Sign() error = %v", err)
	}
	if len(mock.TransmittedCommands) != 1 {
		t.Fatalf("expected 1 command, got %d", len(mock.TransmittedCommands))
	}
	command, err := iso7816.ParseCommand(mock.TransmittedCommands[0])
	if err != nil {
		t.Fatalf("parse command: %v", err)
	}
	if command.Cla != 0x00 || command.Ins != 0x87 {
		t.Fatalf("unexpected header: %X", mock.TransmittedCommands[0][:4])
	}
}
