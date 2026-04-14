package safenet

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	"github.com/PeculiarVentures/piv-go/adapters"
	adapteradmin "github.com/PeculiarVentures/piv-go/adapters/admin"
	internalutil "github.com/PeculiarVentures/piv-go/internal"
	"github.com/PeculiarVentures/piv-go/internal/testtrace"
	"github.com/PeculiarVentures/piv-go/iso7816"
	"github.com/PeculiarVentures/piv-go/piv"

	"github.com/PeculiarVentures/piv-go/emulator"
)

func TestMirrorObjectTag(t *testing.T) {
	tests := []struct {
		slot piv.Slot
		want uint
	}{
		{slot: piv.SlotAuthentication, want: safeNetMirrorTagsBySlot[piv.SlotAuthentication]},
		{slot: piv.SlotSignature, want: safeNetMirrorTagsBySlot[piv.SlotSignature]},
		{slot: piv.SlotKeyManagement, want: safeNetMirrorTagsBySlot[piv.SlotKeyManagement]},
		{slot: piv.SlotCardAuth, want: safeNetMirrorTagsBySlot[piv.SlotCardAuth]},
	}

	for _, test := range tests {
		got, err := mirrorObjectTag(test.slot)
		if err != nil {
			t.Fatalf("privateObjectTag(%s) returned error: %v", test.slot, err)
		}
		if got != test.want {
			t.Fatalf("privateObjectTag(%s) = 0x%X, want 0x%X", test.slot, got, test.want)
		}
	}
}

func TestGenerationObjectTag(t *testing.T) {
	tests := []struct {
		slot piv.Slot
		want uint
	}{
		{slot: piv.SlotAuthentication, want: safeNetGenerationTagsBySlot[piv.SlotAuthentication]},
		{slot: piv.SlotSignature, want: safeNetGenerationTagsBySlot[piv.SlotSignature]},
		{slot: piv.SlotKeyManagement, want: safeNetGenerationTagsBySlot[piv.SlotKeyManagement]},
		{slot: piv.SlotCardAuth, want: safeNetGenerationTagsBySlot[piv.SlotCardAuth]},
	}

	for _, test := range tests {
		got, err := generationObjectTag(test.slot)
		if err != nil {
			t.Fatalf("generationObjectTag(%s) returned error: %v", test.slot, err)
		}
		if got != test.want {
			t.Fatalf("generationObjectTag(%s) = 0x%X, want 0x%X", test.slot, got, test.want)
		}
	}
}

func TestMatchReader(t *testing.T) {
	adapter := NewAdapter()
	if !adapter.MatchReader("SafeNet eToken Fusion") {
		t.Fatal("expected SafeNet reader to match adapter")
	}
	if !adapter.MatchReader("eToken 5110") {
		t.Fatal("expected eToken reader to match adapter")
	}
	if adapter.MatchReader("Yubico YubiKey OTP+FIDO+CCID") {
		t.Fatal("expected non-SafeNet reader not to match adapter")
	}
}

func TestSafeNetAdapterPINStatusFromTLV(t *testing.T) {
	mock := emulator.NewCard()
	mock.SetResponse(0xCB, []byte{0x9A, 0x01, 0x05, 0x9B, 0x01, 0x03}, 0x9000)

	session := &adapters.Session{Client: piv.NewClient(mock), ReaderName: "SafeNet eToken Fusion"}
	adpt := NewAdapter()

	status, err := adapteradmin.ReadPINStatus(adapters.NewRuntime(session, adpt), piv.PINTypePUK)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if status.RetriesLeft != 3 {
		t.Fatalf("wrong PUK retries: %+v", status)
	}

	status, err = adapteradmin.ReadPINStatus(adapters.NewRuntime(session, adpt), piv.PINTypeCard)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if status.RetriesLeft != 5 {
		t.Fatalf("wrong PIN retries: %+v", status)
	}
}

func TestSafeNetAdapterManagementKeyStatusFromTLV(t *testing.T) {
	mock := emulator.NewCard()
	mock.SetSuccessResponse(0xA4, nil)

	inner := append(iso7816.EncodeTLV(0x9A, []byte{0x10}), iso7816.EncodeTLV(0x9B, []byte{0x05})...)
	response := iso7816.EncodeTLV(0xE2, iso7816.EncodeTLV(0xA0, inner))
	mock.SetSuccessResponse(0xCB, response)

	session := &adapters.Session{Client: piv.NewClient(mock), ReaderName: "SafeNet eToken Fusion"}
	adpt := NewAdapter()

	status, err := adapteradmin.ReadManagementKeyStatus(adapters.NewRuntime(session, adpt))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if status.MaxRetries != 16 || status.RetriesLeft != 5 {
		t.Fatalf("wrong MGM status: %+v", status)
	}
}

func TestDescribeSlotFallsBackToMirrorCertificate(t *testing.T) {
	certificateDER := mustCreateSafeNetTestCertificate(t)
	publicKeyObject := iso7816.EncodeTLV(0x53, iso7816.EncodeTLV(0x7F49, iso7816.EncodeTLV(0x86, internalutil.MustEncodeUncompressedPoint(elliptic.P256(), elliptic.P256().Params().Gx, elliptic.P256().Params().Gy))))
	mirrorCertificateObject := buildCertificateObject(certificateDER)

	mock := emulator.NewCard()
	mock.EnqueueResponse(0xCB, publicKeyObject, uint16(iso7816.SwSuccess))
	mock.EnqueueResponse(0xCB, nil, uint16(iso7816.SwFileNotFound))
	mock.EnqueueResponse(0xCB, mirrorCertificateObject, uint16(iso7816.SwSuccess))

	session := &adapters.Session{Client: piv.NewClient(mock), ReaderName: "SafeNet eToken Fusion"}
	description, err := NewAdapter().DescribeSlot(session, piv.SlotAuthentication)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !description.KeyPresent || description.KeyAlgorithm != "eccp256" {
		t.Fatalf("unexpected key description: %+v", description)
	}
	if !description.CertPresent || description.CertLabel != "CN=SafeNet Slot" {
		t.Fatalf("unexpected certificate description: %+v", description)
	}
}

func TestSafeNetAdapterReadCertificatePrefersStandardObject(t *testing.T) {
	certificateDER := mustCreateSafeNetTestCertificate(t)
	standardCertificateObject := buildCertificateObject(certificateDER)

	mock := emulator.NewCard()
	mock.EnqueueResponse(0xCB, standardCertificateObject, uint16(iso7816.SwSuccess))

	session := &adapters.Session{Client: piv.NewClient(mock), ReaderName: "SafeNet eToken Fusion"}
	certData, err := NewAdapter().ReadCertificate(session, piv.SlotAuthentication)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !bytes.Equal(certData, certificateDER) {
		t.Fatalf("unexpected certificate data: got %X, want %X", certData, certificateDER)
	}
}

func TestSafeNetAdapterSerialNumberUsesVendorGetData(t *testing.T) {
	mock := emulator.NewCard()
	mock.SetSuccessResponse(0xA4, nil)
	mock.SetSuccessResponse(0xCA, []byte{0x01, 0x04, 0x08, '5', '4', '8', 'T', 'P', 'K', '7', '3'})

	session := &adapters.Session{Client: piv.NewClient(mock), ReaderName: "SafeNet eToken Fusion"}
	serial, err := NewAdapter().SerialNumber(session)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !bytes.Equal(serial, []byte("548TPK73")) {
		t.Fatalf("unexpected serial: %X", serial)
	}

	testtrace.RequireMatchFile(t, "testdata/serial_number_apdu_trace.txt", mock.APDULog())
}

func TestSafeNetAdapterTokenLabelUsesVendorGetData(t *testing.T) {
	mock := emulator.NewCard()
	mock.SetSuccessResponse(0xA4, nil)
	mock.SetSuccessResponse(0xCB, []byte("eToken Fusion NFC PIV"))
	mock.SetSuccessResponse(0xA4, nil)
	mock.SetSuccessResponse(0xCA, []byte{0x01, 0x04, 0x08, '5', '4', '8', 'T', 'P', 'K', '7', '3'})

	session := &adapters.Session{Client: piv.NewClient(mock), ReaderName: "SafeNet eToken Fusion"}
	label, err := NewAdapter().Label(session)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if label != "IDPrime PIV #548TPK73" {
		t.Fatalf("unexpected token label: %q", label)
	}

	testtrace.RequireMatchFile(t, "testdata/token_label_apdu_trace.txt", mock.APDULog())
}

func TestSafeNetAdapterTokenLabelParsesNestedVendorResponse(t *testing.T) {
	mock := emulator.NewCard()
	mock.SetSuccessResponse(0xA4, nil)
	mock.SetSuccessResponse(0xCB, []byte{
		0x53, 0x3e, 0xff, 0xff, 0x00, 0x06, 0x04, 0x00, 0x01, 0xae, 0xdc,
		0x80, 0x00, 0x11, 0x01, 0x15,
		'T', 'o', 'k', 'e', 'n', ' ', 'F', 'u', 's', 'i', 'o', 'n', ' ', 'N', 'F', 'C', ' ', 'P', 'I', 'V',
		0x80, 0x00, 0x11, 0x02, 0x0d,
		'F', 'U', 'S', 'C', 'N', 'P', 'I', 'V', '4', '0', 'F', '2', '1',
		0x80, 0x00, 0x11, 0x59, 0x04,
		'G', '3', '2', '2',
	})
	mock.SetSuccessResponse(0xA4, nil)
	mock.SetSuccessResponse(0xCA, []byte{0x01, 0x04, 0x08, '5', '4', '8', 'T', 'P', 'K', '7', '3'})

	session := &adapters.Session{Client: piv.NewClient(mock), ReaderName: "SafeNet eToken Fusion"}
	label, err := NewAdapter().Label(session)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if label != "IDPrime PIV #548TPK73" {
		t.Fatalf("unexpected token label: %q", label)
	}
}

func TestSafeNetAdapterReadPublicKeyUsesCertificateObjectFallback(t *testing.T) {
	certificateDER := mustCreateSafeNetTestCertificate(t)
	standardCertificateObject := buildCertificateObject(certificateDER)

	mock := emulator.NewCard()
	mock.EnqueueResponse(0xCB, standardCertificateObject, uint16(iso7816.SwSuccess))
	mock.EnqueueResponse(0xCB, standardCertificateObject, uint16(iso7816.SwSuccess))

	session := &adapters.Session{Client: piv.NewClient(mock), ReaderName: "SafeNet eToken Fusion"}
	publicKey, err := NewAdapter().ReadPublicKey(session, piv.SlotAuthentication)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	cert, err := x509.ParseCertificate(certificateDER)
	if err != nil {
		t.Fatalf("parse test certificate: %v", err)
	}
	if !publicKeysEqual(publicKey, cert.PublicKey) {
		t.Fatalf("unexpected public key returned")
	}
}

func TestSafeNetAdapterReadPublicKeyUsesMirrorCertificateFallback(t *testing.T) {
	certificateDER := mustCreateSafeNetTestCertificate(t)
	mirrorCertificateObject := buildCertificateObject(certificateDER)

	mock := emulator.NewCard()
	mock.EnqueueResponse(0xCB, nil, uint16(iso7816.SwFileNotFound))
	mock.EnqueueResponse(0xCB, mirrorCertificateObject, uint16(iso7816.SwSuccess))

	session := &adapters.Session{Client: piv.NewClient(mock), ReaderName: "SafeNet eToken Fusion"}
	publicKey, err := NewAdapter().ReadPublicKey(session, piv.SlotAuthentication)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	cert, err := x509.ParseCertificate(certificateDER)
	if err != nil {
		t.Fatalf("parse test certificate: %v", err)
	}
	if !publicKeysEqual(publicKey, cert.PublicKey) {
		t.Fatalf("unexpected public key returned")
	}
}

func TestSafeNetAdapterPutCertificatePreservesMirrorPublicKey(t *testing.T) {
	publicKeyObject := iso7816.EncodeTLV(0x53, iso7816.EncodeTLV(0x7F49, iso7816.EncodeTLV(0x86, internalutil.MustEncodeUncompressedPoint(elliptic.P256(), elliptic.P256().Params().Gx, elliptic.P256().Params().Gy))))
	challenge := []byte{0x10, 0x32, 0x54, 0x76, 0x98, 0xBA, 0xDC, 0xFE, 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF}
	challengeResp := iso7816.EncodeTLV(0x7C, iso7816.EncodeTLV(0x81, challenge))

	mock := emulator.NewCard()
	mock.EnqueueResponse(0x87, challengeResp, uint16(iso7816.SwSuccess))
	mock.EnqueueResponse(0x87, nil, uint16(iso7816.SwSuccess))
	mock.SetSuccessResponse(0xCB, publicKeyObject)
	mock.SetSuccessResponse(0xDB, nil)

	session := &adapters.Session{
		Client:              piv.NewClient(mock),
		ReaderName:          "SafeNet eToken Fusion",
		ManagementAlgorithm: piv.AlgAES128,
		ManagementKey:       defaultManagementKey,
	}

	if err := NewAdapter().PutCertificate(session, piv.SlotAuthentication, []byte("cert")); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	for _, command := range mock.TransmittedCommands {
		if len(command) > 10 && command[1] == 0xDB && bytes.Equal(command[5:10], []byte{0x5C, 0x03, 0xFF, 0xF3, 0x05}) {
			t.Fatalf("expected no PUT DATA to mirror object FFF305, but found one")
		}
	}
	var seenStandardSlot bool
	for _, command := range mock.TransmittedCommands {
		if len(command) > 10 && command[1] == 0xDB && bytes.Equal(command[5:10], []byte{0x5C, 0x03, 0x5F, 0xC1, 0x05}) {
			seenStandardSlot = true
			break
		}
	}
	if !seenStandardSlot {
		t.Fatal("expected PUT DATA to standard slot object 5FC105")
	}
}

func publicKeysEqual(a, b crypto.PublicKey) bool {
	switch ak := a.(type) {
	case *ecdsa.PublicKey:
		bk, ok := b.(*ecdsa.PublicKey)
		if !ok {
			return false
		}
		return ak.X.Cmp(bk.X) == 0 && ak.Y.Cmp(bk.Y) == 0 && ak.Curve.Params().BitSize == bk.Curve.Params().BitSize
	case *rsa.PublicKey:
		bk, ok := b.(*rsa.PublicKey)
		if !ok {
			return false
		}
		return ak.N.Cmp(bk.N) == 0 && ak.E == bk.E
	default:
		return false
	}
}

func TestChangeManagementKeyWritesAdminObject(t *testing.T) {
	challenge := []byte{0x10, 0x32, 0x54, 0x76, 0x98, 0xBA, 0xDC, 0xFE, 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF}
	challengeResp := iso7816.EncodeTLV(0x7C, iso7816.EncodeTLV(0x81, challenge))

	mock := emulator.NewCard()
	mock.SetSuccessResponse(0xA4, nil)
	mock.EnqueueResponse(0xCB, []byte{0x76, 0x34, 0x2E, 0x30, 0x30}, uint16(iso7816.SwSuccess))
	mock.EnqueueResponse(0xCB, []byte{0x01}, uint16(iso7816.SwSuccess))
	mock.EnqueueResponse(0xCB, []byte{0x02}, uint16(iso7816.SwSuccess))
	mock.EnqueueResponse(0x87, challengeResp, uint16(iso7816.SwSuccess))
	mock.EnqueueResponse(0x87, nil, uint16(iso7816.SwSuccess))
	mock.SetSuccessResponse(0xDB, nil)
	mock.EnqueueResponse(0x87, challengeResp, uint16(iso7816.SwSuccess))
	mock.EnqueueResponse(0x87, nil, uint16(iso7816.SwSuccess))

	session := &adapters.Session{
		Client:              piv.NewClient(mock),
		ManagementAlgorithm: piv.AlgAES128,
		ManagementKey:       []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08},
	}
	newKey := []byte{0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, 0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01}

	if err := NewAdapter().ChangeManagementKey(session, piv.AlgAES128, newKey); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var putData []byte
	for _, command := range mock.TransmittedCommands {
		if len(command) > 1 && command[1] == 0xDB {
			putData = command
			break
		}
	}
	if putData == nil {
		t.Fatal("expected PUT DATA command")
	}
	wantPrefix := []byte{0x00, 0xDB, 0x3F, 0xFF, 0x1D, 0x5C, 0x03, 0xFF, 0x84, 0x0B, 0x7F, 0x4A, 0x15, 0x80, 0x01, piv.AlgAES128, 0x90, 0x10}
	if !bytes.Equal(putData[:len(wantPrefix)], wantPrefix) {
		t.Fatalf("unexpected PUT DATA prefix: %X", putData)
	}
	if !bytes.Equal(putData[len(wantPrefix):len(wantPrefix)+len(newKey)], newKey) {
		t.Fatalf("unexpected management key payload: %X", putData)
	}
	if !bytes.Equal(session.ManagementKey, newKey) || session.ManagementAlgorithm != piv.AlgAES128 {
		t.Fatalf("session was not updated: %+v", session)
	}
}

func TestFinalizeGenerateKeyStoresAndVerifiesMirrorObject(t *testing.T) {
	publicKey := &ecdsa.PublicKey{Curve: elliptic.P256(), X: elliptic.P256().Params().Gx, Y: elliptic.P256().Params().Gy}
	obj, err := encodePublicObject(piv.AlgECCP256, publicKey)
	if err != nil {
		t.Fatalf("encode public object: %v", err)
	}

	mock := emulator.NewCard()
	mock.SetSuccessResponse(0xDB, nil)
	mock.EnqueueResponse(0xCB, []byte{0x8A, 0x01, 0x05, 0x80, 0x01, piv.AlgECCP256, 0x9D, 0x01, 0x55}, uint16(iso7816.SwSuccess))
	mock.EnqueueResponse(0xCB, obj, uint16(iso7816.SwSuccess))
	mock.EnqueueResponse(0xCB, obj, uint16(iso7816.SwSuccess))

	session := &adapters.Session{Client: piv.NewClient(mock), ReaderName: "SafeNet eToken Fusion"}
	if err := NewAdapter().FinalizeGenerateKey(session, piv.SlotSignature, piv.AlgECCP256, publicKey); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(mock.TransmittedCommands) != 4 {
		t.Fatalf("expected 4 commands, got %d", len(mock.TransmittedCommands))
	}
	if mock.TransmittedCommands[0][1] != 0xDB {
		t.Fatalf("expected first command to be PUT DATA, got %02X", mock.TransmittedCommands[0][1])
	}
	if mock.TransmittedCommands[1][1] != 0xCB {
		t.Fatalf("expected second command to be GET DATA for generation metadata, got %02X", mock.TransmittedCommands[1][1])
	}
	if mock.TransmittedCommands[2][1] != 0xCB {
		t.Fatalf("expected third command to be GET DATA for standard slot presence, got %02X", mock.TransmittedCommands[2][1])
	}
	if mock.TransmittedCommands[3][1] != 0xCB {
		t.Fatalf("expected fourth command to be GET DATA for mirror object verification, got %02X", mock.TransmittedCommands[3][1])
	}
	if !bytes.Equal(mock.TransmittedCommands[0][5:10], []byte{0x5C, 0x03, 0xFF, 0xF3, 0x0A}) {
		t.Fatalf("expected PUT DATA to mirror object FFF30A, got % X", mock.TransmittedCommands[0][5:10])
	}
	if !bytes.Equal(mock.TransmittedCommands[1][5:10], []byte{0x4D, 0x03, 0xFF, 0x90, 0x0C}) {
		t.Fatalf("expected GET DATA for generation object FF900C, got % X", mock.TransmittedCommands[1][5:10])
	}
	if !bytes.Equal(mock.TransmittedCommands[2][5:10], []byte{0x5C, 0x03, 0x5F, 0xC1, 0x0A}) {
		t.Fatalf("expected GET DATA for standard slot object 5FC10A, got % X", mock.TransmittedCommands[2][5:10])
	}
	if !bytes.Equal(mock.TransmittedCommands[3][5:10], []byte{0x5C, 0x03, 0xFF, 0xF3, 0x0A}) {
		t.Fatalf("expected GET DATA to verify mirror object FFF30A, got % X", mock.TransmittedCommands[3][5:10])
	}
}

func TestFinalizeGenerateKeyStoresStandardPublicKeyWhenAbsent(t *testing.T) {
	publicKey := &ecdsa.PublicKey{Curve: elliptic.P256(), X: elliptic.P256().Params().Gx, Y: elliptic.P256().Params().Gy}
	obj, err := encodePublicObject(piv.AlgECCP256, publicKey)
	if err != nil {
		t.Fatalf("encode public object: %v", err)
	}

	mock := emulator.NewCard()
	mock.SetSuccessResponse(0xDB, nil)
	mock.EnqueueResponse(0xCB, []byte{0x8A, 0x01, 0x05, 0x80, 0x01, piv.AlgECCP256, 0x9D, 0x01, 0x55}, uint16(iso7816.SwSuccess))
	mock.EnqueueResponse(0xCB, nil, uint16(iso7816.SwFileNotFound))
	mock.EnqueueResponse(0xCB, obj, uint16(iso7816.SwSuccess))

	session := &adapters.Session{Client: piv.NewClient(mock), ReaderName: "SafeNet eToken Fusion"}
	if err := NewAdapter().FinalizeGenerateKey(session, piv.SlotSignature, piv.AlgECCP256, publicKey); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(mock.TransmittedCommands) != 5 {
		t.Fatalf("expected 5 commands, got %d", len(mock.TransmittedCommands))
	}
	if mock.TransmittedCommands[0][1] != 0xDB {
		t.Fatalf("expected first command to be PUT DATA to mirror object, got %02X", mock.TransmittedCommands[0][1])
	}
	if !bytes.Equal(mock.TransmittedCommands[0][5:10], []byte{0x5C, 0x03, 0xFF, 0xF3, 0x0A}) {
		t.Fatalf("expected mirror object write to FFF30A, got % X", mock.TransmittedCommands[0][5:10])
	}
	if mock.TransmittedCommands[1][1] != 0xCB {
		t.Fatalf("expected second command to be GET DATA for generation metadata, got %02X", mock.TransmittedCommands[1][1])
	}
	if mock.TransmittedCommands[2][1] != 0xCB {
		t.Fatalf("expected third command to be GET DATA for standard slot presence, got %02X", mock.TransmittedCommands[2][1])
	}
	if mock.TransmittedCommands[3][1] != 0xDB {
		t.Fatalf("expected fourth command to be PUT DATA for standard generated public key, got %02X", mock.TransmittedCommands[3][1])
	}
	if !bytes.Equal(mock.TransmittedCommands[3][5:10], []byte{0x5C, 0x03, 0x5F, 0xC1, 0x0A}) {
		t.Fatalf("expected PUT DATA to slot object 5FC10A, got % X", mock.TransmittedCommands[3][5:10])
	}
	if mock.TransmittedCommands[4][1] != 0xCB {
		t.Fatalf("expected fifth command to be GET DATA for mirror object verification, got %02X", mock.TransmittedCommands[4][1])
	}
}

func TestGenerateKeyEmulationProducesTraceAlignedAPDULog(t *testing.T) {
	mock := NewGenerateKeyEmulatorCard(piv.SlotAuthentication)

	client := piv.NewClient(mock)
	session := &adapters.Session{
		Client:        client,
		ReaderName:    "SafeNet eToken Fusion",
		ManagementKey: []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08},
	}

	if err := client.Select(); err != nil {
		t.Fatalf("select PIV application: %v", err)
	}

	adapter := NewAdapter()
	if err := adapter.PrepareGenerateKey(session, piv.SlotAuthentication, piv.AlgECCP256); err != nil {
		t.Fatalf("prepare key generation: %v", err)
	}

	publicKey, err := client.GenerateKeyPair(piv.SlotAuthentication, piv.AlgECCP256)
	if err != nil {
		t.Fatalf("generate key pair: %v", err)
	}

	if err := adapter.FinalizeGenerateKey(session, piv.SlotAuthentication, piv.AlgECCP256, publicKey); err != nil {
		t.Fatalf("finalize key generation: %v", err)
	}

	normalizedLog := testtrace.RequireMatchFile(t, "testdata/generate_key_ecc_p256_9a_apdu_trace.txt", mock.APDULog())
	if len(normalizedLog) == 0 {
		t.Fatal("expected normalized APDU trace")
	}
}

func TestResetSlotClearsSafeNetObjects(t *testing.T) {
	challenge := []byte{0x10, 0x32, 0x54, 0x76, 0x98, 0xBA, 0xDC, 0xFE, 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF}
	challengeResp := iso7816.EncodeTLV(0x7C, iso7816.EncodeTLV(0x81, challenge))

	mock := emulator.NewCard()
	mock.EnqueueResponse(0x87, challengeResp, uint16(iso7816.SwSuccess))
	mock.EnqueueResponse(0x87, nil, uint16(iso7816.SwSuccess))
	mock.SetSuccessResponse(0xA4, nil)
	mock.EnqueueResponse(0xCB, []byte{0x76, 0x34, 0x2E, 0x30, 0x30}, uint16(iso7816.SwSuccess))
	mock.SetSuccessResponse(0xDB, nil)

	session := &adapters.Session{
		Client:              piv.NewClient(mock),
		ManagementAlgorithm: piv.AlgAES128,
		ManagementKey:       []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08},
	}

	if err := NewAdapter().ResetSlot(session, piv.SlotAuthentication); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	putDataCount := 0
	for _, command := range mock.TransmittedCommands {
		if len(command) > 1 && command[1] == 0xDB {
			putDataCount++
		}
	}
	if putDataCount != 3 {
		t.Fatalf("expected 3 PUT DATA commands, got %d", putDataCount)
	}
}

func TestResetTokenClearsVendorObjectsAndRestoresDefaultManagementKey(t *testing.T) {
	challenge := []byte{0x10, 0x32, 0x54, 0x76, 0x98, 0xBA, 0xDC, 0xFE, 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF}
	challengeResp := iso7816.EncodeTLV(0x7C, iso7816.EncodeTLV(0x81, challenge))

	mock := emulator.NewCard()
	mock.EnqueueResponse(0x87, challengeResp, uint16(iso7816.SwSuccess))
	mock.EnqueueResponse(0x87, nil, uint16(iso7816.SwSuccess))
	mock.SetSuccessResponse(0xA4, nil)
	mock.SetSuccessResponse(0x20, nil)
	mock.EnqueueResponse(0xCB, []byte{0x76, 0x34, 0x2E, 0x30, 0x30}, uint16(iso7816.SwSuccess))
	mock.EnqueueResponse(0xCB, nil, uint16(iso7816.SwSuccess))
	mock.EnqueueResponse(0xCB, nil, uint16(iso7816.SwSuccess))
	mock.EnqueueResponse(0xCB, nil, uint16(iso7816.SwSuccess))
	mock.EnqueueResponse(0xCB, nil, uint16(iso7816.SwSuccess))
	mock.EnqueueResponse(0xCB, nil, uint16(iso7816.SwSuccess))
	mock.EnqueueResponse(0xCB, []byte{0xFF, 0x90, 0x0A, 0xFF, 0x90, 0x0C}, uint16(iso7816.SwSuccess))
	mock.EnqueueResponse(0xCB, nil, uint16(iso7816.SwSuccess))
	mock.EnqueueResponse(0xCB, nil, uint16(iso7816.SwSuccess))
	mock.EnqueueResponse(0xCB, []byte{0xFF, 0xF3, 0x05, 0xFF, 0xF3, 0x0A}, uint16(iso7816.SwSuccess))
	mock.EnqueueResponse(0xCB, nil, uint16(iso7816.SwSuccess))
	mock.EnqueueResponse(0xCB, nil, uint16(iso7816.SwSuccess))
	mock.EnqueueResponse(0xCB, nil, uint16(iso7816.SwSuccess))
	mock.EnqueueResponse(0xCB, []byte{0x76, 0x34, 0x2E, 0x30, 0x30}, uint16(iso7816.SwSuccess))
	mock.EnqueueResponse(0xCB, nil, uint16(iso7816.SwSuccess))
	mock.EnqueueResponse(0xCB, nil, uint16(iso7816.SwSuccess))
	mock.EnqueueResponse(0xCB, nil, uint16(iso7816.SwSuccess))
	mock.EnqueueResponse(0xCB, nil, uint16(iso7816.SwSuccess))
	mock.SetSuccessResponse(0xDB, nil)
	mock.SetSuccessResponse(0x2C, nil)
	mock.SetSuccessResponse(0x24, nil)
	mock.EnqueueResponse(0x87, challengeResp, uint16(iso7816.SwSuccess))
	mock.EnqueueResponse(0x87, nil, uint16(iso7816.SwSuccess))
	mock.EnqueueResponse(0x87, challengeResp, uint16(iso7816.SwSuccess))
	mock.EnqueueResponse(0x87, nil, uint16(iso7816.SwSuccess))

	session := &adapters.Session{
		Client:              piv.NewClient(mock),
		ManagementAlgorithm: piv.AlgAES128,
		ManagementKey:       []byte{0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, 0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01},
	}

	if err := NewAdapter().ResetToken(session, adapters.ResetTokenParams{PUK: defaultPUK}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	putData := make(map[uint][][]byte)
	for _, command := range mock.TransmittedCommands {
		if len(command) < 9 || command[1] != 0xDB {
			continue
		}
		tag, value, err := decodeSafeNetPutDataCommand(command)
		if err != nil {
			t.Fatalf("decode PUT DATA command: %v", err)
		}
		putData[tag] = append(putData[tag], value)
	}

	wantDBCommands := 6 + len(piv.KnownObjects()) + 1
	if got := len(flattenPutData(putData)); got != wantDBCommands {
		t.Fatalf("expected %d PUT DATA commands, got %d", wantDBCommands, got)
	}

	if got := putData[0xFFF305]; len(got) != 1 || !bytes.Equal(got[0], iso7816.EncodeTLV(0x53, nil)) {
		t.Fatalf("expected FFF305 to be cleared, got %X", got)
	}
	if got := putData[0xFF900A]; len(got) != 2 || !bytes.Equal(got[0], iso7816.EncodeTLV(0x7F48, nil)) || !bytes.Equal(got[1], iso7816.EncodeTLV(0x7F49, nil)) {
		t.Fatalf("expected FF900A to be cleared with 7F48 and 7F49, got %X", got)
	}
	if got := putData[piv.ObjectCHUID]; len(got) != 1 || !bytes.Equal(got[0], iso7816.EncodeTLV(0x53, nil)) {
		t.Fatalf("expected CHUID to be cleared, got %X", got)
	}
	if got := putData[0xFF840B]; len(got) != 1 || !bytes.Equal(got[0], buildManagementKeyObject(piv.AlgAES128, defaultManagementKey)) {
		t.Fatalf("expected FF840B to restore default management key, got %X", got)
	}
	if !hasCommandPrefix(mock.TransmittedCommands, []byte{0x00, 0x2C, 0x00, 0x80}) {
		t.Fatal("expected RESET RETRY COUNTER command restoring the default PIN")
	}
	if session.ManagementAlgorithm != piv.AlgAES128 || !bytes.Equal(session.ManagementKey, defaultManagementKey) {
		t.Fatalf("session was not updated with default management key: %+v", session)
	}
}

func flattenPutData(commands map[uint][][]byte) []uint {
	flattened := make([]uint, 0)
	for tag, values := range commands {
		for range values {
			flattened = append(flattened, tag)
		}
	}
	return flattened
}

func hasCommandPrefix(commands [][]byte, prefix []byte) bool {
	for _, command := range commands {
		if len(command) >= len(prefix) && bytes.Equal(command[:len(prefix)], prefix) {
			return true
		}
	}
	return false
}

func mustCreateSafeNetTestCertificate(t *testing.T) []byte {
	t.Helper()

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "SafeNet Slot"},
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
