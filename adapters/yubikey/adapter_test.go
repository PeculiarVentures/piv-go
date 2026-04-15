package yubikey

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"strings"
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

func TestYubiKeyAdapterPINStatusFromMetadata(t *testing.T) {
	mock := emulator.NewCard()
	mock.SetSuccessResponse(0xF7, encodePINMetadataTLV(3, 2, false))

	session := &adapters.Session{Client: piv.NewClient(mock), ReaderName: "Yubico YubiKey OTP+FIDO+CCID"}
	adpt := NewAdapter()

	status, err := adapteradmin.ReadPINStatus(adapters.NewRuntime(session, adpt), piv.PINTypeCard)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if status.RetriesLeft != 2 || status.Blocked {
		t.Fatalf("unexpected status: %+v", status)
	}
}

func TestYubiKeyAdapterSerialNumberUsesGetSerial(t *testing.T) {
	mock := emulator.NewCard()
	mock.SetSuccessResponse(0xA4, nil)
	mock.SetSuccessResponse(0xF8, []byte{0x01, 0x98, 0x24, 0x66})

	session := &adapters.Session{Client: piv.NewClient(mock), ReaderName: "Yubico YubiKey OTP+FIDO+CCID"}
	serial, err := NewAdapter().SerialNumber(session)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got := serial; !bytes.Equal(got, []byte{0x01, 0x98, 0x24, 0x66}) {
		t.Fatalf("unexpected serial: %X", got)
	}

	testtrace.RequireMatchFile(t, "testdata/serial_number_apdu_trace.txt", mock.APDULog())
}

func TestYubiKeyAdapterTokenLabelUsesSerialNumber(t *testing.T) {
	mock := emulator.NewCard()
	mock.SetSuccessResponse(0xA4, nil)
	mock.SetSuccessResponse(0xF8, []byte{0x01, 0x98, 0x24, 0x66})

	session := &adapters.Session{Client: piv.NewClient(mock), ReaderName: "Yubico YubiKey OTP+FIDO+CCID"}
	label, err := NewAdapter().Label(session)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if label != "YubiKey PIV #26748006" {
		t.Fatalf("unexpected token label: %q", label)
	}

	testtrace.RequireMatchFile(t, "testdata/token_label_apdu_trace.txt", mock.APDULog())
}

func TestYubiKeyAdapterCapabilitiesIncludeSerialNumber(t *testing.T) {
	report := NewAdapter().Capabilities()
	var got adapters.Capability
	for _, item := range report.Items {
		if item.ID == adapters.CapabilityReadSerialNumber {
			got = item
			break
		}
	}
	if got.ID == "" {
		t.Fatal("expected Read Serial Number capability in report")
	}
	if got.Support != adapters.CapabilityVendor {
		t.Fatalf("expected serial number capability vendor support, got %s", got.Support)
	}
}

func TestYubiKeyAdapterPUKStatus6A88(t *testing.T) {
	mock := emulator.NewCard()
	// PUK status path will call 00 20 00 81 and receive 6A88 from YubiKey
	mock.SetResponse(0x20, nil, 0x6A88)

	session := &adapters.Session{Client: piv.NewClient(mock), ReaderName: "Yubico YubiKey OTP+FIDO+CCID"}
	adpt := NewAdapter()

	status, err := adapteradmin.ReadPINStatus(adapters.NewRuntime(session, adpt), piv.PINTypePUK)
	if err != nil {
		t.Fatalf("expected no error for 6A88 puk status fallback, got %v", err)
	}
	if status.RetriesLeft != -1 {
		t.Fatalf("expected unknown retries (-1), got %d", status.RetriesLeft)
	}
}

func TestYubiKeyAdapterManagementKeyAlgorithmUsesMetadata(t *testing.T) {
	mock := emulator.NewCard()
	mock.SetSuccessResponse(0xF7, encodeManagementMetadataTLV(piv.AlgAES192, true, 0x01))

	session := &adapters.Session{Client: piv.NewClient(mock), ReaderName: "Yubico YubiKey OTP+FIDO+CCID"}
	algorithm, err := NewAdapter().ManagementKeyAlgorithm(session, defaultManagementKey)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if algorithm != piv.AlgAES192 {
		t.Fatalf("unexpected algorithm: 0x%02X", algorithm)
	}
}

func TestYubiKeyAdapterManagementKeyStatusReturnsUnlimitedRetries(t *testing.T) {
	mock := emulator.NewCard()
	mock.SetSuccessResponse(0xF7, encodeManagementMetadataTLV(piv.AlgAES192, true, 0x01))

	session := &adapters.Session{Client: piv.NewClient(mock), ReaderName: "Yubico YubiKey OTP+FIDO+CCID"}
	adpt := NewAdapter()

	status, err := adapteradmin.ReadManagementKeyStatus(adapters.NewRuntime(session, adpt))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if status.RetriesLeft != adapters.UnlimitedRetries || status.MaxRetries != adapters.UnlimitedRetries {
		t.Fatalf("expected unlimited retries, got %+v", status)
	}
}

func TestYubiKeyAdapterDescribeSlotUsesMetadata(t *testing.T) {
	certificateDER := mustCreateYubiKeyTestCertificate(t)
	certificateObject := iso7816.EncodeTLV(0x53, append(append(iso7816.EncodeTLV(0x70, certificateDER), iso7816.EncodeTLV(0x71, []byte{0x00})...), iso7816.EncodeTLV(0xFE, nil)...))

	mock := emulator.NewCard()
	mock.EnqueueResponse(0xCB, nil, uint16(iso7816.SwFileNotFound))
	mock.EnqueueResponse(0xCB, certificateObject, uint16(iso7816.SwSuccess))
	mock.SetSuccessResponse(0xF7, encodeSlotMetadataTLV(piv.AlgECCP256, false, internalutil.MustEncodeUncompressedPoint(elliptic.P256(), elliptic.P256().Params().Gx, elliptic.P256().Params().Gy)))

	session := &adapters.Session{Client: piv.NewClient(mock), ReaderName: "Yubico YubiKey OTP+FIDO+CCID"}
	description, err := NewAdapter().DescribeSlot(session, piv.SlotAuthentication)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !description.KeyPresent || description.KeyAlgorithm != "eccp256" {
		t.Fatalf("unexpected key description: %+v", description)
	}
	if !description.CertPresent || description.CertLabel != "CN=YubiKey Slot" {
		t.Fatalf("unexpected certificate description: %+v", description)
	}
}

func TestYubiKeyAdapterKeyMetadataUsesSlotMetadata(t *testing.T) {
	mock := emulator.NewCard()
	mock.SetSuccessResponse(0xF7, encodeSlotMetadataTLVWithPolicies(piv.AlgECCP256, 0x02, 0x03, false, internalutil.MustEncodeUncompressedPoint(elliptic.P256(), elliptic.P256().Params().Gx, elliptic.P256().Params().Gy)))

	session := &adapters.Session{Client: piv.NewClient(mock), ReaderName: "Yubico YubiKey OTP+FIDO+CCID"}
	metadata, err := NewAdapter().KeyMetadata(session, piv.SlotSignature)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if metadata.Source != adapters.ResolutionSourceVendorMetadata {
		t.Fatalf("unexpected source: %q", metadata.Source)
	}
	if metadata.Algorithm != adapters.KeyAlgorithmECCP256 {
		t.Fatalf("unexpected algorithm: %q", metadata.Algorithm)
	}
	if metadata.PINPolicy != adapters.PINPolicyOnce {
		t.Fatalf("unexpected PIN policy: %q", metadata.PINPolicy)
	}
	if metadata.TouchPolicy != adapters.TouchPolicyCached {
		t.Fatalf("unexpected touch policy: %q", metadata.TouchPolicy)
	}
	if got := metadata.VendorFields["yubikey/pin-policy-raw"]; len(got) != 1 || got[0] != 0x02 {
		t.Fatalf("unexpected raw PIN policy: %X", got)
	}
}

func TestYubiKeyAdapterKeyMetadataMapsNeverPINPolicy(t *testing.T) {
	mock := emulator.NewCard()
	mock.SetSuccessResponse(0xF7, encodeSlotMetadataTLVWithPolicies(piv.AlgECCP256, 0x01, 0x01, false, internalutil.MustEncodeUncompressedPoint(elliptic.P256(), elliptic.P256().Params().Gx, elliptic.P256().Params().Gy)))

	session := &adapters.Session{Client: piv.NewClient(mock), ReaderName: "Yubico YubiKey OTP+FIDO+CCID"}
	metadata, err := NewAdapter().KeyMetadata(session, piv.SlotCardAuth)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if metadata.PINPolicy != adapters.PINPolicyNever {
		t.Fatalf("unexpected PIN policy: %q", metadata.PINPolicy)
	}
	if metadata.TouchPolicy != adapters.TouchPolicyNever {
		t.Fatalf("unexpected touch policy: %q", metadata.TouchPolicy)
	}
}

func TestYubiKeyAdapterKeyMetadataFallsBackWhenMetadataUnavailable(t *testing.T) {
	mock := emulator.NewCard()
	mock.SetResponse(0xF7, nil, uint16(iso7816.SwInsNotSupported))

	session := &adapters.Session{Client: piv.NewClient(mock), ReaderName: "Yubico YubiKey OTP+FIDO+CCID"}
	metadata, err := NewAdapter().KeyMetadata(session, piv.SlotSignature)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if metadata.Source != adapters.ResolutionSourceFallback {
		t.Fatalf("unexpected source: %q", metadata.Source)
	}
	if metadata.PINPolicy != adapters.PINPolicyUnknown {
		t.Fatalf("unexpected PIN policy: %q", metadata.PINPolicy)
	}
}

func TestYubiKeyAdapterDeleteKeyUsesMoveKey(t *testing.T) {
	challenge := []byte{0x10, 0x32, 0x54, 0x76, 0x98, 0xBA, 0xDC, 0xFE, 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF}
	challengeResp := iso7816.EncodeTLV(0x7C, iso7816.EncodeTLV(0x81, challenge))

	mock := emulator.NewCard()
	mock.EnqueueResponse(0x87, challengeResp, uint16(iso7816.SwSuccess))
	mock.EnqueueResponse(0x87, nil, uint16(iso7816.SwSuccess))
	mock.SetSuccessResponse(0xF6, nil)

	session := &adapters.Session{
		Client:              piv.NewClient(mock),
		ReaderName:          "Yubico YubiKey OTP+FIDO+CCID",
		ManagementAlgorithm: piv.AlgAES192,
		ManagementKey:       append([]byte(nil), defaultManagementKey...),
	}

	if err := NewAdapter().DeleteKey(session, piv.SlotAuthentication); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var deleteCmd []byte
	for _, command := range mock.TransmittedCommands {
		if len(command) > 1 && command[1] == 0xF6 {
			deleteCmd = command
			break
		}
	}
	if deleteCmd == nil {
		t.Fatal("expected MOVE KEY delete command")
	}
	if deleteCmd[2] != 0xFF || deleteCmd[3] != byte(piv.SlotAuthentication) {
		t.Fatalf("unexpected delete command: %X", deleteCmd)
	}
}

func TestYubiKeyAdapterDeleteKeyReportsUnsupportedFirmware(t *testing.T) {
	challenge := []byte{0x10, 0x32, 0x54, 0x76, 0x98, 0xBA, 0xDC, 0xFE, 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF}
	challengeResp := iso7816.EncodeTLV(0x7C, iso7816.EncodeTLV(0x81, challenge))

	mock := emulator.NewCard()
	mock.EnqueueResponse(0x87, challengeResp, uint16(iso7816.SwSuccess))
	mock.EnqueueResponse(0x87, nil, uint16(iso7816.SwSuccess))
	mock.SetResponse(0xF6, nil, uint16(iso7816.SwInsNotSupported))
	mock.SetSuccessResponse(0xFD, []byte{0x05, 0x06, 0x00})

	session := &adapters.Session{
		Client:              piv.NewClient(mock),
		ReaderName:          "Yubico YubiKey OTP+FIDO+CCID",
		ManagementAlgorithm: piv.AlgAES192,
		ManagementKey:       append([]byte(nil), defaultManagementKey...),
	}

	err := NewAdapter().DeleteKey(session, piv.SlotAuthentication)
	if err == nil {
		t.Fatal("expected unsupported firmware error")
	}
	if !strings.Contains(err.Error(), "firmware 5.6.0 does not support key deletion") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestYubiKeyAdapterChangeManagementKeyUsesVendorCommand(t *testing.T) {
	challenge := []byte{0x10, 0x32, 0x54, 0x76, 0x98, 0xBA, 0xDC, 0xFE, 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF}
	challengeResp := iso7816.EncodeTLV(0x7C, iso7816.EncodeTLV(0x81, challenge))
	newKey := []byte{0x01, 0x01, 0x01, 0x01, 0x02, 0x02, 0x02, 0x02, 0x03, 0x03, 0x03, 0x03, 0x04, 0x04, 0x04, 0x04, 0x05, 0x05, 0x05, 0x05, 0x06, 0x06, 0x06, 0x06}

	mock := emulator.NewCard()
	mock.SetSuccessResponse(0xF7, encodeManagementMetadataTLV(piv.AlgAES192, true, 0x01))
	mock.EnqueueResponse(0x87, challengeResp, uint16(iso7816.SwSuccess))
	mock.EnqueueResponse(0x87, nil, uint16(iso7816.SwSuccess))
	mock.SetSuccessResponse(0xFF, nil)
	mock.EnqueueResponse(0x87, challengeResp, uint16(iso7816.SwSuccess))
	mock.EnqueueResponse(0x87, nil, uint16(iso7816.SwSuccess))

	session := &adapters.Session{
		Client:        piv.NewClient(mock),
		ReaderName:    "Yubico YubiKey OTP+FIDO+CCID",
		ManagementKey: append([]byte(nil), defaultManagementKey...),
	}

	if err := NewAdapter().ChangeManagementKey(session, piv.AlgAES192, newKey); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var setKeyCmd []byte
	for _, command := range mock.TransmittedCommands {
		if len(command) > 1 && command[1] == 0xFF {
			setKeyCmd = command
			break
		}
	}
	if setKeyCmd == nil {
		t.Fatal("expected SET MANAGEMENT KEY command")
	}
	wantPrefix := []byte{0x00, 0xFF, 0xFF, 0xFF, 0x1B, piv.AlgAES192, 0x9B, 0x18}
	if !bytes.Equal(setKeyCmd[:len(wantPrefix)], wantPrefix) {
		t.Fatalf("unexpected SET MANAGEMENT KEY command: %X", setKeyCmd)
	}
	if !bytes.Equal(setKeyCmd[len(wantPrefix):len(wantPrefix)+len(newKey)], newKey) {
		t.Fatalf("unexpected management key payload: %X", setKeyCmd)
	}
	if session.ManagementAlgorithm != piv.AlgAES192 || !bytes.Equal(session.ManagementKey, newKey) {
		t.Fatalf("session was not updated: %+v", session)
	}
	normalizedLog := testtrace.RequireMatchFile(t, "testdata/change_management_key_apdu_trace.txt", mock.APDULog())
	if len(normalizedLog) == 0 {
		t.Fatal("expected YubiKey management key APDU trace")
	}
}

func TestYubiKeyAdapterChangeManagementKeyIncludesObserverComments(t *testing.T) {
	challenge := []byte{0x10, 0x32, 0x54, 0x76, 0x98, 0xBA, 0xDC, 0xFE, 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF}
	challengeResp := iso7816.EncodeTLV(0x7C, iso7816.EncodeTLV(0x81, challenge))
	newKey := []byte{0x01, 0x01, 0x01, 0x01, 0x02, 0x02, 0x02, 0x02, 0x03, 0x03, 0x03, 0x03, 0x04, 0x04, 0x04, 0x04, 0x05, 0x05, 0x05, 0x05, 0x06, 0x06, 0x06, 0x06}

	mock := emulator.NewCard()
	mock.SetSuccessResponse(0xF7, encodeManagementMetadataTLV(piv.AlgAES192, true, 0x01))
	mock.EnqueueResponse(0x87, challengeResp, uint16(iso7816.SwSuccess))
	mock.EnqueueResponse(0x87, nil, uint16(iso7816.SwSuccess))
	mock.SetSuccessResponse(0xFF, nil)
	mock.EnqueueResponse(0x87, challengeResp, uint16(iso7816.SwSuccess))
	mock.EnqueueResponse(0x87, nil, uint16(iso7816.SwSuccess))

	trace := adapters.NewTraceCollector(adapters.TraceModeAdapterOnly)
	session := adapters.NewSession(
		piv.NewClient(mock),
		adapters.WithReaderName("Yubico YubiKey OTP+FIDO+CCID"),
		adapters.WithManagementCredentials(0, append([]byte(nil), defaultManagementKey...)),
		adapters.WithTraceCollector(trace),
	)

	if err := NewAdapter().ChangeManagementKey(session, piv.AlgAES192, newKey); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	traceLines := session.TraceLog()
	if !containsLineWithPrefix(traceLines, "# yubikey change-management-key: starting YubiKey management key rotation") {
		t.Fatalf("missing management key start trace in %v", traceLines)
	}
	if !containsLineWithPrefix(traceLines, "# yubikey change-management-key: completed YubiKey management key rotation") {
		t.Fatalf("missing management key completion trace in %v", traceLines)
	}
}

func containsLineWithPrefix(logLines []string, prefix string) bool {
	upperPrefix := strings.ToUpper(prefix)
	for _, line := range logLines {
		if strings.HasPrefix(strings.ToUpper(line), upperPrefix) {
			return true
		}
	}
	return false
}

func encodePINMetadataTLV(total int, remaining int, defaultValue bool) []byte {
	defaultByte := byte(0x00)
	if defaultValue {
		defaultByte = 0x01
	}
	data := iso7816.EncodeTLV(yubiKeyMetadataTagIsDefault, []byte{defaultByte})
	data = append(data, iso7816.EncodeTLV(yubiKeyMetadataTagRetries, []byte{byte(total), byte(remaining)})...)
	return data
}

func encodeManagementMetadataTLV(algorithm byte, defaultValue bool, touchPolicy byte) []byte {
	defaultByte := byte(0x00)
	if defaultValue {
		defaultByte = 0x01
	}
	data := iso7816.EncodeTLV(yubiKeyMetadataTagAlgorithm, []byte{algorithm})
	data = append(data, iso7816.EncodeTLV(yubiKeyMetadataTagPolicy, []byte{0x00, touchPolicy})...)
	data = append(data, iso7816.EncodeTLV(yubiKeyMetadataTagIsDefault, []byte{defaultByte})...)
	return data
}

func encodeSlotMetadataTLV(algorithm byte, generated bool, publicKey []byte) []byte {
	return encodeSlotMetadataTLVWithPolicies(algorithm, 0x02, 0x01, generated, publicKey)
}

func encodeSlotMetadataTLVWithPolicies(algorithm byte, pinPolicy byte, touchPolicy byte, generated bool, publicKey []byte) []byte {
	origin := byte(0x02)
	if generated {
		origin = yubiKeyOriginGenerated
	}
	data := iso7816.EncodeTLV(yubiKeyMetadataTagAlgorithm, []byte{algorithm})
	data = append(data, iso7816.EncodeTLV(yubiKeyMetadataTagPolicy, []byte{pinPolicy, touchPolicy})...)
	data = append(data, iso7816.EncodeTLV(yubiKeyMetadataTagOrigin, []byte{origin})...)
	if len(publicKey) > 0 {
		data = append(data, iso7816.EncodeTLV(yubiKeyMetadataTagPublicKey, iso7816.EncodeTLV(0x86, publicKey))...)
	}
	return data
}

func mustCreateYubiKeyTestCertificate(t *testing.T) []byte {
	t.Helper()

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "YubiKey Slot"},
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
