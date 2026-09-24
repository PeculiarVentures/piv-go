package app

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/PeculiarVentures/piv-go/emulator"
	internalutil "github.com/PeculiarVentures/piv-go/internal"
	"github.com/PeculiarVentures/piv-go/iso7816"
	"github.com/PeculiarVentures/piv-go/piv"
)

// neoHarness is a stateful YubiKey NEO profile: GET METADATA (0xF7) is left
// unstubbed (6D00), the slot object store is shared between certificates
// and public key templates, and IMPORT KEY / GENERATE / AUTHENTICATE are
// served with real host-side cryptography.
type neoHarness struct {
	card       *emulator.Card
	objects    map[uint][]byte
	rsaKeys    map[byte]*rsa.PrivateKey
	ecKeys     map[byte]*ecdsa.PrivateKey
	importBuf  map[uint16][]byte
	putBuf     []byte
	signStatus uint16
	version    []byte
}

func newNEOHarness(t *testing.T) *neoHarness {
	t.Helper()
	h := &neoHarness{
		card:      emulator.NewCard(),
		objects:   make(map[uint][]byte),
		rsaKeys:   make(map[byte]*rsa.PrivateKey),
		ecKeys:    make(map[byte]*ecdsa.PrivateKey),
		importBuf: make(map[uint16][]byte),
		version:   []byte{0x03, 0x04, 0x09},
	}
	h.card.SetSuccessResponse(0xA4, nil)
	h.card.RegisterINSHandler(0x20, h.handleVerify)
	h.card.RegisterINSHandler(0x87, h.handleAuthenticate)
	h.card.RegisterINSHandler(0xFE, h.handleImport)
	h.card.RegisterINSHandler(0x47, h.handleGenerate)
	h.card.RegisterINSHandler(0xDB, h.handlePut)
	h.card.RegisterINSHandler(0xCB, h.handleGet)
	h.card.RegisterINSHandler(0xF6, func(_ *emulator.Card, _ []byte) ([]byte, error) {
		return emulator.BuildResponse(nil, uint16(iso7816.SwInsNotSupported)), nil
	})
	h.card.RegisterINSHandler(0xFD, func(_ *emulator.Card, _ []byte) ([]byte, error) {
		if h.version == nil {
			return emulator.BuildResponse(nil, uint16(iso7816.SwInsNotSupported)), nil
		}
		return emulator.BuildSuccessResponse(h.version), nil
	})
	return h
}

func (h *neoHarness) handleVerify(_ *emulator.Card, command []byte) ([]byte, error) {
	cmd, err := iso7816.ParseCommand(command)
	if err != nil {
		return nil, err
	}
	if len(cmd.Data) >= 6 && string(cmd.Data[:6]) == "123456" {
		return emulator.BuildSuccessResponse(nil), nil
	}
	return emulator.BuildResponse(nil, 0x63C2), nil
}

func (h *neoHarness) handleAuthenticate(_ *emulator.Card, command []byte) ([]byte, error) {
	cmd, err := iso7816.ParseCommand(command)
	if err != nil {
		return nil, err
	}
	if cmd.P2 == byte(piv.SlotManagement) {
		tlvs, err := iso7816.ParseAllTLV(cmd.Data)
		if err != nil {
			return nil, err
		}
		outer := iso7816.FindTag(tlvs, 0x7C)
		if outer == nil {
			return emulator.BuildResponse(nil, uint16(iso7816.SwWrongData)), nil
		}
		inner, err := iso7816.ParseAllTLV(outer.Value)
		if err != nil {
			return nil, err
		}
		if iso7816.FindTag(inner, 0x81) != nil {
			challenge := iso7816.EncodeTLV(0x7C, iso7816.EncodeTLV(0x81, bytes.Repeat([]byte{0x10}, 8)))
			return emulator.BuildSuccessResponse(challenge), nil
		}
		return emulator.BuildSuccessResponse(nil), nil
	}
	if h.signStatus != 0 {
		return emulator.BuildResponse(nil, h.signStatus), nil
	}
	tlvs, err := iso7816.ParseAllTLV(cmd.Data)
	if err != nil {
		return nil, err
	}
	outer := iso7816.FindTag(tlvs, 0x7C)
	if outer == nil {
		return emulator.BuildResponse(nil, uint16(iso7816.SwWrongData)), nil
	}
	inner, err := iso7816.ParseAllTLV(outer.Value)
	if err != nil {
		return nil, err
	}
	challenge := iso7816.FindTag(inner, 0x81)
	if challenge == nil {
		return emulator.BuildResponse(nil, uint16(iso7816.SwWrongData)), nil
	}
	if key, ok := h.ecKeys[cmd.P2]; ok {
		sig, err := ecdsa.SignASN1(rand.Reader, key, challenge.Value)
		if err != nil {
			return nil, err
		}
		return emulator.BuildSuccessResponse(iso7816.EncodeTLV(0x7C, iso7816.EncodeTLV(0x82, sig))), nil
	}
	if key, ok := h.rsaKeys[cmd.P2]; ok {
		m := new(big.Int).SetBytes(challenge.Value)
		if m.Cmp(key.N) >= 0 {
			return emulator.BuildResponse(nil, uint16(iso7816.SwWrongData)), nil
		}
		sig := new(big.Int).Exp(m, key.D, key.N).FillBytes(make([]byte, (key.N.BitLen()+7)/8))
		return emulator.BuildSuccessResponse(iso7816.EncodeTLV(0x7C, iso7816.EncodeTLV(0x82, sig))), nil
	}
	return emulator.BuildResponse(nil, uint16(iso7816.SwReferencedDataNotFound)), nil
}

func (h *neoHarness) handleImport(_ *emulator.Card, command []byte) ([]byte, error) {
	cmd, err := iso7816.ParseCommand(command)
	if err != nil {
		return nil, err
	}
	key := uint16(cmd.P1)<<8 | uint16(cmd.P2)
	if cmd.Cla == 0x10 {
		h.importBuf[key] = append(h.importBuf[key], cmd.Data...)
		return emulator.BuildSuccessResponse(nil), nil
	}
	payload := append(append([]byte(nil), h.importBuf[key]...), cmd.Data...)
	delete(h.importBuf, key)
	tlvs, err := iso7816.ParseAllTLV(payload)
	if err != nil {
		return nil, err
	}
	if cmd.P1 == piv.AlgRSA2048 {
		var halves [5]*big.Int
		for i, tag := range []uint{0x01, 0x02, 0x03, 0x04, 0x05} {
			field := iso7816.FindTag(tlvs, tag)
			if field == nil {
				return emulator.BuildResponse(nil, uint16(iso7816.SwWrongData)), nil
			}
			halves[i] = new(big.Int).SetBytes(field.Value)
		}
		p, q := halves[0], halves[1]
		n := new(big.Int).Mul(p, q)
		pm1 := new(big.Int).Sub(p, big.NewInt(1))
		qm1 := new(big.Int).Sub(q, big.NewInt(1))
		gcd := new(big.Int).GCD(nil, nil, pm1, qm1)
		lambda := new(big.Int).Div(new(big.Int).Mul(pm1, qm1), gcd)
		d := new(big.Int).ModInverse(big.NewInt(65537), lambda)
		if d == nil {
			return emulator.BuildResponse(nil, uint16(iso7816.SwWrongData)), nil
		}
		h.rsaKeys[cmd.P2] = &rsa.PrivateKey{
			PublicKey: rsa.PublicKey{N: n, E: 65537},
			D:         d,
			Primes:    []*big.Int{p, q},
		}
		return emulator.BuildSuccessResponse(nil), nil
	}
	if cmd.P1 == piv.AlgECCP256 {
		field := iso7816.FindTag(tlvs, 0x06)
		if field == nil || len(field.Value) != 32 {
			return emulator.BuildResponse(nil, uint16(iso7816.SwWrongData)), nil
		}
		curve := elliptic.P256()
		x, y := curve.ScalarBaseMult(field.Value)
		h.ecKeys[cmd.P2] = &ecdsa.PrivateKey{
			PublicKey: ecdsa.PublicKey{Curve: curve, X: x, Y: y},
			D:         new(big.Int).SetBytes(field.Value),
		}
		return emulator.BuildSuccessResponse(nil), nil
	}
	return emulator.BuildResponse(nil, uint16(iso7816.SwIncorrectP1P2)), nil
}

func (h *neoHarness) handleGenerate(_ *emulator.Card, command []byte) ([]byte, error) {
	cmd, err := iso7816.ParseCommand(command)
	if err != nil {
		return nil, err
	}
	tlvs, err := iso7816.ParseAllTLV(cmd.Data)
	if err != nil {
		return nil, err
	}
	control := iso7816.FindTag(tlvs, 0xAC)
	if control == nil {
		return emulator.BuildResponse(nil, uint16(iso7816.SwWrongData)), nil
	}
	inner, err := iso7816.ParseAllTLV(control.Value)
	if err != nil {
		return nil, err
	}
	algorithm := iso7816.FindTag(inner, 0x80)
	if algorithm == nil || len(algorithm.Value) != 1 || algorithm.Value[0] != piv.AlgECCP256 {
		return emulator.BuildResponse(nil, uint16(iso7816.SwIncorrectP1P2)), nil
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	h.ecKeys[cmd.P2] = key
	point := internalutil.MustEncodeUncompressedPoint(elliptic.P256(), key.PublicKey.X, key.PublicKey.Y)
	return emulator.BuildSuccessResponse(iso7816.EncodeTLV(0x7F49, iso7816.EncodeTLV(0x86, point))), nil
}

func (h *neoHarness) handlePut(_ *emulator.Card, command []byte) ([]byte, error) {
	cmd, err := iso7816.ParseCommand(command)
	if err != nil {
		return nil, err
	}
	if cmd.Cla == 0x10 {
		h.putBuf = append(h.putBuf, cmd.Data...)
		return emulator.BuildSuccessResponse(nil), nil
	}
	payload := append(append([]byte(nil), h.putBuf...), cmd.Data...)
	h.putBuf = nil
	tlvs, err := iso7816.ParseAllTLV(payload)
	if err != nil {
		return nil, err
	}
	name := iso7816.FindTag(tlvs, 0x5C)
	object := iso7816.FindTag(tlvs, 0x53)
	if name == nil || object == nil {
		return emulator.BuildResponse(nil, uint16(iso7816.SwWrongData)), nil
	}
	tag := uint(0)
	for _, b := range name.Value {
		tag = tag<<8 | uint(b)
	}
	h.objects[tag] = iso7816.EncodeTLV(0x53, object.Value)
	return emulator.BuildSuccessResponse(nil), nil
}

func (h *neoHarness) handleGet(_ *emulator.Card, command []byte) ([]byte, error) {
	cmd, err := iso7816.ParseCommand(command)
	if err != nil {
		return nil, err
	}
	tlvs, err := iso7816.ParseAllTLV(cmd.Data)
	if err != nil {
		return nil, err
	}
	name := iso7816.FindTag(tlvs, 0x5C)
	if name == nil {
		return emulator.BuildResponse(nil, uint16(iso7816.SwWrongData)), nil
	}
	tag := uint(0)
	for _, b := range name.Value {
		tag = tag<<8 | uint(b)
	}
	stored, ok := h.objects[tag]
	if !ok {
		return emulator.BuildResponse(nil, uint16(iso7816.SwFileNotFound)), nil
	}
	inner, err := iso7816.ParseAllTLV(stored)
	if err != nil {
		return nil, err
	}
	object := iso7816.FindTag(inner, 0x53)
	if object == nil || len(object.Value) == 0 {
		return emulator.BuildResponse(nil, uint16(iso7816.SwFileNotFound)), nil
	}
	return emulator.BuildSuccessResponse(stored), nil
}

func neoTestTargets(h *neoHarness) *TargetResolver {
	return NewTargetResolver(mutationTestCardContextFactory{builders: map[string]func() piv.Card{
		"YubiKey NEO Test": func() piv.Card { return h.card },
	}}, nil, bytes.NewReader(nil), &bytes.Buffer{})
}

func neoGlobal() GlobalOptions {
	return GlobalOptions{Reader: "YubiKey NEO Test", Adapter: "yubikey", NonInteractive: true, Trace: TraceAll}
}

func writeNEOKeyFile(t *testing.T, name string, data []byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatalf("write %s: %v", name, err)
	}
	return path
}

func mustNEORSAPrivateKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}
	return key
}

func mustNEORSAPEM(t *testing.T, key *rsa.PrivateKey) []byte {
	t.Helper()
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
}

func mustNEOSelfSignedCert(t *testing.T, privateKey interface{}, publicKey interface{}, name string) []byte {
	t.Helper()
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: name},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, publicKey, privateKey)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	return der
}

func mustNEOCertPEM(t *testing.T, der []byte) []byte {
	t.Helper()
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func mapExitCode(t *testing.T, err error) *CLIError {
	t.Helper()
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	mapped := (&ErrorMapper{}).Map(err)
	if mapped == nil {
		t.Fatal("expected mapped error, got nil")
	}
	return mapped
}

// TestNEOImportRSA2048ServiceOK covers F1 at the service level: a valid
// RSA-2048 key imports cleanly on the NEO profile and reads back.
func TestNEOImportRSA2048ServiceOK(t *testing.T) {
	h := newNEOHarness(t)
	targets := neoTestTargets(h)
	mutations := NewMutationService(targets, NewOperationPlanner(bytes.NewReader(nil), &bytes.Buffer{}), bytes.NewReader(nil), &bytes.Buffer{})
	t.Setenv("NEO_TEST_MGM", "010203040506070801020304050607080102030405060708")

	privateKey := mustNEORSAPrivateKey(t)
	keyPath := writeNEOKeyFile(t, "rsa.pem", mustNEORSAPEM(t, privateKey))
	resp, err := mutations.KeyImport(context.Background(), KeyImportRequest{
		Global:        neoGlobal(),
		Slot:          piv.SlotSignature,
		Algorithm:     piv.AlgRSA2048,
		AlgorithmName: "rsa2048",
		Path:          keyPath,
		ManagementKey: SecretRequest{Label: "management key", EnvVar: "NEO_TEST_MGM"},
	})
	if err != nil {
		t.Fatalf("KeyImport() error = %v", err)
	}
	mutation, ok := resp.Result.(MutationResult)
	if !ok || !mutation.Changed {
		t.Fatalf("expected changed key-import, got %+v", resp.Result)
	}
	for _, raw := range h.card.TransmittedCommands {
		if len(raw) >= 5 && len(raw) > 1 && raw[1] == 0xFE && raw[4] == 0x00 {
			t.Fatalf("IMPORT KEY must use short APDUs, got extended-length header: %X", raw[:7])
		}
	}

	info := NewInfoService(targets)
	keyResp, err := info.KeyPublic(context.Background(), ExportRequest{Global: neoGlobal(), Slot: piv.SlotSignature, Format: "pem"})
	if err != nil {
		t.Fatalf("KeyPublic() error = %v", err)
	}
	artifact, ok := keyResp.Result.(ArtifactResult)
	if !ok || artifact.Kind != "public-key" {
		t.Fatalf("unexpected result %+v", keyResp.Result)
	}
	block, _ := pem.Decode([]byte(artifact.Data))
	if block == nil {
		t.Fatalf("expected PEM public key, got %q", artifact.Data)
	}
	imported, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		t.Fatalf("parse public key: %v", err)
	}
	importedRSA, ok := imported.(*rsa.PublicKey)
	if !ok || importedRSA.N.Cmp(privateKey.PublicKey.N) != 0 || importedRSA.E != privateKey.PublicKey.E {
		t.Fatal("imported public key mismatch")
	}
}

// TestNEOGenerateCertSignDeleteFlow covers F2a/F2b/F3: generate, cert
// import, key public from the certificate, sign, cert delete, then key
// public and cert export report not-found while slot show is empty/empty.
func TestNEOGenerateCertSignDeleteFlow(t *testing.T) {
	h := newNEOHarness(t)
	targets := neoTestTargets(h)
	mutations := NewMutationService(targets, NewOperationPlanner(bytes.NewReader(nil), &bytes.Buffer{}), bytes.NewReader(nil), &bytes.Buffer{})
	info := NewInfoService(targets)
	t.Setenv("NEO_TEST_MGM", "010203040506070801020304050607080102030405060708")
	t.Setenv("NEO_TEST_PIN", "123456")
	mgm := SecretRequest{Label: "management key", EnvVar: "NEO_TEST_MGM"}

	genResp, err := mutations.KeyGenerate(context.Background(), KeyGenerateRequest{
		Global: neoGlobal(), Slot: piv.SlotSignature, Algorithm: piv.AlgECCP256, AlgorithmName: "p256", ManagementKey: mgm,
	})
	if err != nil {
		t.Fatalf("KeyGenerate() error = %v", err)
	}
	if mutation, ok := genResp.Result.(MutationResult); !ok || !mutation.Changed {
		t.Fatalf("expected changed key-generate, got %+v", genResp.Result)
	}

	generated := h.ecKeys[byte(piv.SlotSignature)]
	if generated == nil {
		t.Fatal("expected generated key in harness")
	}
	certDER := mustNEOSelfSignedCert(t, generated, &generated.PublicKey, "neo-flow")
	certPath := writeNEOKeyFile(t, "cert.pem", mustNEOCertPEM(t, certDER))
	if _, err := mutations.CertImport(context.Background(), CertImportRequest{
		Global: neoGlobal(), Slot: piv.SlotSignature, Path: certPath, ManagementKey: mgm,
	}); err != nil {
		t.Fatalf("CertImport() error = %v", err)
	}

	keyResp, err := info.KeyPublic(context.Background(), ExportRequest{Global: neoGlobal(), Slot: piv.SlotSignature, Format: "pem"})
	if err != nil {
		t.Fatalf("KeyPublic() with certificate error = %v", err)
	}
	artifact, ok := keyResp.Result.(ArtifactResult)
	if !ok {
		t.Fatalf("unexpected result %+v", keyResp.Result)
	}
	block, _ := pem.Decode([]byte(artifact.Data))
	if block == nil {
		t.Fatalf("expected PEM public key, got %q", artifact.Data)
	}
	fromCert, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		t.Fatalf("parse public key: %v", err)
	}
	fromCertECDSA, ok := fromCert.(*ecdsa.PublicKey)
	if !ok || fromCertECDSA.X.Cmp(generated.PublicKey.X) != 0 || fromCertECDSA.Y.Cmp(generated.PublicKey.Y) != 0 {
		t.Fatal("key public must serve the certificate key")
	}

	payloadPath := writeNEOKeyFile(t, "payload.bin", []byte("neo sign payload"))
	signResp, err := mutations.KeySign(context.Background(), SignRequest{
		Global: neoGlobal(), Slot: piv.SlotSignature, InputPath: payloadPath,
		Hash: "sha256", Encoding: "base64", PIN: SecretRequest{Label: "PIN", EnvVar: "NEO_TEST_PIN"},
	})
	if err != nil {
		t.Fatalf("KeySign() with certificate error = %v", err)
	}
	sigArtifact, ok := signResp.Result.(ArtifactResult)
	if !ok {
		t.Fatalf("unexpected result %+v", signResp.Result)
	}
	sig, err := base64.StdEncoding.DecodeString(sigArtifact.Data)
	if err != nil {
		t.Fatalf("decode signature: %v", err)
	}
	digest := sha256.Sum256([]byte("neo sign payload"))
	if !ecdsa.VerifyASN1(&generated.PublicKey, digest[:], sig) {
		t.Fatal("signature must verify against the slot key")
	}

	if _, err := mutations.CertDelete(context.Background(), DeleteRequest{
		Global: neoGlobal(), Slot: piv.SlotSignature, Yes: true, ManagementKey: mgm,
	}); err != nil {
		t.Fatalf("CertDelete() error = %v", err)
	}

	_, err = info.KeyPublic(context.Background(), ExportRequest{Global: neoGlobal(), Slot: piv.SlotSignature, Format: "pem"})
	mapped := mapExitCode(t, err)
	if mapped.ExitCode != 5 || mapped.Code != "not-found" {
		t.Fatalf("key public after delete = %+v, want not-found exit 5", mapped)
	}
	if mapped.Message != "the requested public key is not present" {
		t.Fatalf("unexpected message %q", mapped.Message)
	}
	if mapped.Hint != "inspect slot state with piv slot show <slot>" {
		t.Fatalf("unexpected hint %q", mapped.Hint)
	}
	if len(TraceLinesFromError(err)) == 0 {
		t.Fatal("key public failure must carry trace lines")
	}

	_, err = info.CertExport(context.Background(), ExportRequest{Global: neoGlobal(), Slot: piv.SlotSignature, Format: "pem"})
	mapped = mapExitCode(t, err)
	if mapped.ExitCode != 5 {
		t.Fatalf("cert export after delete = %+v, want exit 5", mapped)
	}

	slotResp, err := info.SlotShow(context.Background(), SlotRequest{Global: neoGlobal(), Slot: piv.SlotSignature})
	if err != nil {
		t.Fatalf("SlotShow() error = %v", err)
	}
	shown, ok := slotResp.Result.(SlotShowResult)
	if !ok {
		t.Fatalf("unexpected result %+v", slotResp.Result)
	}
	if shown.Slot.KeyPresent || shown.Slot.CertPresent {
		t.Fatalf("slot must show empty/empty after delete, got %+v", shown.Slot)
	}
	if shown.Slot.KeyAlgorithm != "" && shown.Slot.KeyAlgorithm != "-" {
		t.Fatalf("no stale key algorithm allowed, got %q", shown.Slot.KeyAlgorithm)
	}
}

// TestNEOKeyDeleteUnsupportedExit4 covers F5: MOVE KEY 6D00 surfaces the
// exact unsupported string and maps to exit 4.
func TestNEOKeyDeleteUnsupportedExit4(t *testing.T) {
	h := newNEOHarness(t)
	targets := neoTestTargets(h)
	mutations := NewMutationService(targets, NewOperationPlanner(bytes.NewReader(nil), &bytes.Buffer{}), bytes.NewReader(nil), &bytes.Buffer{})
	t.Setenv("NEO_TEST_MGM", "010203040506070801020304050607080102030405060708")
	mgm := SecretRequest{Label: "management key", EnvVar: "NEO_TEST_MGM"}

	privateKey := mustNEORSAPrivateKey(t)
	keyPath := writeNEOKeyFile(t, "rsa.pem", mustNEORSAPEM(t, privateKey))
	if _, err := mutations.KeyImport(context.Background(), KeyImportRequest{
		Global: neoGlobal(), Slot: piv.SlotSignature, Algorithm: piv.AlgRSA2048,
		AlgorithmName: "rsa2048", Path: keyPath, ManagementKey: mgm,
	}); err != nil {
		t.Fatalf("KeyImport() error = %v", err)
	}

	_, err := mutations.KeyDelete(context.Background(), DeleteRequest{
		Global: neoGlobal(), Slot: piv.SlotSignature, Yes: true,
	}, mgm)
	mapped := mapExitCode(t, err)
	if mapped.ExitCode != 4 || mapped.Code != "unsupported-capability" {
		t.Fatalf("key delete = %+v, want unsupported exit 4", mapped)
	}
	if mapped.Hint != "inspect capabilities with piv info" {
		t.Fatalf("unexpected hint %q", mapped.Hint)
	}
	want := "delete YubiKey key from slot 9C: key deletion is not supported on firmware 3.4.9, requires 5.7.0 or later"
	if !strings.Contains(err.Error(), want) {
		t.Fatalf("error = %q, want substring %q", err.Error(), want)
	}
	if len(TraceLinesFromError(err)) == 0 {
		t.Fatal("key delete failure must carry trace lines")
	}
}

// TestNEOSignWrongDataExit1WithTrace covers F4: a card-level wrong-data
// rejection during sign maps to exit 1 and still carries the trace.
func TestNEOSignWrongDataExit1WithTrace(t *testing.T) {
	h := newNEOHarness(t)
	h.signStatus = uint16(iso7816.SwWrongData)
	targets := neoTestTargets(h)
	mutations := NewMutationService(targets, NewOperationPlanner(bytes.NewReader(nil), &bytes.Buffer{}), bytes.NewReader(nil), &bytes.Buffer{})
	t.Setenv("NEO_TEST_MGM", "010203040506070801020304050607080102030405060708")
	t.Setenv("NEO_TEST_PIN", "123456")
	mgm := SecretRequest{Label: "management key", EnvVar: "NEO_TEST_MGM"}

	if _, err := mutations.KeyGenerate(context.Background(), KeyGenerateRequest{
		Global: neoGlobal(), Slot: piv.SlotSignature, Algorithm: piv.AlgECCP256, AlgorithmName: "p256", ManagementKey: mgm,
	}); err != nil {
		t.Fatalf("KeyGenerate() error = %v", err)
	}
	payloadPath := writeNEOKeyFile(t, "payload.bin", []byte("neo sign payload"))
	_, err := mutations.KeySign(context.Background(), SignRequest{
		Global: neoGlobal(), Slot: piv.SlotSignature, InputPath: payloadPath,
		Hash: "sha256", Encoding: "base64", PIN: SecretRequest{Label: "PIN", EnvVar: "NEO_TEST_PIN"},
	})
	mapped := mapExitCode(t, err)
	if mapped.ExitCode != 1 || mapped.Code != "usage-error" {
		t.Fatalf("sign wrong-data = %+v, want usage-error exit 1", mapped)
	}
	trace := TraceLinesFromError(err)
	if len(trace) == 0 {
		t.Fatal("sign failure must carry trace lines")
	}
	found := false
	for _, line := range trace {
		if strings.Contains(line, "87") {
			found = true
		}
	}
	if !found {
		t.Fatalf("trace must include the rejected AUTHENTICATE, got %v", trace)
	}
}

// TestNEOCheckImportKeyMatchRSARange covers F1: moduli within 7 bits of
// the nominal size import, genuine mismatches reject as unsupported.
func TestNEOCheckImportKeyMatchRSARange(t *testing.T) {
	full := mustNEORSAPrivateKey(t)
	if err := checkImportKeyMatch(piv.AlgRSA2048, full); err != nil {
		t.Fatalf("full-size key must match, got %v", err)
	}
	small, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	mismatch := checkImportKeyMatch(piv.AlgRSA2048, small)
	if mismatch == nil {
		t.Fatal("expected mismatch for 1024-bit key under rsa2048")
	}
	if !strings.Contains(mismatch.Error(), "not supported") {
		t.Fatalf("size refusal must contain `not supported`, got %q", mismatch.Error())
	}
	if cliErr, ok := mismatch.(*CLIError); !ok || cliErr.ExitCode != 4 {
		t.Fatalf("size refusal must be exit 4, got %+v", mismatch)
	}
}
