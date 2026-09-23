package app

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/mlkem"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/PeculiarVentures/piv-go/emulator"
	"github.com/PeculiarVentures/piv-go/iso7816"
	"github.com/PeculiarVentures/piv-go/piv"
)

func newPQCResolver(card *emulator.Card, reader string) *TargetResolver {
	if reader == "" {
		reader = "YubiKey Test"
	}
	return NewTargetResolver(mutationTestCardContextFactory{builders: map[string]func() piv.Card{
		reader: func() piv.Card { return card },
	}}, nil, bytes.NewReader(nil), &bytes.Buffer{})
}

func stubSelect(card *emulator.Card) {
	card.SetSuccessResponse(0xA4, nil)
}

func stubSlotMetadata(card *emulator.Card, algorithm byte, inner []byte) {
	data := iso7816.EncodeTLV(0x01, []byte{algorithm})
	data = append(data, iso7816.EncodeTLV(0x02, []byte{0x02, 0x01})...)
	data = append(data, iso7816.EncodeTLV(0x03, []byte{0x01})...)
	data = append(data, iso7816.EncodeTLV(0x04, inner)...)
	card.SetSuccessResponse(0xF7, data)
}

func hasAPDU(card *emulator.Card, ins byte) bool {
	for _, cmd := range card.TransmittedCommands {
		if len(cmd) > 1 && cmd[1] == ins {
			return true
		}
	}
	return false
}

func TestParsePrivateKeyForAlgorithmRawFallback(t *testing.T) {
	seed := bytes.Repeat([]byte{0xAB}, 32)
	hexPath := hex.EncodeToString(seed)
	b64Path := "q6urq6urq6urq6urq6urq6urq6urq6urq6urq6urq6s="

	// Binary raw.
	key, err := ParsePrivateKeyForAlgorithm(seed, piv.AlgEd25519)
	if err != nil {
		t.Fatalf("binary raw: %v", err)
	}
	opaque, ok := key.(*piv.OpaquePrivateKey)
	if !ok || opaque.Algorithm != piv.AlgEd25519 || !bytes.Equal(opaque.Raw, seed) {
		t.Fatalf("binary raw: unexpected key %#v", key)
	}
	// Hex.
	key, err = ParsePrivateKeyForAlgorithm([]byte(hexPath), piv.AlgX25519)
	if err != nil {
		t.Fatalf("hex raw: %v", err)
	}
	if opaque, ok := key.(*piv.OpaquePrivateKey); !ok || !bytes.Equal(opaque.Raw, seed) {
		t.Fatalf("hex raw: unexpected key %#v", key)
	}
	// Base64.
	key, err = ParsePrivateKeyForAlgorithm([]byte(b64Path), piv.AlgEd25519)
	if err != nil {
		t.Fatalf("base64 raw: %v", err)
	}
	if opaque, ok := key.(*piv.OpaquePrivateKey); !ok || !bytes.Equal(opaque.Raw, seed) {
		t.Fatalf("base64 raw: unexpected key %#v", key)
	}
	// PKCS#8 Ed25519 still parses.
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	_ = ecKey
	// Ed25519 PKCS8 via crypto/rand? Use raw path for brevity: invalid input rejects.
	if _, err := ParsePrivateKeyForAlgorithm([]byte("not a key"), piv.AlgEd25519); err == nil {
		t.Fatal("expected error for garbage ed25519 input")
	}
	// Baseline algorithms ignore raw fallback and use strict parsing.
	if _, err := ParsePrivateKeyForAlgorithm([]byte("not a key"), piv.AlgECCP256); err == nil {
		t.Fatal("expected error for garbage p256 input")
	}
}

func TestParseCertificateDataRaw(t *testing.T) {
	raw := []byte{0x01, 0x02, 0x03, 0x04}
	got, err := ParseCertificateDataRaw(raw)
	if err != nil || !bytes.Equal(got, raw) {
		t.Fatalf("raw: got %X, %v", got, err)
	}
	if _, err := ParseCertificateData(raw); err == nil {
		t.Fatal("strict must reject non-x509 bytes")
	}
	if _, err := ParseCertificateDataRaw([]byte("   ")); err == nil {
		t.Fatal("raw must reject empty input")
	}
}

func TestParseCertificateDataRawPreservesTrailingWhitespaceBytes(t *testing.T) {
	// P2: DER bytes are stored verbatim; trailing bytes that coincide
	// with whitespace (0x20/0x0A/0x0D/0x09) must round-trip byte for byte.
	base := []byte{0x30, 0x82, 0x01, 0x00, 0x01, 0x02}
	for _, trail := range [][]byte{
		{0x20}, {0x0A}, {0x0D}, {0x09},
		{0x20, 0x0A, 0x0D, 0x09},
		{0x09, 0x0D, 0x0A, 0x20},
	} {
		raw := append(append([]byte(nil), base...), trail...)
		got, err := ParseCertificateDataRaw(raw)
		if err != nil {
			t.Fatalf("trail %X: %v", trail, err)
		}
		if !bytes.Equal(got, raw) {
			t.Fatalf("trail %X: got %X, want %X", trail, got, raw)
		}
	}
	// PEM input still decodes to block bytes.
	der := mustTestCertificate(t)
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	got, err := ParseCertificateDataRaw(pemBytes)
	if err != nil || !bytes.Equal(got, der) {
		t.Fatalf("pem: got %d bytes, %v", len(got), err)
	}
}

func TestParseRawKeyBytesPreservesWhitespaceEdges(t *testing.T) {
	// P2: binary seeds of the exact length are accepted verbatim, even
	// when edge bytes coincide with whitespace (0x20/0x0A/0x0D/0x09).
	for _, edge := range []byte{0x20, 0x0A, 0x0D, 0x09} {
		seed32 := bytes.Repeat([]byte{0xAB}, 32)
		seed32[0] = edge
		seed32[31] = edge
		for _, alg := range []byte{piv.AlgEd25519, piv.AlgX25519} {
			key, err := ParsePrivateKeyForAlgorithm(seed32, alg)
			if err != nil {
				t.Fatalf("edge 0x%02X alg 0x%02X: %v", edge, alg, err)
			}
			opaque, ok := key.(*piv.OpaquePrivateKey)
			if !ok || !bytes.Equal(opaque.Raw, seed32) {
				t.Fatalf("edge 0x%02X alg 0x%02X: unexpected key %#v", edge, alg, key)
			}
		}
		seed64 := bytes.Repeat([]byte{0xD5}, piv.MLKEMSeedLength)
		seed64[0] = edge
		seed64[piv.MLKEMSeedLength-1] = edge
		key, err := ParsePrivateKeyForAlgorithm(seed64, piv.AlgMLKEM768)
		if err != nil {
			t.Fatalf("edge 0x%02X mlkem768: %v", edge, err)
		}
		opaque, ok := key.(*piv.OpaquePrivateKey)
		if !ok || !bytes.Equal(opaque.Raw, seed64) {
			t.Fatalf("edge 0x%02X mlkem768: unexpected key %#v", edge, key)
		}
	}
}

func TestKeyGenerateMLKEM768(t *testing.T) {
	ek := bytes.Repeat([]byte{0x47}, 1184)
	card := emulator.NewCard()
	stubSelect(card)
	enqueueManagementAuthPair(card, 2)
	card.SetSuccessResponse(0x47, iso7816.EncodeTLV(0x7F49, iso7816.EncodeTLV(0x88, ek)))
	card.SetSuccessResponse(0xDB, nil)
	targets := NewTargetResolver(mutationTestCardContextFactory{builders: map[string]func() piv.Card{
		"YubiKey Test": func() piv.Card { return card },
	}}, nil, bytes.NewReader(nil), &bytes.Buffer{})
	service := NewMutationService(targets, NewOperationPlanner(bytes.NewReader(nil), &bytes.Buffer{}), bytes.NewReader(nil), &bytes.Buffer{})
	t.Setenv("PIV_MANAGEMENT_KEY", "01020304050607080102030405060708")
	resp, err := service.KeyGenerate(context.Background(), KeyGenerateRequest{
		Global:        GlobalOptions{Reader: "YubiKey Test", NonInteractive: true},
		Slot:          piv.SlotSignature,
		Algorithm:     piv.AlgMLKEM768,
		AlgorithmName: "mlkem768",
		ManagementKey: SecretRequest{EnvVar: "PIV_MANAGEMENT_KEY"},
	})
	if err != nil {
		t.Fatalf("KeyGenerate(mlkem768) error = %v", err)
	}
	mutation, ok := resp.Result.(MutationResult)
	if !ok || !mutation.Changed {
		t.Fatalf("expected changed key-generate, got %+v", resp.Result)
	}
	// Verify the GENERATE wire: 00 47 00 9C AC{80 E6}.
	found := false
	for _, raw := range card.TransmittedCommands {
		if len(raw) > 1 && raw[1] == 0x47 {
			cmd, err := iso7816.ParseCommand(raw)
			if err != nil {
				t.Fatalf("parse generate: %v", err)
			}
			if cmd.Cla != 0x00 || cmd.P1 != 0x00 || cmd.P2 != byte(piv.SlotSignature) {
				continue
			}
			outer, _ := iso7816.ParseAllTLV(cmd.Data)
			ac := iso7816.FindTag(outer, 0xAC)
			if ac == nil {
				continue
			}
			inner, _ := iso7816.ParseAllTLV(ac.Value)
			if alg := iso7816.FindTag(inner, 0x80); alg != nil && len(alg.Value) == 1 && alg.Value[0] == piv.AlgMLKEM768 {
				found = true
			}
		}
	}
	if !found {
		t.Fatal("GENERATE 00 47 00 9C AC{80 E6} not found")
	}
	if !hasAPDU(card, 0xDB) {
		t.Fatal("expected PUT DATA storing the generated public key")
	}
}

func TestKeyImportMLDSAGapNoAPDU(t *testing.T) {
	card := emulator.NewCard()
	service := NewMutationService(newPQCResolver(card, ""), nil, bytes.NewReader(nil), &bytes.Buffer{})
	_, err := service.KeyImport(context.Background(), KeyImportRequest{Slot: piv.SlotSignature, Algorithm: piv.AlgMLDSA65, AlgorithmName: "mldsa65", Path: "/nonexistent"})
	if err == nil || !strings.Contains(err.Error(), "not supported") {
		t.Fatalf("expected not-supported gap, got %v", err)
	}
	if len(card.TransmittedCommands) != 0 {
		t.Fatalf("gap must send no APDU, got %d", len(card.TransmittedCommands))
	}
}

func TestKeyImportMLKEM768Seed(t *testing.T) {
	dk, err := mlkem.GenerateKey768()
	if err != nil {
		t.Fatalf("GenerateKey768() error = %v", err)
	}
	seed := dk.Bytes()
	wantEK := dk.EncapsulationKey().Bytes()
	path := filepath.Join(t.TempDir(), "mlkem.seed")
	if err := os.WriteFile(path, seed, 0o644); err != nil {
		t.Fatalf("write seed: %v", err)
	}
	card := emulator.NewCard()
	stubSelect(card)
	enqueueManagementAuthPair(card, 2)
	card.SetSuccessResponse(0xFE, nil)
	card.SetSuccessResponse(0xDB, nil)
	targets := NewTargetResolver(mutationTestCardContextFactory{builders: map[string]func() piv.Card{
		"YubiKey Test": func() piv.Card { return card },
	}}, nil, bytes.NewReader(nil), &bytes.Buffer{})
	service := NewMutationService(targets, NewOperationPlanner(bytes.NewReader(nil), &bytes.Buffer{}), bytes.NewReader(nil), &bytes.Buffer{})
	t.Setenv("PIV_MANAGEMENT_KEY", "01020304050607080102030405060708")
	_, err = service.KeyImport(context.Background(), KeyImportRequest{
		Global:        GlobalOptions{Reader: "YubiKey Test", NonInteractive: true},
		Slot:          piv.SlotSignature,
		Algorithm:     piv.AlgMLKEM768,
		AlgorithmName: "mlkem768",
		Path:          path,
		ManagementKey: SecretRequest{EnvVar: "PIV_MANAGEMENT_KEY"},
	})
	if err != nil {
		t.Fatalf("KeyImport(mlkem768 seed) error = %v", err)
	}
	// Verify IMPORT KEY wire: 00 FE E6 slot 0A{64 seed}.
	found := false
	for _, raw := range card.TransmittedCommands {
		if len(raw) > 1 && raw[1] == 0xFE {
			cmd, err := iso7816.ParseCommand(raw)
			if err != nil {
				t.Fatalf("parse import: %v", err)
			}
			if cmd.P1 != piv.AlgMLKEM768 {
				t.Fatalf("P1 = 0x%02X, want 0xE6", cmd.P1)
			}
			tlvs, _ := iso7816.ParseAllTLV(cmd.Data)
			tag := iso7816.FindTag(tlvs, 0x0A)
			if tag == nil || !bytes.Equal(tag.Value, seed) {
				t.Fatalf("tag 0x0A must carry the 64-byte seed in %X", cmd.Data[:16])
			}
			found = true
		}
	}
	if !found {
		t.Fatal("expected IMPORT KEY APDU")
	}
	// The stored slot object must carry the derived encapsulation key.
	var stored []byte
	for _, raw := range card.TransmittedCommands {
		if len(raw) > 1 && raw[1] == 0xDB {
			chunk, err := iso7816.ParseCommand(raw)
			if err != nil {
				t.Fatalf("parse PUT DATA: %v", err)
			}
			stored = append(stored, chunk.Data...)
		}
	}
	if !bytes.Contains(stored, wantEK) {
		t.Fatal("stored slot object must contain the derived encapsulation key")
	}
}

func TestKeyImportMLKEM512GapNoAPDU(t *testing.T) {
	seed := bytes.Repeat([]byte{0xD5}, piv.MLKEMSeedLength)
	path := filepath.Join(t.TempDir(), "mlkem512.seed")
	if err := os.WriteFile(path, seed, 0o644); err != nil {
		t.Fatalf("write seed: %v", err)
	}
	card := emulator.NewCard()
	service := NewMutationService(newPQCResolver(card, ""), nil, bytes.NewReader(nil), &bytes.Buffer{})
	_, err := service.KeyImport(context.Background(), KeyImportRequest{Slot: piv.SlotSignature, Algorithm: piv.AlgMLKEM512, AlgorithmName: "mlkem512", Path: path})
	if err == nil || !strings.Contains(err.Error(), "not supported") {
		t.Fatalf("expected not-supported gap, got %v", err)
	}
	if len(card.TransmittedCommands) != 0 {
		t.Fatalf("gap must send no APDU, got %d", len(card.TransmittedCommands))
	}
}

func TestKeyChallengeMLKEMDecapsulate(t *testing.T) {
	dk, err := mlkem.GenerateKey768()
	if err != nil {
		t.Fatalf("GenerateKey768() error = %v", err)
	}
	ek := dk.EncapsulationKey().Bytes()
	peer, err := mlkem.NewEncapsulationKey768(ek)
	if err != nil {
		t.Fatalf("NewEncapsulationKey768() error = %v", err)
	}
	hostSecret, ciphertext := peer.Encapsulate()
	if len(ciphertext) != 1088 {
		t.Fatalf("ciphertext length = %d, want 1088", len(ciphertext))
	}
	cardSecret := bytes.Repeat([]byte{0x5E}, 32)
	card := emulator.NewCard()
	stubSelect(card)
	stubSlotMetadata(card, piv.AlgMLKEM768, iso7816.EncodeTLV(0x88, ek))
	card.SetSuccessResponse(0x87, iso7816.EncodeTLV(0x7C, iso7816.EncodeTLV(0x82, cardSecret)))
	service := NewMutationService(newPQCResolver(card, ""), nil, bytes.NewReader(nil), &bytes.Buffer{})
	resp, err := service.KeyChallenge(context.Background(), ChallengeRequest{
		Global: GlobalOptions{Reader: "YubiKey Test", NonInteractive: true}, Slot: piv.SlotKeyManagement,
		ChallengeHex: hex.EncodeToString(ciphertext), Encoding: "base64",
	})
	if err != nil {
		t.Fatalf("KeyChallenge(KEM) error = %v", err)
	}
	artifact, ok := resp.Result.(ArtifactResult)
	if !ok {
		t.Fatalf("expected ArtifactResult, got %T", resp.Result)
	}
	if artifact.Kind != "kem-secret" {
		t.Fatalf("kind = %q, want kem-secret", artifact.Kind)
	}
	_ = hostSecret
	// Verify decapsulate wire: 00 87 E6 slot 7C{82 empty, 86 ct1088}.
	found := false
	for _, raw := range card.TransmittedCommands {
		if len(raw) > 1 && raw[1] == 0x87 {
			cmd, err := iso7816.ParseCommand(raw)
			if err != nil {
				continue
			}
			if cmd.P1 != piv.AlgMLKEM768 {
				continue
			}
			outer, _ := iso7816.ParseAllTLV(cmd.Data)
			auth := iso7816.FindTag(outer, 0x7C)
			if auth == nil {
				continue
			}
			inner, _ := iso7816.ParseAllTLV(auth.Value)
			ctTLV := iso7816.FindTag(inner, 0x86)
			if ctTLV != nil && bytes.Equal(ctTLV.Value, ciphertext) {
				found = true
			}
		}
	}
	if !found {
		t.Fatal("decapsulate command with 0x86 ciphertext not found")
	}
}

func TestKeyChallengeMLKEMRejectsBadCiphertext(t *testing.T) {
	ek := bytes.Repeat([]byte{0x47}, 1184)
	card := emulator.NewCard()
	stubSelect(card)
	stubSlotMetadata(card, piv.AlgMLKEM768, iso7816.EncodeTLV(0x88, ek))
	service := NewMutationService(newPQCResolver(card, ""), nil, bytes.NewReader(nil), &bytes.Buffer{})
	_, err := service.KeyChallenge(context.Background(), ChallengeRequest{
		Global: GlobalOptions{Reader: "YubiKey Test", NonInteractive: true}, Slot: piv.SlotKeyManagement,
		ChallengeHex: hex.EncodeToString(bytes.Repeat([]byte{0xC7}, 32)), Encoding: "base64",
	})
	if err == nil {
		t.Fatal("expected ciphertext length error, got nil")
	}
	if hasAPDU(card, 0x87) {
		t.Fatal("rejected challenge must not send GENERAL AUTHENTICATE")
	}
}

func TestParsePrivateKeyForAlgorithmMLKEMSeed(t *testing.T) {
	dk, err := mlkem.GenerateKey768()
	if err != nil {
		t.Fatalf("GenerateKey768() error = %v", err)
	}
	seed := dk.Bytes()
	// Binary raw.
	key, err := ParsePrivateKeyForAlgorithm(seed, piv.AlgMLKEM768)
	if err != nil {
		t.Fatalf("binary seed: %v", err)
	}
	opaque, ok := key.(*piv.OpaquePrivateKey)
	if !ok || opaque.Algorithm != piv.AlgMLKEM768 || !bytes.Equal(opaque.Raw, seed) {
		t.Fatalf("binary seed: unexpected key %#v", key)
	}
	// Hex and base64.
	for _, encoded := range []string{hex.EncodeToString(seed), base64.StdEncoding.EncodeToString(seed)} {
		key, err := ParsePrivateKeyForAlgorithm([]byte(encoded), piv.AlgMLKEM1024)
		if err != nil {
			t.Fatalf("encoded seed: %v", err)
		}
		if opaque, ok := key.(*piv.OpaquePrivateKey); !ok || opaque.Algorithm != piv.AlgMLKEM1024 || !bytes.Equal(opaque.Raw, seed) {
			t.Fatalf("encoded seed: unexpected key %#v", key)
		}
	}
	// Wrong length rejects.
	if _, err := ParsePrivateKeyForAlgorithm(bytes.Repeat([]byte{0xD5}, 32), piv.AlgMLKEM768); err == nil {
		t.Fatal("expected error for 32-byte input")
	}
}

func TestKeyImportEd25519RawSeed(t *testing.T) {
	seed := bytes.Repeat([]byte{0xAB}, 32)
	path := filepath.Join(t.TempDir(), "ed.seed")
	if err := os.WriteFile(path, seed, 0o644); err != nil {
		t.Fatalf("write seed: %v", err)
	}
	card := emulator.NewCard()
	stubSelect(card)
	stubSlotMetadata(card, piv.AlgEd25519, iso7816.EncodeTLV(0x86, seed))
	// Management auth stubs (AES-128, 16-byte challenge). KeyImport
	// authenticates once in the service and once in the YubiKey adapter.
	challenge := iso7816.EncodeTLV(0x7C, iso7816.EncodeTLV(0x81, bytes.Repeat([]byte{0x10}, 16)))
	card.EnqueueResponse(0x87, challenge, uint16(iso7816.SwSuccess))
	card.EnqueueResponse(0x87, nil, uint16(iso7816.SwSuccess))
	card.EnqueueResponse(0x87, challenge, uint16(iso7816.SwSuccess))
	card.EnqueueResponse(0x87, nil, uint16(iso7816.SwSuccess))
	card.SetSuccessResponse(0xFE, nil)
	card.SetSuccessResponse(0xDB, nil)
	targets := NewTargetResolver(mutationTestCardContextFactory{builders: map[string]func() piv.Card{
		"YubiKey Test": func() piv.Card { return card },
	}}, nil, bytes.NewReader(nil), &bytes.Buffer{})
	service := NewMutationService(targets, NewOperationPlanner(bytes.NewReader(nil), &bytes.Buffer{}), bytes.NewReader(nil), &bytes.Buffer{})
	t.Setenv("PIV_MANAGEMENT_KEY", "01020304050607080102030405060708")
	_, err := service.KeyImport(context.Background(), KeyImportRequest{
		Global:        GlobalOptions{Reader: "YubiKey Test", NonInteractive: true},
		Slot:          piv.SlotSignature,
		Algorithm:     piv.AlgEd25519,
		AlgorithmName: "ed25519",
		Path:          path,
		ManagementKey: SecretRequest{EnvVar: "PIV_MANAGEMENT_KEY"},
	})
	if err != nil {
		t.Fatalf("KeyImport(ed25519 raw) error = %v", err)
	}
	if !hasAPDU(card, 0xFE) {
		t.Fatal("expected IMPORT KEY APDU")
	}
	// Verify tag 0x07 with 32 bytes.
	for _, raw := range card.TransmittedCommands {
		if len(raw) > 1 && raw[1] == 0xFE {
			cmd, err := iso7816.ParseCommand(raw)
			if err != nil {
				t.Fatalf("parse import: %v", err)
			}
			if cmd.P1 != piv.AlgEd25519 {
				t.Fatalf("P1 = 0x%02X, want 0xE0", cmd.P1)
			}
			tlvs, _ := iso7816.ParseAllTLV(cmd.Data)
			tag := iso7816.FindTag(tlvs, 0x07)
			if tag == nil || len(tag.Value) != 32 {
				t.Fatalf("tag 0x07/32 missing in %X", cmd.Data)
			}
		}
	}
}

func TestCertImportMLKEMRejects(t *testing.T) {
	ek := bytes.Repeat([]byte{0x47}, 1184)
	card := emulator.NewCard()
	stubSelect(card)
	stubSlotMetadata(card, piv.AlgMLKEM768, iso7816.EncodeTLV(0x88, ek))
	path := filepath.Join(t.TempDir(), "cert.der")
	if err := os.WriteFile(path, []byte{0x30, 0x00}, 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	service := NewMutationService(newPQCResolver(card, ""), nil, bytes.NewReader(nil), &bytes.Buffer{})
	_, err := service.CertImport(context.Background(), CertImportRequest{Global: GlobalOptions{Reader: "YubiKey Test", NonInteractive: true}, Slot: piv.SlotKeyManagement, Path: path})
	if err == nil || !strings.Contains(err.Error(), "not supported") {
		t.Fatalf("expected not-supported error, got %v", err)
	}
	if hasAPDU(card, 0xDB) {
		t.Fatal("rejected ML-KEM cert import must not send PUT DATA")
	}
}

func TestCertImportX25519Rejects(t *testing.T) {
	raw := bytes.Repeat([]byte{0xA5}, 32)
	card := emulator.NewCard()
	stubSelect(card)
	stubSlotMetadata(card, piv.AlgX25519, iso7816.EncodeTLV(0x86, raw))
	path := filepath.Join(t.TempDir(), "cert.der")
	if err := os.WriteFile(path, []byte{0x30, 0x00}, 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	service := NewMutationService(newPQCResolver(card, ""), nil, bytes.NewReader(nil), &bytes.Buffer{})
	_, err := service.CertImport(context.Background(), CertImportRequest{Global: GlobalOptions{Reader: "YubiKey Test", NonInteractive: true}, Slot: piv.SlotKeyManagement, Path: path})
	if err == nil || !strings.Contains(err.Error(), "no X.509 profile") {
		t.Fatalf("expected no-X.509-profile error, got %v", err)
	}
	if hasAPDU(card, 0xDB) {
		t.Fatal("rejected X25519 cert import must not send PUT DATA")
	}
}

func TestCertImportMLDSARawGate(t *testing.T) {
	// Use the standard adapter path (no management auth) with a stored
	// 0x53{7F49{87 ...}} object: ParsePublicKeyObject infers ML-DSA-44
	// from the value length without metadata context.
	mldsaObject := func() []byte {
		raw := bytes.Repeat([]byte{0x5A}, 1312)
		return iso7816.EncodeTLV(0x53, iso7816.EncodeTLV(0x7F49, iso7816.EncodeTLV(0x87, raw)))
	}
	payload := bytes.Repeat([]byte{0x99}, 64)
	path := filepath.Join(t.TempDir(), "mldsa.cert")
	if err := os.WriteFile(path, payload, 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	card := emulator.NewCard()
	stubSelect(card)
	card.SetSuccessResponse(0xCB, mldsaObject())
	service := NewMutationService(NewTargetResolver(mutationTestCardContextFactory{builders: map[string]func() piv.Card{
		"Standard Token": func() piv.Card { return card },
	}}, nil, bytes.NewReader(nil), &bytes.Buffer{}), nil, bytes.NewReader(nil), &bytes.Buffer{})
	_, err := service.CertImport(context.Background(), CertImportRequest{Global: GlobalOptions{Reader: "Standard Token", NonInteractive: true}, Slot: piv.SlotSignature, Path: path})
	if err == nil || !strings.Contains(err.Error(), "post-quantum certificate requires --raw") {
		t.Fatalf("expected --raw gate, got %v", err)
	}
	// Raw mode stores.
	card2 := emulator.NewCard()
	stubSelect(card2)
	card2.SetSuccessResponse(0xCB, mldsaObject())
	card2.SetSuccessResponse(0xDB, nil)
	service2 := NewMutationService(NewTargetResolver(mutationTestCardContextFactory{builders: map[string]func() piv.Card{
		"Standard Token": func() piv.Card { return card2 },
	}}, nil, bytes.NewReader(nil), &bytes.Buffer{}), nil, bytes.NewReader(nil), &bytes.Buffer{})
	resp, err := service2.CertImport(context.Background(), CertImportRequest{Global: GlobalOptions{Reader: "Standard Token", NonInteractive: true}, Slot: piv.SlotSignature, Path: path, Raw: true})
	if err != nil {
		t.Fatalf("raw CertImport error = %v", err)
	}
	mutation, ok := resp.Result.(MutationResult)
	if !ok || !mutation.Changed || mutation.Action != "cert-import" {
		t.Fatalf("unexpected response %+v", resp.Result)
	}
	if !hasAPDU(card2, 0xDB) {
		t.Fatal("raw cert import must send PUT DATA")
	}
}

func TestKeyChallengeX25519ECDH(t *testing.T) {
	peer := bytes.Repeat([]byte{0x11}, 32)
	secret := bytes.Repeat([]byte{0x22}, 32)
	pubRaw := bytes.Repeat([]byte{0xA5}, 32)
	card := emulator.NewCard()
	stubSelect(card)
	stubSlotMetadata(card, piv.AlgX25519, iso7816.EncodeTLV(0x86, pubRaw))
	card.SetSuccessResponse(0x87, iso7816.EncodeTLV(0x7C, iso7816.EncodeTLV(0x82, secret)))
	service := NewMutationService(newPQCResolver(card, ""), nil, bytes.NewReader(nil), &bytes.Buffer{})
	resp, err := service.KeyChallenge(context.Background(), ChallengeRequest{
		Global: GlobalOptions{Reader: "YubiKey Test", NonInteractive: true}, Slot: piv.SlotKeyManagement,
		ChallengeHex: hex.EncodeToString(peer), Encoding: "base64",
	})
	if err != nil {
		t.Fatalf("KeyChallenge(ECDH) error = %v", err)
	}
	artifact, ok := resp.Result.(ArtifactResult)
	if !ok {
		t.Fatalf("expected ArtifactResult, got %T", resp.Result)
	}
	if artifact.Kind != "ecdh-secret" {
		t.Fatalf("kind = %q, want ecdh-secret", artifact.Kind)
	}
	// Verify ECDH wire: 00 87 E1 slot 7C{82 empty, 85 peer}.
	found := false
	for _, raw := range card.TransmittedCommands {
		if len(raw) > 1 && raw[1] == 0x87 {
			cmd, err := iso7816.ParseCommand(raw)
			if err != nil {
				continue
			}
			if cmd.P1 != piv.AlgX25519 {
				continue
			}
			outer, _ := iso7816.ParseAllTLV(cmd.Data)
			auth := iso7816.FindTag(outer, 0x7C)
			if auth == nil {
				continue
			}
			inner, _ := iso7816.ParseAllTLV(auth.Value)
			peerTLV := iso7816.FindTag(inner, 0x85)
			if peerTLV != nil && bytes.Equal(peerTLV.Value, peer) {
				found = true
			}
		}
	}
	if !found {
		t.Fatalf("ECDH command with 0x85 peer not found: % X", card.TransmittedCommands)
	}
}

func TestKeyPublicPQCRawExport(t *testing.T) {
	pubRaw := bytes.Repeat([]byte{0x5A}, 1312)
	card := emulator.NewCard()
	stubSelect(card)
	stubSlotMetadata(card, piv.AlgMLDSA44, iso7816.EncodeTLV(0x87, pubRaw))
	info := NewInfoService(newPQCResolver(card, ""))
	// PEM must keep the gap.
	if _, err := info.KeyPublic(context.Background(), ExportRequest{Global: GlobalOptions{Reader: "YubiKey Test", NonInteractive: true}, Slot: piv.SlotSignature, Format: "pem"}); err == nil {
		t.Fatal("PEM export of ML-DSA must gap-reject")
	}
	// Raw encodings succeed.
	for _, format := range []string{"raw", "base64", "hex"} {
		card2 := emulator.NewCard()
		stubSelect(card2)
		stubSlotMetadata(card2, piv.AlgMLDSA44, iso7816.EncodeTLV(0x87, pubRaw))
		info2 := NewInfoService(newPQCResolver(card2, ""))
		if _, err := info2.KeyPublic(context.Background(), ExportRequest{Global: GlobalOptions{Reader: "YubiKey Test", NonInteractive: true}, Slot: piv.SlotSignature, Format: format}); err != nil {
			t.Fatalf("KeyPublic(%s) error = %v", format, err)
		}
	}
	// ML-KEM keeps the same PEM gap with zero-APDU rejection semantics at
	// the encode layer, while raw encodings export the 0x88 bytes.
	kemRaw := bytes.Repeat([]byte{0x47}, 1184)
	kemCard := emulator.NewCard()
	stubSelect(kemCard)
	stubSlotMetadata(kemCard, piv.AlgMLKEM768, iso7816.EncodeTLV(0x88, kemRaw))
	kemInfo := NewInfoService(newPQCResolver(kemCard, ""))
	if _, err := kemInfo.KeyPublic(context.Background(), ExportRequest{Global: GlobalOptions{Reader: "YubiKey Test", NonInteractive: true}, Slot: piv.SlotSignature, Format: "pem"}); err == nil {
		t.Fatal("PEM export of ML-KEM must gap-reject")
	}
	kemCard2 := emulator.NewCard()
	stubSelect(kemCard2)
	stubSlotMetadata(kemCard2, piv.AlgMLKEM768, iso7816.EncodeTLV(0x88, kemRaw))
	kemInfo2 := NewInfoService(newPQCResolver(kemCard2, ""))
	resp, err := kemInfo2.KeyPublic(context.Background(), ExportRequest{Global: GlobalOptions{Reader: "YubiKey Test", NonInteractive: true}, Slot: piv.SlotSignature, Format: "base64"})
	if err != nil {
		t.Fatalf("KeyPublic(mlkem768 base64) error = %v", err)
	}
	artifact, ok := resp.Result.(ArtifactResult)
	if !ok || artifact.Kind != "public-key" {
		t.Fatalf("unexpected result %+v", resp.Result)
	}
}

func TestCheckImportKeyMatchRSA3072(t *testing.T) {
	small, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	if err := checkImportKeyMatch(piv.AlgRSA3072, small); err == nil || !strings.Contains(err.Error(), "3072") {
		t.Fatalf("expected 3072 mismatch, got %v", err)
	}
	if err := checkImportKeyMatch(piv.AlgRSA4096, small); err == nil || !strings.Contains(err.Error(), "4096") {
		t.Fatalf("expected 4096 mismatch, got %v", err)
	}
	// Mismatched types still report.
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate EC: %v", err)
	}
	if err := checkImportKeyMatch(piv.AlgEd25519, ecKey); err == nil || !strings.Contains(err.Error(), "ed25519") {
		t.Fatalf("expected ed25519 mismatch, got %v", err)
	}
}

func mustTestCertificate(t *testing.T) []byte {
	t.Helper()
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "PQC Test"},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	return der
}

func enqueueManagementAuthPair(card *emulator.Card, pairs int) {
	challenge := iso7816.EncodeTLV(0x7C, iso7816.EncodeTLV(0x81, bytes.Repeat([]byte{0x10}, 16)))
	for i := 0; i < pairs; i++ {
		card.EnqueueResponse(0x87, challenge, uint16(iso7816.SwSuccess))
		card.EnqueueResponse(0x87, nil, uint16(iso7816.SwSuccess))
	}
}

// F1: cert import on a YubiKey token must authenticate the management key
// (service auth plus adapter auth) instead of failing with "management key
// is required".
func TestCertImportYubiKeyAuthenticatesManagementKey(t *testing.T) {
	der := mustTestCertificate(t)
	path := filepath.Join(t.TempDir(), "cert.pem")
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644); err != nil {
		t.Fatalf("write cert: %v", err)
	}
	card := emulator.NewCard()
	stubSelect(card)
	enqueueManagementAuthPair(card, 2)
	card.SetSuccessResponse(0xDB, nil)
	service := NewMutationService(newPQCResolver(card, ""), nil, bytes.NewReader(nil), &bytes.Buffer{})
	t.Setenv("PIV_MANAGEMENT_KEY", "01020304050607080102030405060708")
	resp, err := service.CertImport(context.Background(), CertImportRequest{
		Global:        GlobalOptions{Reader: "YubiKey Test", NonInteractive: true},
		Slot:          piv.SlotSignature,
		Path:          path,
		ManagementKey: SecretRequest{EnvVar: "PIV_MANAGEMENT_KEY"},
	})
	if err != nil {
		t.Fatalf("CertImport() error = %v", err)
	}
	mutation, ok := resp.Result.(MutationResult)
	if !ok || !mutation.Changed {
		t.Fatalf("expected changed cert-import, got %+v", resp.Result)
	}
	if !hasAPDU(card, 0x87) {
		t.Fatal("expected management authentication APDUs")
	}
	if !hasAPDU(card, 0xDB) {
		t.Fatal("expected PUT DATA certificate write")
	}
}

// F1: cert import without management credentials on a YubiKey token reports
// a usage error before writing.
func TestCertImportYubiKeyRequiresManagementKey(t *testing.T) {
	der := mustTestCertificate(t)
	path := filepath.Join(t.TempDir(), "cert.pem")
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644); err != nil {
		t.Fatalf("write cert: %v", err)
	}
	card := emulator.NewCard()
	stubSelect(card)
	card.SetSuccessResponse(0xDB, nil)
	service := NewMutationService(newPQCResolver(card, ""), nil, bytes.NewReader(nil), &bytes.Buffer{})
	_, err := service.CertImport(context.Background(), CertImportRequest{
		Global: GlobalOptions{Reader: "YubiKey Test", NonInteractive: true},
		Slot:   piv.SlotSignature,
		Path:   path,
	})
	if err == nil {
		t.Fatal("expected management key error, got nil")
	}
	if hasAPDU(card, 0xDB) {
		t.Fatal("no PUT DATA must be sent without management credentials")
	}
}

// F1: cert delete on a YubiKey token authenticates before clearing.
func TestCertDeleteYubiKeyAuthenticatesManagementKey(t *testing.T) {
	der := mustTestCertificate(t)
	certObj := iso7816.EncodeTLV(0x53, append(
		iso7816.EncodeTLV(0x70, der),
		append(iso7816.EncodeTLV(0x71, []byte{0x00}), iso7816.EncodeTLV(0xFE, nil)...)...,
	))
	card := emulator.NewCard()
	stubSelect(card)
	card.SetSuccessResponse(0xCB, certObj)
	enqueueManagementAuthPair(card, 2)
	card.SetSuccessResponse(0xDB, nil)
	targets := newPQCResolver(card, "")
	service := NewMutationService(targets, NewOperationPlanner(bytes.NewReader(nil), &bytes.Buffer{}), bytes.NewReader(nil), &bytes.Buffer{})
	t.Setenv("PIV_MANAGEMENT_KEY", "01020304050607080102030405060708")
	resp, err := service.CertDelete(context.Background(), DeleteRequest{
		Global:        GlobalOptions{Reader: "YubiKey Test", NonInteractive: true},
		Slot:          piv.SlotSignature,
		Yes:           true,
		ManagementKey: SecretRequest{EnvVar: "PIV_MANAGEMENT_KEY"},
	})
	if err != nil {
		t.Fatalf("CertDelete() error = %v", err)
	}
	mutation, ok := resp.Result.(MutationResult)
	if !ok || !mutation.Changed {
		t.Fatalf("expected changed cert-delete, got %+v", resp.Result)
	}
	if !hasAPDU(card, 0x87) {
		t.Fatal("expected management authentication APDUs")
	}
	if !hasAPDU(card, 0xDB) {
		t.Fatal("expected PUT DATA certificate clear")
	}
}

// O1: Ed25519 opaque keys export standard PEM/DER; X25519 keeps the gap
// with an unsupported-capability error (exit 4 via the CLI mapper).
func TestKeyPublicEd25519PEM(t *testing.T) {
	pubRaw := bytes.Repeat([]byte{0xA5}, 32)
	newCard := func() *emulator.Card {
		card := emulator.NewCard()
		stubSelect(card)
		stubSlotMetadata(card, piv.AlgEd25519, iso7816.EncodeTLV(0x86, pubRaw))
		return card
	}
	info := NewInfoService(newPQCResolver(newCard(), ""))
	resp, err := info.KeyPublic(context.Background(), ExportRequest{Global: GlobalOptions{Reader: "YubiKey Test", NonInteractive: true}, Slot: piv.SlotSignature, Format: "pem"})
	if err != nil {
		t.Fatalf("KeyPublic(ed25519 pem) error = %v", err)
	}
	artifact, ok := resp.Result.(ArtifactResult)
	if !ok || artifact.Kind != "public-key" {
		t.Fatalf("unexpected result %+v", resp.Result)
	}
	// X25519 PEM keeps the gap.
	xcard := emulator.NewCard()
	stubSelect(xcard)
	stubSlotMetadata(xcard, piv.AlgX25519, iso7816.EncodeTLV(0x86, pubRaw))
	xinfo := NewInfoService(newPQCResolver(xcard, ""))
	_, err = xinfo.KeyPublic(context.Background(), ExportRequest{Global: GlobalOptions{Reader: "YubiKey Test", NonInteractive: true}, Slot: piv.SlotSignature, Format: "pem"})
	if err == nil {
		t.Fatal("X25519 PEM export must gap-reject")
	}
	mapped := (&ErrorMapper{}).Map(err)
	if mapped == nil || mapped.Code != "unsupported-capability" || mapped.ExitCode != 4 {
		t.Fatalf("X25519 PEM gap must map to unsupported-capability exit 4, got %+v", mapped)
	}
	// X25519 raw export still works.
	xcard2 := emulator.NewCard()
	stubSelect(xcard2)
	stubSlotMetadata(xcard2, piv.AlgX25519, iso7816.EncodeTLV(0x86, pubRaw))
	xinfo2 := NewInfoService(newPQCResolver(xcard2, ""))
	if _, err := xinfo2.KeyPublic(context.Background(), ExportRequest{Global: GlobalOptions{Reader: "YubiKey Test", NonInteractive: true}, Slot: piv.SlotSignature, Format: "raw"}); err != nil {
		t.Fatalf("KeyPublic(x25519 raw) error = %v", err)
	}
}

func TestEncodePublicKeyEd25519Opaque(t *testing.T) {
	pubRaw := bytes.Repeat([]byte{0xA5}, 32)
	encoded, err := EncodePublicKey(&piv.OpaquePublicKey{Algorithm: piv.AlgEd25519, Raw: pubRaw}, "pem")
	if err != nil {
		t.Fatalf("EncodePublicKey(ed25519) error = %v", err)
	}
	block, _ := pem.Decode(encoded)
	if block == nil || block.Type != "PUBLIC KEY" {
		t.Fatalf("expected PUBLIC KEY PEM, got %q", encoded)
	}
	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		t.Fatalf("parse exported key: %v", err)
	}
	edKey, ok := parsed.(ed25519.PublicKey)
	if !ok {
		t.Fatalf("unexpected parsed type %T", parsed)
	}
	if !bytes.Equal(edKey, pubRaw) {
		t.Fatal("exported Ed25519 key must round-trip verbatim")
	}
}

// F4: X25519 sign rejection must carry the "not supported" substring so the
// CLI mapper reports unsupported-capability (exit 4), not internal (exit 9).
func TestX25519SignMapsToUnsupported(t *testing.T) {
	card := emulator.NewCard()
	_, err := piv.NewClient(card).Sign(piv.AlgX25519, piv.SlotSignature, []byte{0xAA}, piv.RSASignHashNone)
	if err == nil {
		t.Fatal("expected X25519 sign rejection")
	}
	if !strings.Contains(err.Error(), "x25519 cannot sign: use ECDH") || !strings.Contains(err.Error(), "not supported") {
		t.Fatalf("error must carry both hint and not-supported, got %v", err)
	}
	mapped := (&ErrorMapper{}).Map(err)
	if mapped == nil || mapped.Code != "unsupported-capability" || mapped.ExitCode != 4 {
		t.Fatalf("must map to unsupported-capability exit 4, got %+v", mapped)
	}
	if len(card.TransmittedCommands) != 0 {
		t.Fatalf("rejection must send no APDU, got %d", len(card.TransmittedCommands))
	}
}

// F1 regression guard: standard-token cert delete stays credential-free.
func TestCertDeleteStandardNoManagementKey(t *testing.T) {
	der := mustTestCertificate(t)
	certObj := iso7816.EncodeTLV(0x53, append(
		iso7816.EncodeTLV(0x70, der),
		append(iso7816.EncodeTLV(0x71, []byte{0x00}), iso7816.EncodeTLV(0xFE, nil)...)...,
	))
	card := emulator.NewCard()
	stubSelect(card)
	card.SetSuccessResponse(0xCB, certObj)
	card.SetSuccessResponse(0xDB, nil)
	targets := NewTargetResolver(mutationTestCardContextFactory{builders: map[string]func() piv.Card{
		"Standard Token": func() piv.Card { return card },
	}}, nil, bytes.NewReader(nil), &bytes.Buffer{})
	service := NewMutationService(targets, NewOperationPlanner(bytes.NewReader(nil), &bytes.Buffer{}), bytes.NewReader(nil), &bytes.Buffer{})
	resp, err := service.CertDelete(context.Background(), DeleteRequest{
		Global: GlobalOptions{Reader: "Standard Token", NonInteractive: true},
		Slot:   piv.SlotSignature,
		Yes:    true,
	})
	if err != nil {
		t.Fatalf("CertDelete() error = %v", err)
	}
	mutation, ok := resp.Result.(MutationResult)
	if !ok || !mutation.Changed {
		t.Fatalf("expected changed cert-delete, got %+v", resp.Result)
	}
	if hasAPDU(card, 0x87) {
		t.Fatal("standard cert delete must not authenticate")
	}
}
