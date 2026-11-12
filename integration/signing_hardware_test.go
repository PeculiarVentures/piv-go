//go:build hardware

package integration_test

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/PeculiarVentures/piv-go/adapters"
	"github.com/PeculiarVentures/piv-go/adapters/yubikey"
	"github.com/PeculiarVentures/piv-go/iso7816"
	"github.com/PeculiarVentures/piv-go/pcsc"
	"github.com/PeculiarVentures/piv-go/piv"
)

// TestYubiKeySigningOpenSSL resets only the explicitly selected test card's
// PIV application and replaces its keys. Both the build tag and environment
// opt-in are required; it is never part of ordinary go test ./....
func TestYubiKeySigningOpenSSL(t *testing.T) {
	if os.Getenv("PIV_TEST_ALLOW_RESET") != "1" {
		t.Skip("set PIV_TEST_ALLOW_RESET=1 to reset a dedicated test card")
	}
	reader := os.Getenv("PIV_TEST_READER")
	serial := os.Getenv("PIV_TEST_SERIAL")
	if reader == "" || serial == "" {
		t.Fatal("PIV_TEST_READER and PIV_TEST_SERIAL must identify the dedicated test card")
	}
	// This suite currently contains a fixed matrix for the separately qualified
	// preview device. The external inventory is captured before opening a PIV
	// session, so no hidden applet switch occurs during discovery.
	model := os.Getenv("PIV_TEST_MODEL")
	firmware := os.Getenv("PIV_TEST_DEVICE_FIRMWARE")
	if model != "YubiKey 5C NFC - Enhanced PIN" || firmware != "6.0.0.alpha.8" {
		t.Fatal("PIV_TEST_MODEL and PIV_TEST_DEVICE_FIRMWARE must select the qualified preview matrix")
	}
	device := inventoryYubiKey(t, "--device", serial, serial, model, firmware)
	openssl := os.Getenv("PIV_TEST_OPENSSL")
	if openssl == "" {
		openssl = "openssl"
	}
	version := runOpenSSL(t, openssl, "version")
	if !strings.HasPrefix(version, "OpenSSL 3.") {
		t.Fatalf("OpenSSL 3 with ML-DSA support is required, got %s", version)
	}
	ctx, err := pcsc.NewContext()
	if err != nil {
		t.Fatal(err)
	}
	defer ctx.Release()
	card, err := ctx.Connect(reader)
	if err != nil {
		t.Fatal(err)
	}
	defer card.Close()
	if err := card.Begin(); err != nil {
		t.Fatal(err)
	}
	defer card.End()
	client := piv.NewClient(card)
	if err := client.Select(); err != nil {
		t.Fatal(err)
	}
	adapter := yubikey.NewAdapter()
	session := adapters.NewSession(client, adapters.WithReaderName(reader))
	requireDirectPIVSerial(t, client, serial)
	pivVersion, err := adapter.PIVVersion(session)
	if err != nil {
		t.Fatal(err)
	}
	if pivVersion != "0.0.1" {
		t.Fatalf("PIV applet version %q does not match qualified preview matrix; refusing reset", pivVersion)
	}
	device.PIVVersion = pivVersion
	report := adapter.SigningCapabilities(device)
	t.Logf("reader=%s model=%s device firmware=%s PIV applet=%s verifier=%s", reader, device.Model, device.Firmware, pivVersion, version)
	if err := adapter.ResetToken(session, adapters.ResetTokenParams{}); err != nil {
		t.Fatalf("reset dedicated PIV test application: %v", err)
	}
	managementKey := bytes.Repeat([]byte{1, 2, 3, 4, 5, 6, 7, 8}, 3)
	generate := func(t *testing.T, slot piv.Slot, algorithm byte) crypto.PublicKey {
		t.Helper()
		if err := client.AuthenticateManagementKeyWithAlgorithm(piv.AlgAES192, managementKey); err != nil {
			t.Fatal(err)
		}
		key, err := client.GenerateKeyPairWithPolicies(slot, algorithm, 0x03, 0x01)
		if err != nil {
			t.Fatalf("generate algorithm=%02X slot=%s: %v", algorithm, slot, err)
		}
		description, err := adapter.DescribeSlot(session, slot)
		if err != nil || description.KeyState != adapters.SlotStatePresent || description.PublicKeySource != adapters.PublicKeySourceMetadata || description.Metadata == nil || description.Metadata.Algorithm != adapters.NormalizeKeyAlgorithm(algorithm) {
			t.Fatalf("generated key lacks matching current metadata: state=%s source=%s metadata=%v error=%v", description.KeyState, description.PublicKeySource, description.Metadata != nil, err)
		}
		if !bytes.Equal(hardwarePublicPEM(t, key), hardwarePublicPEM(t, description.PublicKey)) {
			t.Fatal("generated public key does not match current slot metadata")
		}
		return key
	}
	match := func(t *testing.T, slot piv.Slot, publicKey crypto.PublicKey, request adapters.SigningRequest) {
		t.Helper()
		description, err := adapter.DescribeSlot(session, slot)
		if err != nil || description.KeyState != adapters.SlotStatePresent || description.PublicKeySource != adapters.PublicKeySourceMetadata || description.Metadata == nil {
			t.Fatalf("current slot metadata unavailable: %v", err)
		}
		if !bytes.Equal(hardwarePublicPEM(t, publicKey), hardwarePublicPEM(t, description.PublicKey)) {
			t.Fatal("signing key no longer matches current slot metadata")
		}
		evidence, err := adapters.SigningKeyEvidenceFromSlot(slot, description, true)
		if err != nil {
			t.Fatalf("construct signing evidence: %v", err)
		}
		decision := adapters.MatchSigningCapability(report, evidence, request)
		if decision.Support != adapters.SigningSupported || decision.ProfileID == "" {
			t.Fatalf("operation does not match an advertised profile: %+v", decision)
		}
	}
	verifyPIN := func(t *testing.T) {
		t.Helper()
		if err := client.VerifyPIN("123456"); err != nil {
			t.Fatal(err)
		}
	}
	message := []byte("piv-go hardware qualification: exact scheme parameters")
	for _, tc := range []struct {
		name string
		alg  byte
		slot piv.Slot
	}{
		{"RSA2048", piv.AlgRSA2048, piv.SlotAuthentication},
		{"RSA3072", piv.AlgRSA3072, piv.SlotSignature},
		{"RSA4096", piv.AlgRSA4096, 0x82},
	} {
		t.Run(tc.name, func(t *testing.T) {
			publicKey := generate(t, tc.slot, tc.alg).(*rsa.PublicKey)
			publicPEM := hardwarePublicPEM(t, publicKey)
			for _, hash := range []crypto.Hash{crypto.SHA256, crypto.SHA384, crypto.SHA512} {
				digest, hashName := hardwareDigest(hash, message)
				t.Run(hashName, func(t *testing.T) {
					opts := piv.RSAPKCS1v15DigestOptions{Hash: hash}
					request, err := adapters.SigningRequestFromRSAOptions(tc.alg, publicKey, digest, opts)
					if err != nil {
						t.Fatal(err)
					}
					match(t, tc.slot, publicKey, request)
					verifyPIN(t)
					sig, err := client.SignRSA(tc.alg, tc.slot, publicKey, digest, opts)
					if err != nil {
						t.Fatal(err)
					}
					verifyHardware(t, openssl, publicPEM, digest, sig, "-pkeyopt", "rsa_padding_mode:pkcs1", "-pkeyopt", "digest:"+hashName)
					maxSalt := (publicKey.N.BitLen()-1+7)/8 - hash.Size() - 2
					for _, salt := range []int{0, 1, hash.Size(), maxSalt} {
						t.Run(fmt.Sprintf("PSS-salt-%d", salt), func(t *testing.T) {
							pss := piv.RSAPSSOptions{Hash: hash, MGF1Hash: hash, SaltLength: salt}
							request, err := adapters.SigningRequestFromRSAOptions(tc.alg, publicKey, digest, pss)
							if err != nil {
								t.Fatal(err)
							}
							match(t, tc.slot, publicKey, request)
							verifyPIN(t)
							sig, err := client.SignRSA(tc.alg, tc.slot, publicKey, digest, pss)
							if err != nil {
								t.Fatal(err)
							}
							verifyHardware(t, openssl, publicPEM, digest, sig, "-pkeyopt", "rsa_padding_mode:pss", "-pkeyopt", "digest:"+hashName,
								"-pkeyopt", "rsa_mgf1_md:"+hashName, "-pkeyopt", fmt.Sprintf("rsa_pss_saltlen:%d", salt))
							if err := piv.VerifyRSA(publicKey, digest, sig, pss); err != nil {
								t.Fatalf("library exact verification: %v", err)
							}
						})
					}
				})
			}
			for _, payload := range [][]byte{nil, message, bytes.Repeat([]byte{0xA5}, publicKey.Size()-11)} {
				opts := piv.RSAPKCS1v15PayloadOptions{}
				request, err := adapters.SigningRequestFromRSAOptions(tc.alg, publicKey, payload, opts)
				if err != nil {
					t.Fatal(err)
				}
				match(t, tc.slot, publicKey, request)
				verifyPIN(t)
				sig, err := client.SignRSA(tc.alg, tc.slot, publicKey, payload, opts)
				if err != nil {
					t.Fatalf("exact payload length %d: %v", len(payload), err)
				}
				verifyHardware(t, openssl, publicPEM, payload, sig, "-pkeyopt", "rsa_padding_mode:pkcs1")
			}
			t.Logf("qualified algorithm=%02X slot=%s", tc.alg, tc.slot)
		})
	}
	for _, tc := range []struct {
		name string
		alg  byte
		slot piv.Slot
	}{
		{"P256-key-management", piv.AlgECCP256, piv.SlotKeyManagement},
		{"P384-card-authentication", piv.AlgECCP384, piv.SlotCardAuth},
		{"P256-retired-last", piv.AlgECCP256, 0x95},
		{"Ed25519", piv.AlgEd25519, piv.SlotSignature},
		{"MLDSA44", piv.AlgMLDSA44, piv.SlotSignature},
		{"MLDSA65", piv.AlgMLDSA65, piv.SlotSignature},
		{"MLDSA87", piv.AlgMLDSA87, piv.SlotSignature},
	} {
		t.Run(tc.name, func(t *testing.T) {
			publicKey := generate(t, tc.slot, tc.alg)
			publicPEM := hardwarePublicPEM(t, publicKey)
			if tc.alg == piv.AlgECCP256 || tc.alg == piv.AlgECCP384 {
				for _, hash := range []crypto.Hash{crypto.SHA256, crypto.SHA384, crypto.SHA512} {
					digest, name := hardwareDigest(hash, message)
					match(t, tc.slot, publicKey, adapters.SigningRequest{Parameters: adapters.SigningParameters{Scheme: adapters.SigningECDSA, Input: adapters.SigningInputDigest, Hash: hash, Context: adapters.SigningContextAbsent}, InputLength: len(digest)})
					verifyPIN(t)
					sig, err := client.SignECDSA(tc.alg, tc.slot, publicKey.(*ecdsa.PublicKey), digest)
					if err != nil {
						t.Fatalf("ECDSA %s: %v", name, err)
					}
					verifyHardware(t, openssl, publicPEM, digest, sig, "-pkeyopt", "digest:"+name)
				}
			} else {
				scheme := adapters.SigningEdDSA
				if piv.IsMLDSAAlgorithm(tc.alg) {
					scheme = adapters.SigningMLDSA
				}
				for _, input := range [][]byte{nil, message, bytes.Repeat([]byte{0xA5}, 32), bytes.Repeat([]byte{0x5A}, 4096)} {
					match(t, tc.slot, publicKey, adapters.SigningRequest{Parameters: adapters.SigningParameters{Scheme: scheme, Input: adapters.SigningInputMessage, Mode: adapters.SigningModePure, Context: adapters.SigningContextAbsent}, InputLength: len(input)})
					verifyPIN(t)
					var sig []byte
					var err error
					if piv.IsMLDSAAlgorithm(tc.alg) {
						signer, signerErr := piv.NewMLDSASigner(client, tc.slot, tc.alg, publicKey.(*piv.OpaquePublicKey))
						if signerErr != nil {
							t.Fatal(signerErr)
						}
						sig, err = signer.Sign(nil, input, crypto.Hash(0))
					} else {
						sig, err = client.Sign(tc.alg, tc.slot, input, piv.RSASignHashNone)
					}
					if err != nil {
						t.Fatal(err)
					}
					verifyHardware(t, openssl, publicPEM, input, sig, "-rawin")
				}
			}
			t.Logf("qualified algorithm=%02X slot=%s", tc.alg, tc.slot)
		})
	}
}

// TestYubiKeyPreviewIdentityReadOnly exercises the same direct serial guard
// used before reset, without authentication, signing or any mutation.
func TestYubiKeyPreviewIdentityReadOnly(t *testing.T) {
	if os.Getenv("PIV_TEST_IDENTITY_READ_ONLY") != "1" {
		t.Skip("set PIV_TEST_IDENTITY_READ_ONLY=1 to inspect the preview device")
	}
	reader, serial := os.Getenv("PIV_TEST_READER"), os.Getenv("PIV_TEST_SERIAL")
	model, firmware := os.Getenv("PIV_TEST_MODEL"), os.Getenv("PIV_TEST_DEVICE_FIRMWARE")
	if reader == "" || serial == "" || model != "YubiKey 5C NFC - Enhanced PIN" || firmware != "6.0.0.alpha.8" {
		t.Fatal("explicit reader, serial, model and device firmware for the preview card are required")
	}
	device := inventoryYubiKey(t, "--device", serial, serial, model, firmware)
	ctx, err := pcsc.NewContext()
	if err != nil {
		t.Fatal(err)
	}
	defer ctx.Release()
	card, err := ctx.Connect(reader)
	if err != nil {
		t.Fatal(err)
	}
	defer card.Close()
	if err := card.Begin(); err != nil {
		t.Fatal(err)
	}
	defer card.End()
	client := piv.NewClient(card)
	if err := client.Select(); err != nil {
		t.Fatal(err)
	}
	requireDirectPIVSerial(t, client, serial)
	session := adapters.NewSession(client, adapters.WithReaderName(reader))
	device.PIVVersion, err = yubikey.NewAdapter().PIVVersion(session)
	if err != nil || device.PIVVersion != "0.0.1" {
		t.Fatalf("unexpected PIV applet version %q: %v", device.PIVVersion, err)
	}
	t.Logf("model=%s device firmware=%s PIV applet=%s direct PIV serial matched", device.Model, device.Firmware, device.PIVVersion)
}

// requireDirectPIVSerial does not use the adapter's OTP fallback, so it cannot
// switch applets within an active PIV transaction. Call after PIV SELECT.
func requireDirectPIVSerial(t *testing.T, client *piv.Client, serial string) {
	t.Helper()
	response, err := client.Execute(&iso7816.Command{Cla: 0x00, Ins: 0xF8, Le: 0x00})
	if err != nil {
		t.Fatal(err)
	}
	if err := response.Err(); err != nil || len(response.Data) != 4 {
		t.Fatalf("direct PIV GET SERIAL unavailable: %v", err)
	}
	var got uint64
	for _, b := range response.Data {
		got = got<<8 | uint64(b)
	}
	if fmt.Sprint(got) != serial {
		t.Fatal("direct PIV serial does not match selected device")
	}
}

// TestYubiKeyLegacySigningEvidence is read-only. It verifies that a useful
// static device report cannot turn metadata-blind private-key state into support.
func TestYubiKeyLegacySigningEvidence(t *testing.T) {
	if os.Getenv("PIV_TEST_LEGACY_READ_ONLY") != "1" {
		t.Skip("set PIV_TEST_LEGACY_READ_ONLY=1 to inspect a selected legacy card")
	}
	reader, serial := os.Getenv("PIV_TEST_READER"), os.Getenv("PIV_TEST_SERIAL")
	model, firmware := os.Getenv("PIV_TEST_MODEL"), os.Getenv("PIV_TEST_DEVICE_FIRMWARE")
	if reader == "" || serial == "" || model != "YubiKey NEO" || firmware != "3.4.9" {
		t.Fatal("explicit reader, serial, model and device firmware for the NEO are required")
	}
	device := inventoryYubiKey(t, "--reader", reader, serial, model, firmware)
	ctx, err := pcsc.NewContext()
	if err != nil {
		t.Fatal(err)
	}
	defer ctx.Release()
	card, err := ctx.Connect(reader)
	if err != nil {
		t.Fatal(err)
	}
	defer card.Close()
	if err := card.Begin(); err != nil {
		t.Fatal(err)
	}
	defer card.End()
	client := piv.NewClient(card)
	if err := client.Select(); err != nil {
		t.Fatal(err)
	}
	adapter := yubikey.NewAdapter()
	session := adapters.NewSession(client, adapters.WithReaderName(reader))
	device.PIVVersion, err = adapter.PIVVersion(session)
	if err != nil || device.PIVVersion != "1.0.4" {
		t.Fatalf("unexpected PIV applet version %q: %v", device.PIVVersion, err)
	}
	report := adapter.SigningCapabilities(device)
	var staticProfile bool
	for _, profile := range report.Profiles {
		if profile.Key.Family == adapters.SigningKeyEC && profile.Key.CurveOID == adapters.SigningCurveP256 && profile.Parameters.Scheme == adapters.SigningECDSA && profile.Parameters.Hash == crypto.SHA256 && profile.Support == adapters.SigningSupported {
			staticProfile = true
		}
	}
	if !staticProfile {
		t.Fatal("expected independently documented P-256/SHA-256 device profile")
	}
	description, err := adapter.DescribeSlot(session, piv.SlotAuthentication)
	if err != nil {
		t.Fatal(err)
	}
	evidence, err := adapters.SigningKeyEvidenceFromSlot(piv.SlotAuthentication, description, true)
	if err != nil {
		t.Fatal(err)
	}
	request := adapters.SigningRequest{Parameters: adapters.SigningParameters{Scheme: adapters.SigningECDSA, Input: adapters.SigningInputDigest, Hash: crypto.SHA256, Context: adapters.SigningContextAbsent}, InputLength: sha256.Size}
	decision := adapters.MatchSigningCapability(report, evidence, request)
	if decision.Support != adapters.SigningUnknown || decision.Reason != adapters.SigningReasonKeyUnknown {
		t.Fatalf("metadata-blind slot must remain unknown, got %+v", decision)
	}
	t.Logf("model=%s device firmware=%s PIV applet=%s static profiles=%d slot decision=%s/%s", device.Model, device.Firmware, device.PIVVersion, len(report.Profiles), decision.Support, decision.Reason)
}

// inventoryYubiKey explicitly invokes vendor inventory before opening a PIV
// session. Environment values select an expected device, but are not evidence.
func inventoryYubiKey(t *testing.T, selector, target, serial, model, firmware string) adapters.SigningDevice {
	t.Helper()
	ykman := os.Getenv("PIV_TEST_YKMAN")
	if ykman == "" {
		ykman = "ykman"
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, ykman, selector, target, "info").Output()
	if err != nil {
		t.Fatalf("passive device inventory failed: %v", err)
	}
	fields := map[string]string{}
	for _, line := range strings.Split(string(out), "\n") {
		if name, value, ok := strings.Cut(line, ":"); ok {
			switch name {
			case "Device type", "Serial number", "Firmware version":
				if _, exists := fields[name]; exists {
					t.Fatalf("passive inventory contains duplicate %s", name)
				}
				fields[name] = strings.TrimSpace(value)
			}
		}
	}
	if fields["Serial number"] != serial || fields["Device type"] != model || fields["Firmware version"] != firmware {
		t.Fatal("passive inventory does not match selected serial, model and device firmware; refusing reset")
	}
	return adapters.SigningDevice{Model: fields["Device type"], Firmware: fields["Firmware version"], Evidence: []adapters.SigningEvidence{{Source: "ykman info", Reference: "passive device inventory", ObservedAt: time.Now()}}}
}

func hardwareDigest(hash crypto.Hash, input []byte) ([]byte, string) {
	switch hash {
	case crypto.SHA256:
		d := sha256.Sum256(input)
		return d[:], "sha256"
	case crypto.SHA384:
		d := sha512.Sum384(input)
		return d[:], "sha384"
	default:
		d := sha512.Sum512(input)
		return d[:], "sha512"
	}
}

func hardwarePublicPEM(t *testing.T, key crypto.PublicKey) []byte {
	t.Helper()
	var der []byte
	var err error
	if opaque, ok := key.(*piv.OpaquePublicKey); ok {
		if piv.IsMLDSAAlgorithm(opaque.Algorithm) {
			der, err = piv.MarshalMLDSAPKIXPublicKey(opaque)
		} else if opaque.Algorithm == piv.AlgEd25519 {
			der, err = x509.MarshalPKIXPublicKey(ed25519.PublicKey(opaque.Raw))
		} else {
			t.Fatalf("unsupported opaque public key %02X", opaque.Algorithm)
		}
	} else {
		der, err = x509.MarshalPKIXPublicKey(key)
	}
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
}

func verifyHardware(t *testing.T, openssl string, publicPEM, input, signature []byte, options ...string) {
	t.Helper()
	dir := t.TempDir()
	for name, data := range map[string][]byte{"public.pem": publicPEM, "input": input, "signature": signature} {
		if err := os.WriteFile(filepath.Join(dir, name), data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	args := []string{"pkeyutl", "-verify", "-pubin", "-inkey", filepath.Join(dir, "public.pem"), "-in", filepath.Join(dir, "input"), "-sigfile", filepath.Join(dir, "signature")}
	if len(options) == 2 && options[0] == "-pkeyopt" && options[1] == "rsa_padding_mode:pkcs1" {
		// Exact payloads need no DigestInfo interpretation. Recover the
		// payload with OpenSSL and compare its complete bytes, including an
		// empty payload (which OpenSSL's PKCS#1 provider rejects as zero
		// recovered bytes). For that boundary, inspect the raw representative.
		recovered := filepath.Join(dir, "recovered")
		padding := "pkcs1"
		if len(input) == 0 {
			padding = "none"
		}
		runOpenSSL(t, openssl, "pkeyutl", "-verifyrecover", "-pubin", "-inkey", filepath.Join(dir, "public.pem"),
			"-in", filepath.Join(dir, "signature"), "-out", recovered, "-pkeyopt", "rsa_padding_mode:"+padding)
		got, err := os.ReadFile(recovered)
		want := input
		if len(input) == 0 {
			want = bytes.Repeat([]byte{0xFF}, len(signature))
			want[0], want[1], want[len(want)-1] = 0, 1, 0
		}
		if err != nil || !bytes.Equal(got, want) {
			t.Fatalf("OpenSSL recovered payload differs: %v", err)
		}
		return
	}
	if len(input) == 0 && len(options) == 1 && options[0] == "-rawin" {
		// pkeyutl cannot allocate a zero-length one-shot buffer even though
		// EVP supports empty messages. Use the same OpenSSL installation.
		binary, err := exec.LookPath(openssl)
		if err != nil {
			t.Fatal(err)
		}
		binary, err = filepath.EvalSymlinks(binary)
		if err != nil {
			t.Fatal(err)
		}
		prefix := filepath.Dir(filepath.Dir(binary))
		verifier := filepath.Join(dir, "verify-empty")
		runOpenSSL(t, "cc", "testdata/verify_empty.c", "-o", verifier,
			"-I"+filepath.Join(prefix, "include"), "-L"+filepath.Join(prefix, "lib"),
			"-Wl,-rpath,"+filepath.Join(prefix, "lib"), "-lcrypto")
		version := runOpenSSL(t, verifier, filepath.Join(dir, "public.pem"), filepath.Join(dir, "signature"))
		selectedVersion := runOpenSSL(t, openssl, "version")
		if index := strings.Index(selectedVersion, "(Library: "); index >= 0 {
			selectedVersion = strings.TrimSuffix(selectedVersion[index+len("(Library: "):], ")")
		}
		if version != selectedVersion {
			t.Fatalf("empty-message verification used %q, selected OpenSSL runtime is %q", version, selectedVersion)
		}
		return
	}
	runOpenSSL(t, openssl, append(args, options...)...)
}

func runOpenSSL(t *testing.T, openssl string, args ...string) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, openssl, args...).CombinedOutput()
	if err != nil {
		t.Fatalf("OpenSSL %v: %v\n%s", args, err, out)
	}
	return strings.TrimSpace(string(out))
}
