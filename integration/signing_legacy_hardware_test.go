//go:build hardware

package integration_test

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"fmt"
	"os"
	"testing"

	"github.com/PeculiarVentures/piv-go/adapters"
	"github.com/PeculiarVentures/piv-go/adapters/yubikey"
	"github.com/PeculiarVentures/piv-go/pcsc"
	"github.com/PeculiarVentures/piv-go/piv"
)

// TestYubiKeyProductionSigningOpenSSL resets one explicitly selected test PIV
// application. The opt-in, exact device identity, separate pre-session vendor
// inventory, and (where supported) direct PIV serial read precede every reset.
func TestYubiKeyProductionSigningOpenSSL(t *testing.T) {
	if os.Getenv("PIV_TEST_ALLOW_RESET") != "1" {
		t.Skip("set PIV_TEST_ALLOW_RESET=1 to reset a dedicated test card")
	}
	reader, serial := os.Getenv("PIV_TEST_READER"), os.Getenv("PIV_TEST_SERIAL")
	model, fw := os.Getenv("PIV_TEST_MODEL"), os.Getenv("PIV_TEST_DEVICE_FIRMWARE")
	if reader == "" || serial == "" {
		t.Fatal("reader and serial are required")
	}
	legacy := model == "YubiKey NEO" && fw == "3.4.9"
	modern := model == "YubiKey 5C NFC" && fw == "5.4.3"
	if !legacy && !modern {
		t.Fatal("this test matrix requires the specified NEO or 5C NFC firmware")
	}
	// The reader-bound vendor inventory is deliberately outside the PIV
	// transaction. In particular, NEO cannot supply PIV GET SERIAL and its
	// separate inventory may use another applet; no hidden applet switch occurs
	// inside the PIV transaction.
	device := inventoryYubiKey(t, "--reader", reader, serial, model, fw)
	openssl := os.Getenv("PIV_TEST_OPENSSL")
	if openssl == "" {
		openssl = "openssl"
	}
	version := runOpenSSL(t, openssl, "version")
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
	if modern {
		requireDirectPIVSerial(t, client, serial)
	}
	device.PIVVersion, err = adapter.PIVVersion(session)
	if err != nil {
		t.Fatal(err)
	}
	if (legacy && device.PIVVersion != "1.0.4") || (modern && device.PIVVersion != "5.4.3") {
		t.Fatal("unexpected PIV applet version; refusing reset")
	}
	report := adapter.SigningCapabilities(device)
	if len(report.Profiles) == 0 {
		t.Fatal("expected documented device profiles")
	}
	t.Logf("model=%s device firmware=%s PIV applet=%s verifier=%s", model, fw, device.PIVVersion, version)
	if err := adapter.ResetToken(session, adapters.ResetTokenParams{}); err != nil {
		t.Fatalf("reset PIV application: %v", err)
	}
	mgm := bytes.Repeat([]byte{1, 2, 3, 4, 5, 6, 7, 8}, 3)
	generate := func(t *testing.T, slot piv.Slot, alg byte) crypto.PublicKey {
		t.Helper()
		if err := client.AuthenticateManagementKeyWithAlgorithm(piv.Alg3DES, mgm); err != nil {
			t.Fatal(err)
		}
		key, err := client.GenerateKeyPair(slot, alg)
		if err != nil {
			t.Fatalf("generate %02X: %v", alg, err)
		}
		return key
	}
	match := func(t *testing.T, slot piv.Slot, key crypto.PublicKey, request adapters.SigningRequest) {
		t.Helper()
		desc, err := adapter.DescribeSlot(session, slot)
		if err != nil {
			t.Fatal(err)
		}
		evidence, err := adapters.SigningKeyEvidenceFromSlot(slot, desc, true)
		if err != nil {
			t.Fatal(err)
		}
		d := adapters.MatchSigningCapability(report, evidence, request)
		if legacy {
			if d.Support != adapters.SigningUnknown || d.Reason != adapters.SigningReasonKeyUnknown {
				t.Fatalf("legacy metadata decision: %+v", d)
			}
			return
		}
		if desc.PublicKeySource != adapters.PublicKeySourceMetadata || desc.PublicKey == nil || !bytes.Equal(hardwarePublicPEM(t, key), hardwarePublicPEM(t, desc.PublicKey)) {
			t.Fatal("current metadata does not match generated public key")
		}
		if d.Support != adapters.SigningSupported || d.ProfileID == "" {
			t.Fatalf("no matching supported profile: %+v", d)
		}
	}
	verifyPIN := func(t *testing.T) {
		t.Helper()
		if err := client.VerifyPIN("123456"); err != nil {
			t.Fatal(err)
		}
	}
	message := []byte("piv-go hardware qualification: exact scheme parameters")
	t.Run("RSA2048", func(t *testing.T) {
		key := generate(t, piv.SlotAuthentication, piv.AlgRSA2048).(*rsa.PublicKey)
		pem := hardwarePublicPEM(t, key)
		for _, hash := range []crypto.Hash{crypto.SHA256, crypto.SHA384, crypto.SHA512} {
			digest, name := hardwareDigest(hash, message)
			opts := piv.RSAPKCS1v15DigestOptions{Hash: hash}
			req, err := adapters.SigningRequestFromRSAOptions(piv.AlgRSA2048, key, digest, opts)
			if err != nil {
				t.Fatal(err)
			}
			match(t, piv.SlotAuthentication, key, req)
			verifyPIN(t)
			sig, err := client.SignRSA(piv.AlgRSA2048, piv.SlotAuthentication, key, digest, opts)
			if err != nil {
				t.Fatal(err)
			}
			verifyHardware(t, openssl, pem, digest, sig, "-pkeyopt", "rsa_padding_mode:pkcs1", "-pkeyopt", "digest:"+name)
			maxSalt := (key.N.BitLen()-1+7)/8 - hash.Size() - 2
			for _, salt := range []int{0, 1, hash.Size(), maxSalt} {
				pss := piv.RSAPSSOptions{Hash: hash, MGF1Hash: hash, SaltLength: salt}
				req, err := adapters.SigningRequestFromRSAOptions(piv.AlgRSA2048, key, digest, pss)
				if err != nil {
					t.Fatal(err)
				}
				match(t, piv.SlotAuthentication, key, req)
				verifyPIN(t)
				sig, err := client.SignRSA(piv.AlgRSA2048, piv.SlotAuthentication, key, digest, pss)
				if err != nil {
					t.Fatal(err)
				}
				verifyHardware(t, openssl, pem, digest, sig, "-pkeyopt", "rsa_padding_mode:pss", "-pkeyopt", "digest:"+name, "-pkeyopt", "rsa_mgf1_md:"+name, "-pkeyopt", fmt.Sprintf("rsa_pss_saltlen:%d", salt))
			}
		}
		for _, payload := range [][]byte{nil, message, bytes.Repeat([]byte{0xa5}, key.Size()-11)} {
			opts := piv.RSAPKCS1v15PayloadOptions{}
			req, err := adapters.SigningRequestFromRSAOptions(piv.AlgRSA2048, key, payload, opts)
			if err != nil {
				t.Fatal(err)
			}
			match(t, piv.SlotAuthentication, key, req)
			verifyPIN(t)
			sig, err := client.SignRSA(piv.AlgRSA2048, piv.SlotAuthentication, key, payload, opts)
			if err != nil {
				t.Fatal(err)
			}
			verifyHardware(t, openssl, pem, payload, sig, "-pkeyopt", "rsa_padding_mode:pkcs1")
		}
		t.Log("RSA 2048 PKCS#1 digest and payload; PSS exact salt matrix verified")
	})
	tests := []struct {
		name      string
		slot      piv.Slot
		algorithm byte
	}{{"P256", piv.SlotSignature, piv.AlgECCP256}}
	if modern {
		tests = append(tests, struct {
			name      string
			slot      piv.Slot
			algorithm byte
		}{"P384", piv.SlotKeyManagement, piv.AlgECCP384})
	} else {
		t.Log("P-384 and RSA >2048 have no NEO device profile; not tested")
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			key := generate(t, tc.slot, tc.algorithm).(*ecdsa.PublicKey)
			pem := hardwarePublicPEM(t, key)
			for _, hash := range []crypto.Hash{crypto.SHA256, crypto.SHA384, crypto.SHA512} {
				digest, name := hardwareDigest(hash, message)
				if err := piv.ValidateECDSASignRequest(tc.algorithm, key, digest); err != nil {
					t.Fatal(err)
				}
				req := adapters.SigningRequest{Parameters: adapters.SigningParameters{Scheme: adapters.SigningECDSA, Input: adapters.SigningInputDigest, Hash: hash, Context: adapters.SigningContextAbsent}, InputLength: len(digest)}
				match(t, tc.slot, key, req)
				verifyPIN(t)
				sig, err := client.SignECDSA(tc.algorithm, tc.slot, key, digest)
				if err != nil {
					t.Fatal(err)
				}
				verifyHardware(t, openssl, pem, digest, sig, "-pkeyopt", "digest:"+name)
			}
			t.Log("ECDSA SHA-256, SHA-384, SHA-512 verified")
		})
	}
}
