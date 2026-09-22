package piv

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"math/big"
	"strings"
	"testing"

	"github.com/PeculiarVentures/piv-go/emulator"
	"github.com/PeculiarVentures/piv-go/iso7816"
)

func mustParseCommand(t *testing.T, raw []byte) *iso7816.Command {
	t.Helper()
	cmd, err := iso7816.ParseCommand(raw)
	if err != nil {
		t.Fatalf("parse command: %v", err)
	}
	return cmd
}

func assertGenerateCommand(t *testing.T, raw []byte, slot Slot, algorithm byte, pinPolicy byte, touchPolicy byte) {
	t.Helper()
	cmd := mustParseCommand(t, raw)
	if cmd.Cla != 0x00 || cmd.Ins != 0x47 || cmd.P1 != 0x00 || cmd.P2 != byte(slot) {
		t.Fatalf("generate header = %02X %02X %02X %02X, want 00 47 00 %02X", cmd.Cla, cmd.Ins, cmd.P1, cmd.P2, byte(slot))
	}
	if cmd.Le != 256 {
		t.Fatalf("generate Le = %d, want 256", cmd.Le)
	}
	outer, err := iso7816.ParseAllTLV(cmd.Data)
	if err != nil {
		t.Fatalf("parse outer: %v", err)
	}
	ac := iso7816.FindTag(outer, 0xAC)
	if ac == nil {
		t.Fatalf("control reference 0xAC not found in %X", cmd.Data)
	}
	inner, err := iso7816.ParseAllTLV(ac.Value)
	if err != nil {
		t.Fatalf("parse AC: %v", err)
	}
	alg := iso7816.FindTag(inner, 0x80)
	if alg == nil || len(alg.Value) != 1 || alg.Value[0] != algorithm {
		t.Fatalf("algorithm tag 0x80 missing or wrong in %X", ac.Value)
	}
	pin := iso7816.FindTag(inner, TagPinPolicy)
	if pinPolicy == PinPolicyDefault {
		if pin != nil {
			t.Fatalf("PIN tag must be omitted for default, got %X", ac.Value)
		}
	} else if pin == nil || len(pin.Value) != 1 || pin.Value[0] != pinPolicy {
		t.Fatalf("PIN tag wrong in %X", ac.Value)
	}
	touch := iso7816.FindTag(inner, TagTouchPolicy)
	if touchPolicy == TouchPolicyDefault {
		if touch != nil {
			t.Fatalf("touch tag must be omitted for default, got %X", ac.Value)
		}
	} else if touch == nil || len(touch.Value) != 1 || touch.Value[0] != touchPolicy {
		t.Fatalf("touch tag wrong in %X", ac.Value)
	}
}

func TestClient_GenerateKeyPairPQC(t *testing.T) {
	tests := []struct {
		name      string
		algorithm byte
		response  []byte
	}{
		{
			name:      "rsa3072",
			algorithm: AlgRSA3072,
			response: iso7816.EncodeTLV(0x7F49, append(
				iso7816.EncodeTLV(0x81, append([]byte{0x80}, bytes.Repeat([]byte{0x55}, 383)...)),
				iso7816.EncodeTLV(0x82, []byte{0x01, 0x00, 0x01})...,
			)),
		},
		{
			name:      "rsa4096",
			algorithm: AlgRSA4096,
			response: iso7816.EncodeTLV(0x7F49, append(
				iso7816.EncodeTLV(0x81, append([]byte{0x80}, bytes.Repeat([]byte{0x56}, 511)...)),
				iso7816.EncodeTLV(0x82, []byte{0x01, 0x00, 0x01})...,
			)),
		},
		{name: "ed25519", algorithm: AlgEd25519, response: iso7816.EncodeTLV(0x7F49, iso7816.EncodeTLV(0x86, bytes.Repeat([]byte{0x41}, 32)))},
		{name: "x25519", algorithm: AlgX25519, response: iso7816.EncodeTLV(0x7F49, iso7816.EncodeTLV(0x86, bytes.Repeat([]byte{0x42}, 32)))},
		{name: "mldsa44", algorithm: AlgMLDSA44, response: iso7816.EncodeTLV(0x7F49, iso7816.EncodeTLV(0x87, bytes.Repeat([]byte{0x43}, 1312)))},
		{name: "mldsa65", algorithm: AlgMLDSA65, response: iso7816.EncodeTLV(0x7F49, iso7816.EncodeTLV(0x87, bytes.Repeat([]byte{0x44}, 1952)))},
		{name: "mldsa87", algorithm: AlgMLDSA87, response: iso7816.EncodeTLV(0x7F49, iso7816.EncodeTLV(0x87, bytes.Repeat([]byte{0x45}, 2592)))},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			mock := emulator.NewCard()
			mock.SetSuccessResponse(0x47, test.response)
			key, err := NewClient(mock).GenerateKeyPairWithPolicies(SlotSignature, test.algorithm, PinPolicyOnce, TouchPolicyAlways)
			if err != nil {
				t.Fatalf("GenerateKeyPairWithPolicies() error = %v", err)
			}
			if key == nil {
				t.Fatal("expected non-nil public key")
			}
			if len(mock.TransmittedCommands) != 1 {
				t.Fatalf("expected 1 command, got %d", len(mock.TransmittedCommands))
			}
			assertGenerateCommand(t, mock.TransmittedCommands[0], SlotSignature, test.algorithm, PinPolicyOnce, TouchPolicyAlways)
			// Default policies omit AA/AB and stay byte-compatible.
			legacy := emulator.NewCard()
			legacy.SetSuccessResponse(0x47, test.response)
			if _, err := NewClient(legacy).GenerateKeyPair(SlotSignature, test.algorithm); err != nil {
				t.Fatalf("GenerateKeyPair() error = %v", err)
			}
			assertGenerateCommand(t, legacy.TransmittedCommands[0], SlotSignature, test.algorithm, PinPolicyDefault, TouchPolicyDefault)
		})
	}
}

func syntheticRSAKeyForImport(t *testing.T, bits int) *rsa.PrivateKey {
	t.Helper()
	halfBytes := bits / 16
	for attempts := 0; attempts < 200; attempts++ {
		pBytes := make([]byte, halfBytes)
		qBytes := make([]byte, halfBytes)
		if _, err := rand.Read(pBytes); err != nil {
			t.Fatal(err)
		}
		if _, err := rand.Read(qBytes); err != nil {
			t.Fatal(err)
		}
		pBytes[0] |= 0x80
		qBytes[0] |= 0x80
		pBytes[len(pBytes)-1] |= 0x01
		qBytes[len(qBytes)-1] |= 0x01
		p := new(big.Int).SetBytes(pBytes)
		q := new(big.Int).SetBytes(qBytes)
		if p.Cmp(q) == 0 {
			continue
		}
		n := new(big.Int).Mul(p, q)
		if n.BitLen() != bits {
			continue
		}
		key := &rsa.PrivateKey{PublicKey: rsa.PublicKey{N: n, E: 65537}, D: new(big.Int).SetBytes(append(append([]byte{}, pBytes...), qBytes...)), Primes: []*big.Int{p, q}}
		// Bypass rsa.Precompute validation (our primes are random odd
		// values, not a real key): derive the CRT halves directly.
		one := big.NewInt(1)
		key.Precomputed.Dp = new(big.Int).Mod(key.D, new(big.Int).Sub(p, one))
		key.Precomputed.Dq = new(big.Int).Mod(key.D, new(big.Int).Sub(q, one))
		key.Precomputed.Qinv = new(big.Int).ModInverse(q, p)
		if key.Precomputed.Qinv == nil {
			continue
		}
		return key
	}
	t.Fatalf("unable to synthesize %d-bit RSA key", bits)
	return nil
}

func assertImportCommand(t *testing.T, raw []byte, slot Slot, algorithm byte, tags map[uint]int) {
	t.Helper()
	cmd := mustParseCommand(t, raw)
	if cmd.Cla != 0x00 || cmd.Ins != InsImportKey || cmd.P1 != algorithm || cmd.P2 != byte(slot) {
		t.Fatalf("import header = %02X %02X %02X %02X, want 00 FE %02X %02X", cmd.Cla, cmd.Ins, cmd.P1, cmd.P2, algorithm, byte(slot))
	}
	tlvs, err := iso7816.ParseAllTLV(cmd.Data)
	if err != nil {
		t.Fatalf("parse import payload: %v", err)
	}
	for tag, wantLen := range tags {
		field := iso7816.FindTag(tlvs, tag)
		if field == nil {
			t.Fatalf("expected import tag 0x%02X", tag)
		}
		if len(field.Value) != wantLen {
			t.Fatalf("tag 0x%02X: expected %d bytes, got %d", tag, wantLen, len(field.Value))
		}
	}
}

func TestClient_ImportKeyPQC(t *testing.T) {
	t.Run("rsa3072 halves 192", func(t *testing.T) {
		key := syntheticRSAKeyForImport(t, 3072)
		mock := emulator.NewCard()
		mock.SetSuccessResponse(InsImportKey, nil)
		if err := NewClient(mock).ImportKey(SlotKeyManagement, AlgRSA3072, key, PinPolicyDefault, TouchPolicyDefault); err != nil {
			t.Fatalf("ImportKey() error = %v", err)
		}
		assertImportCommand(t, mock.TransmittedCommands[0], SlotKeyManagement, AlgRSA3072,
			map[uint]int{0x01: 192, 0x02: 192, 0x03: 192, 0x04: 192, 0x05: 192})
	})
	t.Run("rsa4096 halves 256", func(t *testing.T) {
		key := syntheticRSAKeyForImport(t, 4096)
		mock := emulator.NewCard()
		mock.SetSuccessResponse(InsImportKey, nil)
		if err := NewClient(mock).ImportKey(SlotKeyManagement, AlgRSA4096, key, PinPolicyDefault, TouchPolicyDefault); err != nil {
			t.Fatalf("ImportKey() error = %v", err)
		}
		assertImportCommand(t, mock.TransmittedCommands[0], SlotKeyManagement, AlgRSA4096,
			map[uint]int{0x01: 256, 0x02: 256, 0x03: 256, 0x04: 256, 0x05: 256})
	})
	t.Run("ed25519 tag 07", func(t *testing.T) {
		seed := bytes.Repeat([]byte{0xAB}, 32)
		mock := emulator.NewCard()
		mock.SetSuccessResponse(InsImportKey, nil)
		if err := NewClient(mock).ImportKey(SlotSignature, AlgEd25519, &OpaquePrivateKey{Algorithm: AlgEd25519, Raw: seed}, PinPolicyOnce, TouchPolicyDefault); err != nil {
			t.Fatalf("ImportKey() error = %v", err)
		}
		assertImportCommand(t, mock.TransmittedCommands[0], SlotSignature, AlgEd25519, map[uint]int{0x07: 32})
		cmd := mustParseCommand(t, mock.TransmittedCommands[0])
		tlvs, _ := iso7816.ParseAllTLV(cmd.Data)
		if pin := iso7816.FindTag(tlvs, TagPinPolicy); pin == nil || pin.Value[0] != PinPolicyOnce {
			t.Fatalf("PIN policy tag wrong in %X", cmd.Data)
		}
	})
	t.Run("x25519 tag 08 raw bytes", func(t *testing.T) {
		seed := bytes.Repeat([]byte{0xCD}, 32)
		mock := emulator.NewCard()
		mock.SetSuccessResponse(InsImportKey, nil)
		if err := NewClient(mock).ImportKey(SlotKeyManagement, AlgX25519, seed, PinPolicyDefault, TouchPolicyDefault); err != nil {
			t.Fatalf("ImportKey() error = %v", err)
		}
		assertImportCommand(t, mock.TransmittedCommands[0], SlotKeyManagement, AlgX25519, map[uint]int{0x08: 32})
	})
}

func assertSignCommand(t *testing.T, raw []byte, slot Slot, algorithm byte, msg []byte) {
	t.Helper()
	cmd := mustParseCommand(t, raw)
	if cmd.Cla != 0x00 || cmd.Ins != 0x87 || cmd.P1 != algorithm || cmd.P2 != byte(slot) {
		t.Fatalf("sign header = %02X %02X %02X %02X, want 00 87 %02X %02X", cmd.Cla, cmd.Ins, cmd.P1, cmd.P2, algorithm, byte(slot))
	}
	outer, err := iso7816.ParseAllTLV(cmd.Data)
	if err != nil {
		t.Fatalf("parse outer: %v", err)
	}
	auth := iso7816.FindTag(outer, 0x7C)
	if auth == nil {
		t.Fatalf("0x7C not found in %X", cmd.Data)
	}
	inner, err := iso7816.ParseAllTLV(auth.Value)
	if err != nil {
		t.Fatalf("parse inner: %v", err)
	}
	placeholder := iso7816.FindTag(inner, 0x82)
	if placeholder == nil || len(placeholder.Value) != 0 {
		t.Fatalf("0x82 placeholder must be empty in %X", auth.Value)
	}
	challenge := iso7816.FindTag(inner, 0x81)
	if challenge == nil || !bytes.Equal(challenge.Value, msg) {
		t.Fatalf("0x81 challenge mismatch in %X", auth.Value)
	}
}

func TestClient_SignPQC(t *testing.T) {
	tests := []struct {
		name      string
		algorithm byte
		sigLen    int
	}{
		{name: "ed25519", algorithm: AlgEd25519, sigLen: 64},
		{name: "mldsa44", algorithm: AlgMLDSA44, sigLen: 100},
		{name: "mldsa65", algorithm: AlgMLDSA65, sigLen: 100},
		{name: "mldsa87", algorithm: AlgMLDSA87, sigLen: 100},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			msg := []byte{0x01, 0x02, 0x03}
			sig := bytes.Repeat([]byte{0xEE}, test.sigLen)
			mock := emulator.NewCard()
			mock.SetSuccessResponse(0x87, iso7816.EncodeTLV(0x7C, iso7816.EncodeTLV(0x82, sig)))
			got, err := NewClient(mock).Sign(test.algorithm, SlotSignature, msg)
			if err != nil {
				t.Fatalf("Sign() error = %v", err)
			}
			if !bytes.Equal(got, sig) {
				t.Fatal("signature bytes must round-trip verbatim")
			}
			if len(mock.TransmittedCommands) != 1 {
				t.Fatalf("expected 1 command, got %d", len(mock.TransmittedCommands))
			}
			assertSignCommand(t, mock.TransmittedCommands[0], SlotSignature, test.algorithm, msg)
		})
	}
}

func signChallenge(t *testing.T, raw []byte) []byte {
	t.Helper()
	cmd := mustParseCommand(t, raw)
	outer, err := iso7816.ParseAllTLV(cmd.Data)
	if err != nil {
		t.Fatalf("parse outer: %v", err)
	}
	auth := iso7816.FindTag(outer, 0x7C)
	inner, err := iso7816.ParseAllTLV(auth.Value)
	if err != nil {
		t.Fatalf("parse inner: %v", err)
	}
	challenge := iso7816.FindTag(inner, 0x81)
	if challenge == nil {
		t.Fatalf("0x81 not found in %X", auth.Value)
	}
	return challenge.Value
}

func assertPKCS1v15Block(t *testing.T, em []byte, k int, suffix []byte) {
	t.Helper()
	if len(em) != k {
		t.Fatalf("padded block length = %d, want %d", len(em), k)
	}
	if em[0] != 0x00 || em[1] != 0x01 {
		t.Fatalf("block must start 00 01, got %X", em[:2])
	}
	if !bytes.Equal(em[k-len(suffix):], suffix) {
		t.Fatal("block suffix mismatch")
	}
	if em[k-len(suffix)-1] != 0x00 {
		t.Fatal("block separator 00 missing")
	}
	for _, b := range em[2 : k-len(suffix)-1] {
		if b != 0xFF {
			t.Fatalf("padding bytes must be FF, got %X", em)
		}
	}
}

func TestClient_SignExtendedRSAPadding(t *testing.T) {
	// F3: YubiKey 6 performs the raw RSA private-key operation for
	// RSA-3072/4096, so the host formats the challenge to exactly
	// modulus length. A 32-byte message is DigestInfo-wrapped (CLI --hash
	// sha256); shorter messages are type-1 padded raw (CLI --hash none).
	digest := bytes.Repeat([]byte{0x5A}, 32)
	for _, test := range []struct {
		algorithm byte
		k         int
		sigLen    int
	}{
		{algorithm: AlgRSA3072, k: 384, sigLen: 384},
		{algorithm: AlgRSA4096, k: 512, sigLen: 512},
	} {
		t.Run("digest", func(t *testing.T) {
			mock := emulator.NewCard()
			mock.SetSuccessResponse(0x87, iso7816.EncodeTLV(0x7C, iso7816.EncodeTLV(0x82, bytes.Repeat([]byte{0xEE}, test.sigLen))))
			if _, err := NewClient(mock).Sign(test.algorithm, SlotSignature, digest); err != nil {
				t.Fatalf("Sign() error = %v", err)
			}
			challenge := signChallenge(t, mock.TransmittedCommands[0])
			wantSuffix := append(append([]byte(nil), sha256DigestInfoPrefix...), digest...)
			assertPKCS1v15Block(t, challenge, test.k, wantSuffix)
		})
		t.Run("raw", func(t *testing.T) {
			msg := []byte{0x01, 0x02, 0x03}
			mock := emulator.NewCard()
			mock.SetSuccessResponse(0x87, iso7816.EncodeTLV(0x7C, iso7816.EncodeTLV(0x82, bytes.Repeat([]byte{0xEE}, test.sigLen))))
			if _, err := NewClient(mock).Sign(test.algorithm, SlotSignature, msg); err != nil {
				t.Fatalf("Sign() error = %v", err)
			}
			challenge := signChallenge(t, mock.TransmittedCommands[0])
			assertPKCS1v15Block(t, challenge, test.k, msg)
		})
	}
	// Oversize messages reject before any APDU.
	mock := emulator.NewCard()
	if _, err := NewClient(mock).Sign(AlgRSA3072, SlotSignature, bytes.Repeat([]byte{0x01}, 400)); err == nil || !strings.Contains(err.Error(), "too long") {
		t.Fatalf("expected too-long error, got %v", err)
	}
	if len(mock.TransmittedCommands) != 0 {
		t.Fatalf("no APDU must be sent for oversize message, got %d", len(mock.TransmittedCommands))
	}
}

func TestClient_CalculateSecret(t *testing.T) {
	peer := bytes.Repeat([]byte{0x11}, 32)
	secret := bytes.Repeat([]byte{0x22}, 32)
	mock := emulator.NewCard()
	mock.SetSuccessResponse(0x87, iso7816.EncodeTLV(0x7C, iso7816.EncodeTLV(0x82, secret)))
	got, err := NewClient(mock).CalculateSecret(SlotKeyManagement, peer)
	if err != nil {
		t.Fatalf("CalculateSecret() error = %v", err)
	}
	if !bytes.Equal(got, secret) {
		t.Fatal("secret must round-trip verbatim")
	}
	if len(mock.TransmittedCommands) != 1 {
		t.Fatalf("expected 1 command, got %d", len(mock.TransmittedCommands))
	}
	cmd := mustParseCommand(t, mock.TransmittedCommands[0])
	if cmd.Cla != 0x00 || cmd.Ins != 0x87 || cmd.P1 != AlgX25519 || cmd.P2 != byte(SlotKeyManagement) {
		t.Fatalf("ECDH header = %02X %02X %02X %02X, want 00 87 E1 9D", cmd.Cla, cmd.Ins, cmd.P1, cmd.P2)
	}
	outer, _ := iso7816.ParseAllTLV(cmd.Data)
	auth := iso7816.FindTag(outer, 0x7C)
	inner, _ := iso7816.ParseAllTLV(auth.Value)
	if placeholder := iso7816.FindTag(inner, 0x82); placeholder == nil || len(placeholder.Value) != 0 {
		t.Fatalf("0x82 placeholder must be empty in %X", auth.Value)
	}
	if peerTLV := iso7816.FindTag(inner, 0x85); peerTLV == nil || !bytes.Equal(peerTLV.Value, peer) {
		t.Fatalf("0x85 peer mismatch in %X", auth.Value)
	}
}

func TestClient_CalculateSecretRejectsBadPeer(t *testing.T) {
	mock := emulator.NewCard()
	if _, err := NewClient(mock).CalculateSecret(SlotKeyManagement, []byte{0x01}); err == nil || !strings.Contains(err.Error(), "32 bytes") {
		t.Fatalf("expected 32-byte error, got %v", err)
	}
	if len(mock.TransmittedCommands) != 0 {
		t.Fatalf("no APDU must be sent for bad peer, got %d", len(mock.TransmittedCommands))
	}
}

func TestClient_StoreGeneratedPublicKeyPQC(t *testing.T) {
	t.Run("rsa3072", func(t *testing.T) {
		modulus := append([]byte{0x80}, bytes.Repeat([]byte{0x55}, 383)...)
		n := new(big.Int).SetBytes(modulus)
		mock := emulator.NewCard()
		mock.SetSuccessResponse(0xDB, nil)
		if err := NewClient(mock).StoreGeneratedPublicKey(SlotSignature, AlgRSA3072, &rsa.PublicKey{N: n, E: 65537}); err != nil {
			t.Fatalf("StoreGeneratedPublicKey() error = %v", err)
		}
		if len(mock.TransmittedCommands) == 0 {
			t.Fatal("expected PUT DATA commands")
		}
	})
	t.Run("ed25519 tag 86", func(t *testing.T) {
		raw := bytes.Repeat([]byte{0x41}, 32)
		template, err := encodeGeneratedPublicKeyTemplate(AlgEd25519, &OpaquePublicKey{Algorithm: AlgEd25519, Raw: raw})
		if err != nil {
			t.Fatalf("encodeGeneratedPublicKeyTemplate() error = %v", err)
		}
		tlvs, _ := iso7816.ParseAllTLV(template)
		key := iso7816.FindTag(tlvs, 0x7F49)
		inner, _ := iso7816.ParseAllTLV(key.Value)
		if point := iso7816.FindTag(inner, 0x86); point == nil || !bytes.Equal(point.Value, raw) {
			t.Fatalf("7F49{86} mismatch in %X", template)
		}
		mock := emulator.NewCard()
		mock.SetSuccessResponse(0xDB, nil)
		if err := NewClient(mock).StoreGeneratedPublicKey(SlotSignature, AlgEd25519, &OpaquePublicKey{Algorithm: AlgEd25519, Raw: raw}); err != nil {
			t.Fatalf("StoreGeneratedPublicKey() error = %v", err)
		}
	})
	t.Run("mldsa44 tag 87", func(t *testing.T) {
		raw := bytes.Repeat([]byte{0x43}, 1312)
		template, err := encodeGeneratedPublicKeyTemplate(AlgMLDSA44, &OpaquePublicKey{Algorithm: AlgMLDSA44, Raw: raw})
		if err != nil {
			t.Fatalf("encodeGeneratedPublicKeyTemplate() error = %v", err)
		}
		tlvs, _ := iso7816.ParseAllTLV(template)
		key := iso7816.FindTag(tlvs, 0x7F49)
		inner, _ := iso7816.ParseAllTLV(key.Value)
		if point := iso7816.FindTag(inner, 0x87); point == nil || len(point.Value) != 1312 {
			t.Fatalf("7F49{87/1312} mismatch in %X", template[:64])
		}
	})
}
