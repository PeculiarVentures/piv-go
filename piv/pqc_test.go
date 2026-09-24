package piv

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
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
		{name: "mlkem512", algorithm: AlgMLKEM512, response: iso7816.EncodeTLV(0x7F49, iso7816.EncodeTLV(0x88, bytes.Repeat([]byte{0x46}, 800)))},
		{name: "mlkem768", algorithm: AlgMLKEM768, response: iso7816.EncodeTLV(0x7F49, iso7816.EncodeTLV(0x88, bytes.Repeat([]byte{0x47}, 1184)))},
		{name: "mlkem1024", algorithm: AlgMLKEM1024, response: iso7816.EncodeTLV(0x7F49, iso7816.EncodeTLV(0x88, bytes.Repeat([]byte{0x48}, 1568)))},
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

func TestClient_GenerateKeyPairMLKEM768ExactBytes(t *testing.T) {
	// Contract v1: 00 47 00 9E AC{80 E6} -> 7F49{88 1184}.
	ek := bytes.Repeat([]byte{0x47}, 1184)
	mock := emulator.NewCard()
	mock.SetSuccessResponse(0x47, iso7816.EncodeTLV(0x7F49, iso7816.EncodeTLV(0x88, ek)))
	key, err := NewClient(mock).GenerateKeyPair(SlotCardAuth, AlgMLKEM768)
	if err != nil {
		t.Fatalf("GenerateKeyPair() error = %v", err)
	}
	opaque, ok := key.(*OpaquePublicKey)
	if !ok || opaque.Algorithm != AlgMLKEM768 || !bytes.Equal(opaque.Raw, ek) {
		t.Fatalf("unexpected ML-KEM-768 public key: %#v", key)
	}
	if len(mock.TransmittedCommands) != 1 {
		t.Fatalf("expected 1 command, got %d", len(mock.TransmittedCommands))
	}
	raw := mock.TransmittedCommands[0]
	cmd := mustParseCommand(t, raw)
	if cmd.Cla != 0x00 || cmd.Ins != 0x47 || cmd.P1 != 0x00 || cmd.P2 != byte(SlotCardAuth) {
		t.Fatalf("generate header = %02X %02X %02X %02X, want 00 47 00 9E", cmd.Cla, cmd.Ins, cmd.P1, cmd.P2)
	}
	wantData := iso7816.EncodeTLV(0xAC, iso7816.EncodeTLV(0x80, []byte{AlgMLKEM768}))
	if !bytes.Equal(cmd.Data, wantData) {
		t.Fatalf("generate data = %X, want %X", cmd.Data, wantData)
	}
	if len(raw) < 4 || raw[0] != 0x00 || raw[1] != 0x47 || raw[2] != 0x00 || raw[3] != 0x9E {
		t.Fatalf("generate APDU prefix = %X, want 00 47 00 9E", raw[:4])
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

func assertImportCommand(t *testing.T, card *emulator.Card, slot Slot, algorithm byte, tags map[uint]int) {
	t.Helper()
	payload := reassembleChainedImport(t, card, slot, algorithm)
	tlvs, err := iso7816.ParseAllTLV(payload)
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
		assertImportCommand(t, mock, SlotKeyManagement, AlgRSA3072,
			map[uint]int{0x01: 192, 0x02: 192, 0x03: 192, 0x04: 192, 0x05: 192})
	})
	t.Run("rsa4096 halves 256", func(t *testing.T) {
		key := syntheticRSAKeyForImport(t, 4096)
		mock := emulator.NewCard()
		mock.SetSuccessResponse(InsImportKey, nil)
		if err := NewClient(mock).ImportKey(SlotKeyManagement, AlgRSA4096, key, PinPolicyDefault, TouchPolicyDefault); err != nil {
			t.Fatalf("ImportKey() error = %v", err)
		}
		assertImportCommand(t, mock, SlotKeyManagement, AlgRSA4096,
			map[uint]int{0x01: 256, 0x02: 256, 0x03: 256, 0x04: 256, 0x05: 256})
	})
	t.Run("ed25519 tag 07", func(t *testing.T) {
		seed := bytes.Repeat([]byte{0xAB}, 32)
		mock := emulator.NewCard()
		mock.SetSuccessResponse(InsImportKey, nil)
		if err := NewClient(mock).ImportKey(SlotSignature, AlgEd25519, &OpaquePrivateKey{Algorithm: AlgEd25519, Raw: seed}, PinPolicyOnce, TouchPolicyDefault); err != nil {
			t.Fatalf("ImportKey() error = %v", err)
		}
		assertImportCommand(t, mock, SlotSignature, AlgEd25519, map[uint]int{0x07: 32})
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
		assertImportCommand(t, mock, SlotKeyManagement, AlgX25519, map[uint]int{0x08: 32})
	})
	t.Run("mlkem768 tag 0A seed 64", func(t *testing.T) {
		seed := bytes.Repeat([]byte{0xD5}, MLKEMSeedLength)
		mock := emulator.NewCard()
		mock.SetSuccessResponse(InsImportKey, nil)
		if err := NewClient(mock).ImportKey(SlotKeyManagement, AlgMLKEM768, &OpaquePrivateKey{Algorithm: AlgMLKEM768, Raw: seed}, PinPolicyDefault, TouchPolicyDefault); err != nil {
			t.Fatalf("ImportKey() error = %v", err)
		}
		assertImportCommand(t, mock, SlotKeyManagement, AlgMLKEM768, map[uint]int{0x0A: MLKEMSeedLength})
		cmd := mustParseCommand(t, mock.TransmittedCommands[0])
		if cmd.Cla != 0x00 || cmd.Ins != InsImportKey || cmd.P1 != AlgMLKEM768 {
			t.Fatalf("import header = %02X %02X %02X, want 00 FE E6", cmd.Cla, cmd.Ins, cmd.P1)
		}
		tlvs, _ := iso7816.ParseAllTLV(cmd.Data)
		field := iso7816.FindTag(tlvs, 0x0A)
		if field == nil || !bytes.Equal(field.Value, seed) {
			t.Fatalf("tag 0x0A must carry the seed verbatim in %X", cmd.Data[:64])
		}
	})
	t.Run("mlkem seed 64 for every variant", func(t *testing.T) {
		for _, algorithm := range []byte{AlgMLKEM512, AlgMLKEM768, AlgMLKEM1024} {
			mock := emulator.NewCard()
			mock.SetSuccessResponse(InsImportKey, nil)
			if err := NewClient(mock).ImportKey(SlotSignature, algorithm, bytes.Repeat([]byte{0xD5}, MLKEMSeedLength), PinPolicyDefault, TouchPolicyDefault); err != nil {
				t.Fatalf("ImportKey(0x%02X) error = %v", algorithm, err)
			}
			assertImportCommand(t, mock, SlotSignature, algorithm, map[uint]int{0x0A: MLKEMSeedLength})
		}
	})
	t.Run("mlkem rejects mismatch and bad length without APDU", func(t *testing.T) {
		// Algorithm mismatch.
		mock := emulator.NewCard()
		if err := NewClient(mock).ImportKey(SlotSignature, AlgMLKEM768, &OpaquePrivateKey{Algorithm: AlgMLKEM512, Raw: bytes.Repeat([]byte{0xD5}, MLKEMSeedLength)}, PinPolicyDefault, TouchPolicyDefault); err == nil || !strings.Contains(err.Error(), "does not match") {
			t.Fatalf("expected algorithm-mismatch error, got %v", err)
		}
		// Wrong seed length: a full decapsulation key or an
		// encapsulation key is not accepted, only the 64-byte seed.
		for _, raw := range [][]byte{
			bytes.Repeat([]byte{0xD5}, 32),
			bytes.Repeat([]byte{0xD5}, 63),
			bytes.Repeat([]byte{0xD5}, 65),
			bytes.Repeat([]byte{0xD5}, 1184),
			bytes.Repeat([]byte{0xD5}, 2400),
		} {
			if err := NewClient(mock).ImportKey(SlotSignature, AlgMLKEM768, raw, PinPolicyDefault, TouchPolicyDefault); err == nil || !strings.Contains(err.Error(), "must be 64 bytes") {
				t.Fatalf("expected length error for %d bytes, got %v", len(raw), err)
			}
		}
		if len(mock.TransmittedCommands) != 0 {
			t.Fatalf("no APDU must be sent on rejection, got %d commands", len(mock.TransmittedCommands))
		}
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
			got, err := NewClient(mock).Sign(test.algorithm, SlotSignature, msg, RSASignHashNone)
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
	// modulus length with explicit hash mode. RSASignHashSHA256 wraps a
	// 32-byte digest with DigestInfo (CLI --hash sha256 after hashInput);
	// RSASignHashNone pads raw without DigestInfo (CLI --hash none).
	// Raw follows ykman _pad_message (yubikit/piv.py:546): RSA always
	// carries PKCS#1 v1.5 type-1 padding, so raw means "no DigestInfo",
	// not unpadded textbook RSA.
	digest := bytes.Repeat([]byte{0x5A}, 32)
	for _, test := range []struct {
		algorithm byte
		k         int
		sigLen    int
	}{
		{algorithm: AlgRSA3072, k: 384, sigLen: 384},
		{algorithm: AlgRSA4096, k: 512, sigLen: 512},
	} {
		t.Run("digest-sha256", func(t *testing.T) {
			mock := emulator.NewCard()
			mock.SetSuccessResponse(0x87, iso7816.EncodeTLV(0x7C, iso7816.EncodeTLV(0x82, bytes.Repeat([]byte{0xEE}, test.sigLen))))
			if _, err := NewClient(mock).Sign(test.algorithm, SlotSignature, digest, RSASignHashSHA256); err != nil {
				t.Fatalf("Sign() error = %v", err)
			}
			challenge := signChallenge(t, mock.TransmittedCommands[0])
			wantSuffix := append(append([]byte(nil), sha256DigestInfoPrefix...), digest...)
			assertPKCS1v15Block(t, challenge, test.k, wantSuffix)
		})
		t.Run("raw-short", func(t *testing.T) {
			msg := []byte{0x01, 0x02, 0x03}
			mock := emulator.NewCard()
			mock.SetSuccessResponse(0x87, iso7816.EncodeTLV(0x7C, iso7816.EncodeTLV(0x82, bytes.Repeat([]byte{0xEE}, test.sigLen))))
			if _, err := NewClient(mock).Sign(test.algorithm, SlotSignature, msg, RSASignHashNone); err != nil {
				t.Fatalf("Sign() error = %v", err)
			}
			challenge := signChallenge(t, mock.TransmittedCommands[0])
			assertPKCS1v15Block(t, challenge, test.k, msg)
			if bytes.Contains(challenge, sha256DigestInfoPrefix) {
				t.Fatal("raw challenge must not contain DigestInfo")
			}
		})
		t.Run("raw-32-no-digestinfo", func(t *testing.T) {
			// Regression: a 32-byte raw message under --hash none must
			// stay raw; length alone must not trigger DigestInfo.
			msg32 := bytes.Repeat([]byte{0x01}, 32)
			mock := emulator.NewCard()
			mock.SetSuccessResponse(0x87, iso7816.EncodeTLV(0x7C, iso7816.EncodeTLV(0x82, bytes.Repeat([]byte{0xEE}, test.sigLen))))
			if _, err := NewClient(mock).Sign(test.algorithm, SlotSignature, msg32, RSASignHashNone); err != nil {
				t.Fatalf("Sign() error = %v", err)
			}
			challenge := signChallenge(t, mock.TransmittedCommands[0])
			assertPKCS1v15Block(t, challenge, test.k, msg32)
			if bytes.Contains(challenge, sha256DigestInfoPrefix) {
				t.Fatal("32-byte raw challenge must not contain DigestInfo")
			}
		})
	}
	// SHA-256 mode requires a 32-byte digest; anything else rejects
	// before any APDU.
	for _, msg := range [][]byte{{0x01, 0x02, 0x03}, bytes.Repeat([]byte{0x01}, 33), bytes.Repeat([]byte{0x01}, 400)} {
		mock := emulator.NewCard()
		if _, err := NewClient(mock).Sign(AlgRSA3072, SlotSignature, msg, RSASignHashSHA256); err == nil {
			t.Fatalf("expected digest-length error for %d bytes, got nil", len(msg))
		}
		if len(mock.TransmittedCommands) != 0 {
			t.Fatalf("no APDU must be sent on digest-length rejection, got %d commands", len(mock.TransmittedCommands))
		}
	}
	// Oversize raw messages reject before any APDU.
	mock := emulator.NewCard()
	if _, err := NewClient(mock).Sign(AlgRSA3072, SlotSignature, bytes.Repeat([]byte{0x01}, 400), RSASignHashNone); err == nil || !strings.Contains(err.Error(), "too long") {
		t.Fatalf("expected too-long error, got %v", err)
	}
	if len(mock.TransmittedCommands) != 0 {
		t.Fatalf("no APDU must be sent for oversize message, got %d", len(mock.TransmittedCommands))
	}
}

func TestClient_SignExtendedRSAGoVerification(t *testing.T) {
	// The sha256 wire block must match Go's PKCS#1 v1.5 construction:
	// a real RSA-3072 SignPKCS1v15/VerifyPKCS1v15 round-trip over the
	// same digest proves the DigestInfo path, while the none wire block
	// is verified manually (00 01 FF..FF 00 || msg, no DigestInfo)
	// because Go's VerifyPKCS1v15 always expects DigestInfo for named
	// hashes and has no raw type-1 verifier.
	priv, err := rsa.GenerateKey(rand.Reader, 3072)
	if err != nil {
		t.Fatalf("generate RSA-3072: %v", err)
	}
	msg := []byte("extended-rsa verification payload")
	sum := sha256.Sum256(msg)
	sig, err := rsa.SignPKCS1v15(rand.Reader, priv, crypto.SHA256, sum[:])
	if err != nil {
		t.Fatalf("SignPKCS1v15: %v", err)
	}
	if err := rsa.VerifyPKCS1v15(&priv.PublicKey, crypto.SHA256, sum[:], sig); err != nil {
		t.Fatalf("VerifyPKCS1v15: %v", err)
	}
	em, err := formatExtendedRSAChallenge(AlgRSA3072, sum[:], RSASignHashSHA256)
	if err != nil {
		t.Fatalf("formatExtendedRSAChallenge(sha256): %v", err)
	}
	wantSuffix := append(append([]byte(nil), sha256DigestInfoPrefix...), sum[:]...)
	assertPKCS1v15Block(t, em, 384, wantSuffix)

	rawMsg := []byte{0x01, 0x02, 0x03}
	emRaw, err := formatExtendedRSAChallenge(AlgRSA3072, rawMsg, RSASignHashNone)
	if err != nil {
		t.Fatalf("formatExtendedRSAChallenge(none): %v", err)
	}
	assertPKCS1v15Block(t, emRaw, 384, rawMsg)
	if bytes.Contains(emRaw, sha256DigestInfoPrefix) {
		t.Fatal("raw block must not contain DigestInfo")
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

func TestClient_DecapsulateMLKEM768ExactBytes(t *testing.T) {
	// Contract v1: 00 87 E6 slot 7C{82 empty, 86 1088} -> 7C{82 32}.
	ciphertext := bytes.Repeat([]byte{0xC7}, 1088)
	secret := bytes.Repeat([]byte{0x5E}, 32)
	mock := emulator.NewCard()
	mock.SetSuccessResponse(0x87, iso7816.EncodeTLV(0x7C, iso7816.EncodeTLV(0x82, secret)))
	got, err := NewClient(mock).Decapsulate(AlgMLKEM768, SlotKeyManagement, ciphertext)
	if err != nil {
		t.Fatalf("Decapsulate() error = %v", err)
	}
	if !bytes.Equal(got, secret) {
		t.Fatal("secret must round-trip verbatim")
	}
	if len(mock.TransmittedCommands) != 1 {
		t.Fatalf("expected 1 command, got %d", len(mock.TransmittedCommands))
	}
	raw := mock.TransmittedCommands[0]
	if len(raw) < 4 || raw[0] != 0x00 || raw[1] != 0x87 || raw[2] != AlgMLKEM768 || raw[3] != byte(SlotKeyManagement) {
		t.Fatalf("decapsulate APDU prefix = %X, want 00 87 E6 9D", raw[:4])
	}
	cmd := mustParseCommand(t, raw)
	outer, _ := iso7816.ParseAllTLV(cmd.Data)
	auth := iso7816.FindTag(outer, 0x7C)
	if auth == nil {
		t.Fatalf("0x7C not found in %X", cmd.Data)
	}
	inner, _ := iso7816.ParseAllTLV(auth.Value)
	if placeholder := iso7816.FindTag(inner, 0x82); placeholder == nil || len(placeholder.Value) != 0 {
		t.Fatalf("0x82 placeholder must be empty in %X", auth.Value)
	}
	if ctTLV := iso7816.FindTag(inner, 0x86); ctTLV == nil || !bytes.Equal(ctTLV.Value, ciphertext) {
		t.Fatalf("0x86 ciphertext mismatch in %X", auth.Value[:64])
	}
}

func TestClient_DecapsulateSizesAndRejects(t *testing.T) {
	for _, test := range []struct {
		algorithm byte
		ctLen     int
	}{
		{algorithm: AlgMLKEM512, ctLen: 768},
		{algorithm: AlgMLKEM768, ctLen: 1088},
		{algorithm: AlgMLKEM1024, ctLen: 1568},
	} {
		mock := emulator.NewCard()
		mock.SetSuccessResponse(0x87, iso7816.EncodeTLV(0x7C, iso7816.EncodeTLV(0x82, bytes.Repeat([]byte{0x5E}, 32))))
		if _, err := NewClient(mock).Decapsulate(test.algorithm, SlotSignature, bytes.Repeat([]byte{0xC7}, test.ctLen)); err != nil {
			t.Fatalf("Decapsulate(0x%02X) error = %v", test.algorithm, err)
		}
		cmd := mustParseCommand(t, mock.TransmittedCommands[0])
		if cmd.P1 != test.algorithm {
			t.Fatalf("P1 = 0x%02X, want 0x%02X", cmd.P1, test.algorithm)
		}
	}
	// Wrong ciphertext length and non-KEM algorithm reject before any APDU.
	mock := emulator.NewCard()
	if _, err := NewClient(mock).Decapsulate(AlgMLKEM768, SlotSignature, bytes.Repeat([]byte{0xC7}, 1087)); err == nil || !strings.Contains(err.Error(), "must be 1088 bytes") {
		t.Fatalf("expected length error, got %v", err)
	}
	if _, err := NewClient(mock).Decapsulate(AlgECCP256, SlotSignature, bytes.Repeat([]byte{0xC7}, 1088)); err == nil || !strings.Contains(err.Error(), "unsupported decapsulation algorithm") {
		t.Fatalf("expected algorithm error, got %v", err)
	}
	if _, err := NewClient(mock).Decapsulate(AlgX25519, SlotSignature, bytes.Repeat([]byte{0xC7}, 32)); err == nil || !strings.Contains(err.Error(), "unsupported decapsulation algorithm") {
		t.Fatalf("expected algorithm error, got %v", err)
	}
	if len(mock.TransmittedCommands) != 0 {
		t.Fatalf("no APDU must be sent on rejection, got %d commands", len(mock.TransmittedCommands))
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
	t.Run("mlkem768 tag 88 stored as 53", func(t *testing.T) {
		raw := bytes.Repeat([]byte{0x47}, 1184)
		template, err := encodeGeneratedPublicKeyTemplate(AlgMLKEM768, &OpaquePublicKey{Algorithm: AlgMLKEM768, Raw: raw})
		if err != nil {
			t.Fatalf("encodeGeneratedPublicKeyTemplate() error = %v", err)
		}
		tlvs, _ := iso7816.ParseAllTLV(template)
		key := iso7816.FindTag(tlvs, 0x7F49)
		inner, _ := iso7816.ParseAllTLV(key.Value)
		if point := iso7816.FindTag(inner, 0x88); point == nil || !bytes.Equal(point.Value, raw) {
			t.Fatalf("7F49{88/1184} mismatch in %X", template[:64])
		}
		// Storing issues PUT DATA (0xDB) with the 0x53{7F49{88} + 71 00 + FE}
		// wrapper shared with the other generated-key flows.
		mock := emulator.NewCard()
		mock.SetSuccessResponse(0xDB, nil)
		if err := NewClient(mock).StoreGeneratedPublicKey(SlotCardAuth, AlgMLKEM768, &OpaquePublicKey{Algorithm: AlgMLKEM768, Raw: raw}); err != nil {
			t.Fatalf("StoreGeneratedPublicKey() error = %v", err)
		}
		if len(mock.TransmittedCommands) == 0 {
			t.Fatal("expected PUT DATA commands")
		}
		rawCmd := mock.TransmittedCommands[len(mock.TransmittedCommands)-1]
		if len(rawCmd) < 2 || rawCmd[1] != 0xDB {
			t.Fatalf("store APDU INS = 0x%02X, want 0xDB", rawCmd[1])
		}
		var stored []byte
		for _, chunk := range mock.TransmittedCommands {
			parsed, err := iso7816.ParseCommand(chunk)
			if err != nil {
				t.Fatalf("parse PUT DATA: %v", err)
			}
			stored = append(stored, parsed.Data...)
		}
		objects, err := iso7816.ParseAllTLV(stored)
		if err != nil {
			t.Fatalf("parse stored object: %v", err)
		}
		wrapper := iso7816.FindTag(objects, 0x53)
		if wrapper == nil {
			t.Fatalf("0x53 wrapper missing in %X", stored[:16])
		}
		fields, err := iso7816.ParseAllTLV(wrapper.Value)
		if err != nil {
			t.Fatalf("parse 0x53 wrapper: %v", err)
		}
		if key := iso7816.FindTag(fields, 0x7F49); key == nil {
			t.Fatalf("7F49 missing in 0x53 wrapper %X", wrapper.Value[:16])
		}
		if policy := iso7816.FindTag(fields, 0x71); policy == nil {
			t.Fatalf("71 missing in 0x53 wrapper %X", wrapper.Value[:16])
		}
		if iso7816.FindTag(fields, 0xFE) == nil {
			t.Fatalf("FE missing in 0x53 wrapper %X", wrapper.Value[:16])
		}
		if !bytes.Contains(wrapper.Value, raw) {
			t.Fatal("0x53 wrapper must contain the 1184-byte encapsulation key")
		}
	})
}
