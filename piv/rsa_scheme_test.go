package piv

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"os"
	"testing"

	"github.com/PeculiarVentures/piv-go/emulator"
	"github.com/PeculiarVentures/piv-go/internal/rsascheme"
	"github.com/PeculiarVentures/piv-go/iso7816"
)

func rsaSchemeTestPublicKey(bits int) *rsa.PublicKey {
	n := new(big.Int).Lsh(big.NewInt(1), uint(bits-1))
	n.SetBit(n, 0, 1)
	return &rsa.PublicKey{N: n, E: 65537}
}

func rsaSchemeDigest(hash crypto.Hash) []byte {
	h := hash.New()
	h.Write([]byte("explicit card RSA scheme test"))
	return h.Sum(nil)
}

func TestSignRSAExplicitSchemesAndWidths(t *testing.T) {
	for _, width := range []struct {
		bits      int
		algorithm byte
	}{
		{1024, AlgRSA1024}, {2048, AlgRSA2048}, {3072, AlgRSA3072}, {4096, AlgRSA4096},
	} {
		t.Run(fmt.Sprint(width.bits), func(t *testing.T) {
			key := rsaSchemeTestPublicKey(width.bits)
			for _, hash := range []crypto.Hash{crypto.SHA256, crypto.SHA384, crypto.SHA512} {
				input := rsaSchemeDigest(hash)
				cases := []struct {
					name    string
					options RSASignOptions
				}{
					{"digest", RSAPKCS1v15DigestOptions{Hash: hash}},
				}
				maxSalt := (width.bits-1+7)/8 - hash.Size() - 2
				for _, saltLength := range []int{0, 1, hash.Size(), maxSalt} {
					if saltLength <= maxSalt {
						cases = append(cases, struct {
							name    string
							options RSASignOptions
						}{fmt.Sprintf("pss-%d", saltLength), RSAPSSOptions{Hash: hash, MGF1Hash: hash, SaltLength: saltLength}})
					}
				}
				for _, tc := range cases {
					t.Run(hash.String()+"/"+tc.name, func(t *testing.T) {
						card := emulator.NewCard()
						wantSignature := bytes.Repeat([]byte{0x5a}, key.Size())
						card.SetSuccessResponse(0x87, iso7816.EncodeTLV(0x7c, iso7816.EncodeTLV(0x82, wantSignature)))
						got, err := NewClient(card).SignRSA(width.algorithm, SlotSignature, key, input, tc.options)
						if err != nil || !bytes.Equal(got, wantSignature) {
							t.Fatalf("SignRSA: signature %d bytes, error %v", len(got), err)
						}
						em := rsaSignChallenge(t, card)
						if len(em) != key.Size() {
							t.Fatalf("encoded length %d, want %d", len(em), key.Size())
						}
						if pss, ok := tc.options.(RSAPSSOptions); ok {
							if err := rsascheme.VerifyPSS(input, em, width.bits-1, pss.SaltLength, hash.New()); err != nil {
								t.Fatalf("PSS challenge was changed or padded twice: %v", err)
							}
						} else {
							if em[0] != 0 || em[1] != 1 || !bytes.Equal(em[len(em)-len(input):], input) {
								t.Fatal("invalid v1.5 encoding")
							}
						}
						for _, raw := range card.TransmittedCommands {
							command, err := iso7816.ParseCommand(raw)
							if err != nil || command.P1 != width.algorithm || command.P2 != byte(SlotSignature) {
								t.Fatalf("wrong RSA algorithm/slot: %v", err)
							}
							if width.bits <= 2048 && len(command.Data) > 255 {
								t.Fatal("legacy algorithm sent an extended APDU")
							}
						}
					})
				}
			}
		})
	}
}

func TestSignRSAExactPayloadBoundaries(t *testing.T) {
	for _, size := range []struct {
		bits      int
		algorithm byte
	}{{2048, AlgRSA2048}, {3072, AlgRSA3072}, {4096, AlgRSA4096}} {
		key := rsaSchemeTestPublicKey(size.bits)
		for _, input := range [][]byte{nil, bytes.Repeat([]byte{0x42}, key.Size()-11), {0x30, 0xff, 0x00, 0x7f}} {
			card := emulator.NewCard()
			card.SetSuccessResponse(0x87, iso7816.EncodeTLV(0x7c, iso7816.EncodeTLV(0x82, make([]byte, key.Size()))))
			if _, err := NewClient(card).SignRSA(size.algorithm, SlotAuthentication, key, input, RSAPKCS1v15PayloadOptions{}); err != nil {
				t.Fatal(err)
			}
			em := rsaSignChallenge(t, card)
			separator := bytes.IndexByte(em[2:], 0) + 2
			if separator < 10 || !bytes.Equal(em[separator+1:], input) {
				t.Fatal("payload, including malformed DigestInfo, must be preserved exactly")
			}
		}
		for _, length := range []int{key.Size() - 10, key.Size()} {
			card := emulator.NewCard()
			_, err := NewClient(card).SignRSA(size.algorithm, SlotSignature, key, make([]byte, length), RSAPKCS1v15PayloadOptions{})
			if !errors.Is(err, rsa.ErrMessageTooLong) || len(card.TransmittedCommands) != 0 {
				t.Fatalf("oversize payload sent APDU or wrong error: %v", err)
			}
		}
	}
}

func TestSignRSAInvalidRequestsSendNoAPDU(t *testing.T) {
	valid := rsaSchemeTestPublicKey(2048)
	digest := rsaSchemeDigest(crypto.SHA256)
	defaultOptions := RSAPSSOptions{Hash: crypto.SHA256, MGF1Hash: crypto.SHA256, SaltLength: 32}
	badKey := func(change func(*rsa.PublicKey)) *rsa.PublicKey {
		copy := &rsa.PublicKey{N: new(big.Int).Set(valid.N), E: valid.E}
		change(copy)
		return copy
	}
	for _, tc := range []struct {
		name      string
		algorithm byte
		key       *rsa.PublicKey
		input     []byte
		options   RSASignOptions
	}{
		{"nil-key", AlgRSA2048, nil, digest, defaultOptions},
		{"nil-modulus", AlgRSA2048, &rsa.PublicKey{E: 65537}, digest, defaultOptions},
		{"zero-modulus", AlgRSA2048, &rsa.PublicKey{N: new(big.Int), E: 65537}, digest, defaultOptions},
		{"even-modulus", AlgRSA2048, badKey(func(k *rsa.PublicKey) { k.N.SetBit(k.N, 0, 0) }), digest, defaultOptions},
		{"small-modulus", AlgRSA2048, rsaSchemeTestPublicKey(1023), digest, defaultOptions},
		{"large-modulus", AlgRSA2048, rsaSchemeTestPublicKey(4097), digest, defaultOptions},
		{"negative-exponent", AlgRSA2048, badKey(func(k *rsa.PublicKey) { k.E = -1 }), digest, defaultOptions},
		{"even-exponent", AlgRSA2048, badKey(func(k *rsa.PublicKey) { k.E = 4 }), digest, defaultOptions},
		{"large-exponent", AlgRSA2048, badKey(func(k *rsa.PublicKey) { k.E = 1 << 31 }), digest, defaultOptions},
		{"size-binding", AlgRSA3072, valid, digest, defaultOptions},
		{"non-byte-modulus", AlgRSA2048, rsaSchemeTestPublicKey(2047), digest, defaultOptions},
		{"unknown-algorithm", 0xff, valid, digest, defaultOptions},
		{"nil-options", AlgRSA2048, valid, digest, nil},
		{"typed-nil-pss", AlgRSA2048, valid, digest, (*RSAPSSOptions)(nil)},
		{"typed-nil-digest", AlgRSA2048, valid, digest, (*RSAPKCS1v15DigestOptions)(nil)},
		{"typed-nil-payload", AlgRSA2048, valid, digest, (*RSAPKCS1v15PayloadOptions)(nil)},
		{"digest-length", AlgRSA2048, valid, digest[:31], defaultOptions},
		{"digest-zero-hash", AlgRSA2048, valid, digest, RSAPKCS1v15DigestOptions{}},
		{"unknown-hash", AlgRSA2048, valid, digest, RSAPKCS1v15DigestOptions{Hash: crypto.Hash(999)}},
		{"unsupported-hash", AlgRSA2048, valid, make([]byte, 20), RSAPKCS1v15DigestOptions{Hash: crypto.SHA1}},
		{"missing-mgf", AlgRSA2048, valid, digest, RSAPSSOptions{Hash: crypto.SHA256, SaltLength: 32}},
		{"different-mgf", AlgRSA2048, valid, digest, RSAPSSOptions{Hash: crypto.SHA256, MGF1Hash: crypto.SHA384, SaltLength: 32}},
		{"unknown-mgf", AlgRSA2048, valid, digest, RSAPSSOptions{Hash: crypto.SHA256, MGF1Hash: crypto.Hash(999), SaltLength: 32}},
		{"negative-salt", AlgRSA2048, valid, digest, RSAPSSOptions{Hash: crypto.SHA256, MGF1Hash: crypto.SHA256, SaltLength: -1}},
		{"salt-max-plus-one", AlgRSA2048, valid, digest, RSAPSSOptions{Hash: crypto.SHA256, MGF1Hash: crypto.SHA256, SaltLength: 223}},
		{"salt-int-max", AlgRSA2048, valid, digest, RSAPSSOptions{Hash: crypto.SHA256, MGF1Hash: crypto.SHA256, SaltLength: int(^uint(0) >> 1)}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			card := emulator.NewCard()
			_, err := NewClient(card).signRSAWithRandom(tc.algorithm, SlotSignature, tc.key, tc.input, tc.options, rsaFailReader{})
			if err == nil || (!errors.Is(err, ErrInvalidRSAParameters) && !errors.Is(err, ErrUnsupportedRSAOptions)) {
				t.Fatalf("expected identifiable validation error, got %v", err)
			}
			if len(card.TransmittedCommands) != 0 {
				t.Fatal("invalid request sent APDU")
			}
		})
	}
}

type rsaFailReader struct{}

func (rsaFailReader) Read([]byte) (int, error) { return 0, io.ErrUnexpectedEOF }

type rsaUnknownOptions struct{}

func (rsaUnknownOptions) rsaSignOptions() {}

func TestRSAOptionsAbsenceIsAnInvalidRequest(t *testing.T) {
	key := rsaSchemeTestPublicKey(2048)
	digest := rsaSchemeDigest(crypto.SHA256)
	for _, options := range []RSASignOptions{nil, (*RSAPSSOptions)(nil), (*RSAPKCS1v15DigestOptions)(nil), (*RSAPKCS1v15PayloadOptions)(nil)} {
		if err := ValidateRSASignRequest(AlgRSA2048, key, digest, options); !errors.Is(err, ErrInvalidRSAParameters) || errors.Is(err, ErrUnsupportedRSAOptions) {
			t.Fatalf("%T preflight error = %v", options, err)
		}
		if err := VerifyRSA(key, digest, nil, options); !errors.Is(err, ErrInvalidRSAParameters) {
			t.Fatalf("%T verification request error = %v", options, err)
		}
		card := emulator.NewCard()
		if _, err := NewClient(card).SignRSA(AlgRSA2048, SlotSignature, key, digest, options); !errors.Is(err, ErrInvalidRSAParameters) || len(card.TransmittedCommands) != 0 {
			t.Fatalf("%T invalid request contacted the card or returned wrong error: %v", options, err)
		}
	}
	if err := ValidateRSASignRequest(AlgRSA2048, key, digest, rsaUnknownOptions{}); !errors.Is(err, ErrUnsupportedRSAOptions) || errors.Is(err, ErrInvalidRSAParameters) {
		t.Fatalf("unknown concrete options must remain unsupported, got %v", err)
	}
}

func TestValidateRSACompatibilityWrapper(t *testing.T) {
	key := rsaSchemeTestPublicKey(2048)
	digest := rsaSchemeDigest(crypto.SHA256)
	for _, options := range []RSASignOptions{RSAPSSOptions{Hash: crypto.SHA256, MGF1Hash: crypto.SHA256}, nil} {
		canonical := ValidateRSASignRequest(AlgRSA2048, key, digest, options)
		compatibility := ValidateRSA(AlgRSA2048, key, digest, options)
		if fmt.Sprint(canonical) != fmt.Sprint(compatibility) || errors.Is(canonical, ErrInvalidRSAParameters) != errors.Is(compatibility, ErrInvalidRSAParameters) {
			t.Fatalf("compatibility wrapper changed validation: %v vs %v", canonical, compatibility)
		}
	}
}

func TestSignRSARandomnessFailureAndZeroSalt(t *testing.T) {
	key := rsaSchemeTestPublicKey(2048)
	digest := rsaSchemeDigest(crypto.SHA256)
	options := RSAPSSOptions{Hash: crypto.SHA256, MGF1Hash: crypto.SHA256, SaltLength: 32}
	card := emulator.NewCard()
	_, err := NewClient(card).signRSAWithRandom(AlgRSA2048, SlotSignature, key, digest, options, rsaFailReader{})
	if !errors.Is(err, io.ErrUnexpectedEOF) || len(card.TransmittedCommands) != 0 {
		t.Fatalf("random failure: %v", err)
	}
	card.SetSuccessResponse(0x87, iso7816.EncodeTLV(0x7c, iso7816.EncodeTLV(0x82, make([]byte, key.Size()))))
	options.SaltLength = 0
	if _, err := NewClient(card).signRSAWithRandom(AlgRSA2048, SlotSignature, key, digest, options, rsaFailReader{}); err != nil {
		t.Fatalf("empty salt must not read randomness: %v", err)
	}
}

func rsaPrimitiveTestCard(t *testing.T, key *rsa.PrivateKey) *emulator.Card {
	t.Helper()
	card := emulator.NewCard()
	var data []byte
	card.RegisterINSHandler(0x87, func(_ *emulator.Card, raw []byte) ([]byte, error) {
		cmd, err := iso7816.ParseCommand(raw)
		if err != nil {
			return nil, err
		}
		data = append(data, cmd.Data...)
		if cmd.Cla&0x10 != 0 {
			return emulator.BuildSuccessResponse(nil), nil
		}
		outer, err := iso7816.ParseAllTLV(data)
		if err != nil {
			return nil, err
		}
		inner, err := iso7816.ParseAllTLV(iso7816.FindTag(outer, 0x7c).Value)
		if err != nil {
			return nil, err
		}
		challenge := iso7816.FindTag(inner, 0x81).Value
		data = nil
		m := new(big.Int).SetBytes(challenge)
		if len(challenge) != key.Size() || m.Cmp(key.N) >= 0 {
			return nil, fmt.Errorf("invalid RSA representative")
		}
		sig := new(big.Int).Exp(m, key.D, key.N).FillBytes(make([]byte, key.Size()))
		return emulator.BuildSuccessResponse(iso7816.EncodeTLV(0x7c, iso7816.EncodeTLV(0x82, sig))), nil
	})
	return card
}

func TestSignRSAIndependentStdlibVerification(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	for _, hash := range []crypto.Hash{crypto.SHA256, crypto.SHA384, crypto.SHA512} {
		digest := rsaSchemeDigest(hash)
		options := RSAPKCS1v15DigestOptions{Hash: hash}
		sig, err := NewClient(rsaPrimitiveTestCard(t, key)).SignRSA(AlgRSA2048, SlotSignature, &key.PublicKey, digest, options)
		if err != nil {
			t.Fatal(err)
		}
		if err := rsa.VerifyPKCS1v15(&key.PublicKey, hash, digest, sig); err != nil {
			t.Fatalf("independent v1.5 verification: %v", err)
		}
		if err := VerifyRSA(&key.PublicKey, digest, sig, options); err != nil {
			t.Fatal(err)
		}
		stdlibSig, err := rsa.SignPKCS1v15(rand.Reader, key, hash, digest)
		if err != nil {
			t.Fatal(err)
		}
		if err := VerifyRSA(&key.PublicKey, digest, stdlibSig, options); err != nil {
			t.Fatalf("stdlib v1.5 signature rejected: %v", err)
		}
		for _, saltLength := range []int{0, 1, hash.Size(), key.Size() - hash.Size() - 2} {
			pss := RSAPSSOptions{Hash: hash, MGF1Hash: hash, SaltLength: saltLength}
			sig, err := NewClient(rsaPrimitiveTestCard(t, key)).SignRSA(AlgRSA2048, SlotSignature, &key.PublicKey, digest, pss)
			if err != nil {
				t.Fatal(err)
			}
			if err := rsa.VerifyPSS(&key.PublicKey, hash, digest, sig, &rsa.PSSOptions{SaltLength: saltLength}); err != nil {
				t.Fatalf("independent PSS verification salt %d: %v", saltLength, err)
			}
			if err := VerifyRSA(&key.PublicKey, digest, sig, pss); err != nil {
				t.Fatal(err)
			}
			wrongSalt := pss
			wrongSalt.SaltLength = (saltLength + 1) % (key.Size() - hash.Size() - 1)
			if err := VerifyRSA(&key.PublicKey, digest, sig, wrongSalt); !errors.Is(err, rsa.ErrVerification) {
				t.Fatalf("salt %d accepted as %d: %v", saltLength, wrongSalt.SaltLength, err)
			}
			if saltLength > 0 {
				stdlibSig, err := rsa.SignPSS(rand.Reader, key, hash, digest, &rsa.PSSOptions{SaltLength: saltLength})
				if err != nil {
					t.Fatal(err)
				}
				if err := VerifyRSA(&key.PublicKey, digest, stdlibSig, pss); err != nil {
					t.Fatalf("stdlib PSS signature rejected: %v", err)
				}
			}
		}
	}
	malformed := []byte{0x30, 0xff, 0x00, 0x01}
	sig, err := NewClient(rsaPrimitiveTestCard(t, key)).SignRSA(AlgRSA2048, SlotSignature, &key.PublicKey, malformed, RSAPKCS1v15PayloadOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if err := rsa.VerifyPKCS1v15(&key.PublicKey, 0, malformed, sig); err != nil {
		t.Fatalf("exact payload: %v", err)
	}
	if err := VerifyRSA(&key.PublicKey, malformed, sig, &RSAPKCS1v15PayloadOptions{}); err != nil {
		t.Fatal(err)
	}
}

func TestSignRSAResponseValidationAndContinuation(t *testing.T) {
	key := rsaSchemeTestPublicKey(2048)
	digest := rsaSchemeDigest(crypto.SHA256)
	for _, test := range []struct {
		response []byte
		badWidth bool
	}{
		{iso7816.EncodeTLV(0x7c, iso7816.EncodeTLV(0x82, make([]byte, 255))), true},
		{iso7816.EncodeTLV(0x7c, iso7816.EncodeTLV(0x82, make([]byte, 257))), true},
		{iso7816.EncodeTLV(0x7c, iso7816.EncodeTLV(0x81, make([]byte, 256))), false},
		{[]byte{0x7c, 0x82, 0xff}, false},
	} {
		card := emulator.NewCard()
		card.SetSuccessResponse(0x87, test.response)
		_, err := NewClient(card).SignRSA(AlgRSA2048, SlotSignature, key, digest, RSAPKCS1v15DigestOptions{Hash: crypto.SHA256})
		if err == nil || test.badWidth && !errors.Is(err, ErrInvalidSignatureResponse) {
			t.Fatalf("malformed/incorrect-width signature error = %v", err)
		}
		finalOperations := 0
		for _, command := range card.TransmittedCommands {
			if command[1] == 0x87 && command[0]&0x10 == 0 {
				finalOperations++
			}
		}
		if finalOperations != 1 {
			t.Fatal("bad RSA response must not cause an automatic retry")
		}
	}
	card := emulator.NewCard()
	want := bytes.Repeat([]byte{0x42}, key.Size())
	response := iso7816.EncodeTLV(0x7c, iso7816.EncodeTLV(0x82, want))
	card.RegisterINSHandler(0x87, func(_ *emulator.Card, raw []byte) ([]byte, error) {
		if raw[0]&0x10 != 0 {
			return emulator.BuildSuccessResponse(nil), nil
		}
		return emulator.BuildResponse(response[:50], 0x6100), nil
	})
	card.SetSuccessResponse(0xc0, response[50:])
	got, err := NewClient(card).SignRSA(AlgRSA2048, SlotSignature, key, digest, RSAPKCS1v15DigestOptions{Hash: crypto.SHA256})
	if err != nil || !bytes.Equal(got, want) {
		t.Fatalf("response continuation: %v", err)
	}
	if card.TransmittedCommands[len(card.TransmittedCommands)-1][1] != 0xc0 {
		t.Fatal("no GET RESPONSE")
	}
}

func TestVerifyRSAOpenSSLFixtures(t *testing.T) {
	fixture, err := os.ReadFile("testdata/rsa-openssl.json")
	if err != nil {
		t.Fatal(err)
	}
	var data struct {
		OpenSSL   string `json:"openssl"`
		PublicKey string `json:"public_key"`
		Message   string `json:"message"`
		Vectors   []struct {
			Hash       string `json:"hash"`
			Scheme     string `json:"scheme"`
			SaltLength int    `json:"salt_length"`
			Signature  string `json:"signature"`
		} `json:"vectors"`
	}
	if err := json.Unmarshal(fixture, &data); err != nil {
		t.Fatal(err)
	}
	if data.OpenSSL == "" {
		t.Fatal("fixture must identify independent OpenSSL version")
	}
	block, _ := pem.Decode([]byte(data.PublicKey))
	if block == nil {
		t.Fatal("invalid fixture PEM")
	}
	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	key := parsed.(*rsa.PublicKey)
	for _, v := range data.Vectors {
		hash := map[string]crypto.Hash{"sha256": crypto.SHA256, "sha384": crypto.SHA384, "sha512": crypto.SHA512}[v.Hash]
		h := hash.New()
		h.Write([]byte(data.Message))
		digest := h.Sum(nil)
		sig, err := hex.DecodeString(v.Signature)
		if err != nil {
			t.Fatal(err)
		}
		var options RSASignOptions = RSAPKCS1v15DigestOptions{Hash: hash}
		if v.Scheme == "pss" {
			options = RSAPSSOptions{Hash: hash, MGF1Hash: hash, SaltLength: v.SaltLength}
		}
		if err := VerifyRSA(key, digest, sig, options); err != nil {
			t.Fatalf("OpenSSL %s/%s/salt=%d: %v", v.Hash, v.Scheme, v.SaltLength, err)
		}
		if v.Scheme == "pss" {
			wrong := RSAPSSOptions{Hash: hash, MGF1Hash: hash, SaltLength: (v.SaltLength + 1) % (key.Size() - hash.Size() - 1)}
			if err := VerifyRSA(key, digest, sig, wrong); !errors.Is(err, rsa.ErrVerification) {
				t.Fatalf("OpenSSL fixture accepted with wrong salt: %v", err)
			}
			if v.SaltLength == 0 {
				em, err := rsascheme.EncodePSS(digest, key.N.BitLen()-1, nil, hash.New())
				if err != nil {
					t.Fatal(err)
				}
				recovered := new(big.Int).Exp(new(big.Int).SetBytes(sig), big.NewInt(int64(key.E)), key.N).FillBytes(make([]byte, key.Size()))
				if !bytes.Equal(em, recovered) {
					t.Fatal("zero-salt encoder differs from independent OpenSSL encoding")
				}
			}
		}
		bad := append([]byte(nil), digest...)
		bad[0] ^= 1
		if err := VerifyRSA(key, bad, sig, options); !errors.Is(err, rsa.ErrVerification) {
			t.Fatal("changed digest accepted")
		}
		if err := VerifyRSA(key, digest, sig[1:], options); !errors.Is(err, rsa.ErrVerification) {
			t.Fatal("short signature accepted")
		}
		if err := VerifyRSA(key, digest, key.N.FillBytes(make([]byte, key.Size())), options); !errors.Is(err, rsa.ErrVerification) {
			t.Fatal("signature representative >= N accepted")
		}
	}
}

func TestVerifyRSANonByteAlignedModulus(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2049)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256([]byte("non-byte-aligned modulus"))
	options := RSAPSSOptions{Hash: crypto.SHA256, MGF1Hash: crypto.SHA256, SaltLength: 0}
	em, err := rsascheme.EncodePSS(digest[:], key.N.BitLen()-1, nil, crypto.SHA256.New())
	if err != nil {
		t.Fatal(err)
	}
	if len(em) != key.Size()-1 {
		t.Fatal("expected emLen one less than modulus width")
	}
	sig := new(big.Int).Exp(new(big.Int).SetBytes(em), key.D, key.N).FillBytes(make([]byte, key.Size()))
	if err := VerifyRSA(&key.PublicKey, digest[:], sig, options); err != nil {
		t.Fatal(err)
	}
	if err := rsa.VerifyPSS(&key.PublicKey, crypto.SHA256, digest[:], sig, &rsa.PSSOptions{SaltLength: 0}); err != nil {
		t.Fatalf("independent non-byte-aligned verification: %v", err)
	}
}
