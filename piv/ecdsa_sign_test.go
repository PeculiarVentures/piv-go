package piv

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/asn1"
	"errors"
	"math/big"
	"testing"

	"github.com/PeculiarVentures/piv-go/emulator"
	"github.com/PeculiarVentures/piv-go/iso7816"
)

func TestSignECDSAHashToIntegerInteroperability(t *testing.T) {
	message := []byte("ECDSA digest lengths must not change the signed message")
	h256, h384, h512 := sha256.Sum256(message), sha512.Sum384(message), sha512.Sum512(message)
	for _, tc := range []struct {
		name      string
		curve     elliptic.Curve
		algorithm byte
		width     int
	}{
		{"P256", elliptic.P256(), AlgECCP256, 32},
		{"P384", elliptic.P384(), AlgECCP384, 48},
	} {
		t.Run(tc.name, func(t *testing.T) {
			key, err := ecdsa.GenerateKey(tc.curve, rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			for _, digest := range [][]byte{h256[:], h384[:], h512[:]} {
				card := emulator.NewCard()
				if err := ValidateECDSASignRequest(tc.algorithm, &key.PublicKey, digest); err != nil {
					t.Fatalf("valid preflight request: %v", err)
				}
				card.RegisterINSHandler(0x87, func(_ *emulator.Card, raw []byte) ([]byte, error) {
					if raw[2] != tc.algorithm || raw[3] != byte(SlotSignature) {
						t.Fatal("wrong protocol key reference")
					}
					challenge := mldsaSignChallenge(t, raw)
					if len(challenge) != tc.width {
						t.Fatalf("challenge width %d, want %d", len(challenge), tc.width)
					}
					sig, err := ecdsa.SignASN1(rand.Reader, key, challenge)
					if err != nil {
						return nil, err
					}
					return emulator.BuildSuccessResponse(iso7816.EncodeTLV(0x7C, iso7816.EncodeTLV(0x82, sig))), nil
				})
				sig, err := NewClient(card).SignECDSA(tc.algorithm, SlotSignature, &key.PublicKey, digest)
				if err != nil {
					t.Fatal(err)
				}
				if !ecdsa.VerifyASN1(&key.PublicKey, digest, sig) {
					t.Fatalf("signature did not verify against original %d-byte digest", len(digest))
				}
				if len(card.TransmittedCommands) != 1 {
					t.Fatal("unexpected APDU count")
				}
			}
		})
	}
}

func TestPrepareECDSADigestP521Boundaries(t *testing.T) {
	curve := elliptic.P521()
	key := &ecdsa.PublicKey{Curve: curve, X: curve.Params().Gx, Y: curve.Params().Gy}
	for _, tc := range []struct{ digest, want []byte }{
		{bytes.Repeat([]byte{0xFF}, 80), append([]byte{1}, bytes.Repeat([]byte{0xFF}, 65)...)},
		{bytes.Repeat([]byte{0xA5}, 64), append([]byte{0, 0}, bytes.Repeat([]byte{0xA5}, 64)...)},
	} {
		original := append([]byte(nil), tc.digest...)
		got, err := PrepareECDSADigest(key, tc.digest)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, tc.want) {
			t.Fatalf("got %x, want %x", got, tc.want)
		}
		if !bytes.Equal(tc.digest, original) {
			t.Fatal("digest modified")
		}
	}
}

func TestSignECDSARejectsBeforeAPDU(t *testing.T) {
	curve := elliptic.P256()
	valid := &ecdsa.PublicKey{Curve: curve, X: curve.Params().Gx, Y: curve.Params().Gy}
	for _, tc := range []struct {
		key       *ecdsa.PublicKey
		algorithm byte
		digest    []byte
	}{
		{nil, AlgECCP256, []byte{1}},
		{&ecdsa.PublicKey{}, AlgECCP256, []byte{1}},
		{&ecdsa.PublicKey{Curve: curve, X: big.NewInt(1), Y: big.NewInt(1)}, AlgECCP256, []byte{1}},
		{valid, AlgECCP256, nil},
		{valid, AlgECCP384, []byte{1}},
		{valid, AlgEd25519, []byte{1}},
	} {
		card := emulator.NewCard()
		if err := ValidateECDSASignRequest(tc.algorithm, tc.key, tc.digest); !errors.Is(err, ErrInvalidECDSAParameters) {
			t.Fatalf("preflight error = %v", err)
		}
		if _, err := NewClient(card).SignECDSA(tc.algorithm, SlotSignature, tc.key, tc.digest); !errors.Is(err, ErrInvalidECDSAParameters) {
			t.Fatalf("got %v", err)
		}
		if len(card.TransmittedCommands) != 0 {
			t.Fatal("invalid ECDSA request reached card")
		}
	}
}

func TestSignECDSANilClientFailsBeforePrivateOperation(t *testing.T) {
	curve := elliptic.P256()
	key := &ecdsa.PublicKey{Curve: curve, X: curve.Params().Gx, Y: curve.Params().Gy}
	for _, client := range []*Client{nil, NewClient(nil)} {
		if _, err := client.SignECDSA(AlgECCP256, SlotSignature, key, []byte{1}); !errors.Is(err, ErrInvalidECDSAParameters) || errors.Is(err, ErrInvalidSignatureResponse) {
			t.Fatalf("nil client must be a preflight failure, got %v", err)
		}
	}
}

func TestSignECDSARejectsMalformedResponse(t *testing.T) {
	curve := elliptic.P256()
	key := &ecdsa.PublicKey{Curve: curve, X: curve.Params().Gx, Y: curve.Params().Gy}
	for _, response := range [][]byte{
		{0x30, 0x00},
		{0x30, 0x06, 0x02, 0x01, 0x00, 0x02, 0x01, 0x01},
		{0x30, 0x09, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01},
	} {
		card := emulator.NewCard()
		card.SetSuccessResponse(0x87, iso7816.EncodeTLV(0x7C, iso7816.EncodeTLV(0x82, response)))
		if _, err := NewClient(card).SignECDSA(AlgECCP256, SlotSignature, key, []byte{1}); !errors.Is(err, ErrInvalidSignatureResponse) {
			t.Fatalf("malformed DER response must be identifiable after the private operation, got %v", err)
		}
		if len(card.TransmittedCommands) != 1 {
			t.Fatal("malformed response must not cause an automatic retry")
		}
	}
	oversized, err := asn1.Marshal(struct{ R, S *big.Int }{curve.Params().N, big.NewInt(1)})
	if err != nil {
		t.Fatal(err)
	}
	card := emulator.NewCard()
	card.SetSuccessResponse(0x87, iso7816.EncodeTLV(0x7C, iso7816.EncodeTLV(0x82, oversized)))
	if _, err := NewClient(card).SignECDSA(AlgECCP256, SlotSignature, key, []byte{1}); !errors.Is(err, ErrInvalidSignatureResponse) {
		t.Fatalf("out-of-range scalar response error = %v", err)
	}
}
