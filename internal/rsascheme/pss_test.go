package rsascheme

import (
	"bytes"
	"crypto/rsa"
	"crypto/sha256"
	"errors"
	"testing"
)

func TestPSSBitBoundariesAndExactSalt(t *testing.T) {
	digest := sha256.Sum256([]byte("PSS encoded-message boundary"))
	for _, bits := range []int{1023, 1024, 1025, 2047, 2048, 2049} {
		emLen := (bits + 7) / 8
		for _, saltLength := range []int{0, 1, 32, emLen - 32 - 2} {
			salt := bytes.Repeat([]byte{0x5a}, saltLength)
			em, err := EncodePSS(digest[:], bits, salt, sha256.New())
			if err != nil {
				t.Fatal(err)
			}
			if len(em) != emLen || em[0] & ^byte(0xff>>(8*emLen-bits)) != 0 {
				t.Fatalf("incorrect emBits=%d encoding", bits)
			}
			copy := append([]byte(nil), em...)
			if err := VerifyPSS(digest[:], em, bits, saltLength, sha256.New()); err != nil {
				t.Fatalf("bits=%d salt=%d: %v", bits, saltLength, err)
			}
			if !bytes.Equal(em, copy) {
				t.Fatal("verification changed its encoded input")
			}
			wrongSalt := (saltLength + 1) % (emLen - 32 - 1)
			if err := VerifyPSS(digest[:], em, bits, wrongSalt, sha256.New()); !errors.Is(err, rsa.ErrVerification) {
				t.Fatalf("salt %d accepted as %d", saltLength, wrongSalt)
			}
		}
	}
}

func TestPSSRejectsInvalidEncodings(t *testing.T) {
	digest := sha256.Sum256([]byte("PSS invalid encoding"))
	em, err := EncodePSS(digest[:], 2047, nil, sha256.New())
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name  string
		input []byte
		bits  int
		salt  int
	}{
		{"short", em[1:], 2047, 0},
		{"empty", nil, 2047, 0},
		{"negative-bits", em, -1, 0},
		{"zero-bits", em, 0, 0},
		{"overflow-bits", em, int(^uint(0) >> 1), 0},
		{"negative-salt", em, 2047, -1},
		{"overflow-salt", em, 2047, int(^uint(0) >> 1)},
		{"too-long-salt", em, 2047, 223},
		{"wrong-salt", em, 2047, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := VerifyPSS(digest[:], tc.input, tc.bits, tc.salt, sha256.New()); !errors.Is(err, rsa.ErrVerification) {
				t.Fatalf("expected verification error, got %v", err)
			}
		})
	}
	for _, index := range []int{0, 1, 200, len(em) - 1} {
		corrupt := append([]byte(nil), em...)
		corrupt[index] ^= 0x80
		if err := VerifyPSS(digest[:], corrupt, 2047, 0, sha256.New()); !errors.Is(err, rsa.ErrVerification) {
			t.Fatalf("corrupted byte %d accepted", index)
		}
	}
	for _, bits := range []int{-1, 0, 1, int(^uint(0) >> 1)} {
		if _, err := EncodePSS(digest[:], bits, nil, sha256.New()); err == nil {
			t.Fatalf("invalid bit length %d accepted", bits)
		}
	}
	if _, err := EncodePSS(digest[:31], 2047, nil, sha256.New()); err == nil {
		t.Fatal("wrong digest length accepted")
	}
	if _, err := EncodePSS(digest[:], 2047, make([]byte, 223), sha256.New()); !errors.Is(err, rsa.ErrMessageTooLong) {
		t.Fatalf("overlong salt accepted: %v", err)
	}
}
