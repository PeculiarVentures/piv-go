package piv

import (
	"bytes"
	"crypto"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha512"
	"encoding/asn1"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/PeculiarVentures/piv-go/emulator"
	"github.com/PeculiarVentures/piv-go/iso7816"
)

type mldsaExtendedOptions struct {
	hash    crypto.Hash
	context string
}

func (o *mldsaExtendedOptions) HashFunc() crypto.Hash { return o.hash }

type mldsaPanickingOptions struct{}

func (mldsaPanickingOptions) HashFunc() crypto.Hash { panic("must not inspect unknown options") }

type mldsaPanickingReader struct{}

func (mldsaPanickingReader) Read([]byte) (int, error) {
	panic("card randomness is not host-controlled")
}

func TestMLDSASignerRejectsUnsupportedOptionsBeforeAPDU(t *testing.T) {
	for _, algorithm := range mldsaTestAlgorithms {
		publicKey, _ := mldsaKATKey(t, algorithm)
		for _, test := range []struct {
			name string
			opts crypto.SignerOpts
		}{
			{"SHA256", crypto.SHA256},
			{"SHA512", crypto.SHA512},
			{"invalid_hash", crypto.Hash(999)},
			{"extended_zero_hash", &mldsaExtendedOptions{context: "context"}},
			{"extended_nonzero_hash", &mldsaExtendedOptions{hash: crypto.SHA512}},
			{"unknown_method_panics", mldsaPanickingOptions{}},
			{"typed_nil_extended", (*mldsaExtendedOptions)(nil)},
			{"typed_nil_hash", (*crypto.Hash)(nil)},
			{"EdDSA_options", &ed25519.Options{}},
			{"typed_nil_EdDSA_options", (*ed25519.Options)(nil)},
			{"RSA_options", &rsa.PSSOptions{}},
		} {
			t.Run(fmt.Sprintf("%02X/%s", algorithm, test.name), func(t *testing.T) {
				card := emulator.NewCard()
				signer, err := NewMLDSASigner(NewClient(card), SlotSignature, algorithm,
					&OpaquePublicKey{Algorithm: algorithm, Raw: publicKey})
				if err != nil {
					t.Fatal(err)
				}
				signature, err := signer.Sign(mldsaPanickingReader{}, []byte("message"), test.opts)
				if !errors.Is(err, ErrUnsupportedMLDSAOptions) || !errors.Is(err, ErrMLDSAOptionsUnsupported) {
					t.Fatalf("error = %v, want both ML-DSA options error names", err)
				}
				if signature != nil || len(card.TransmittedCommands) != 0 {
					t.Fatalf("unsupported options returned a signature or sent %d APDUs", len(card.TransmittedCommands))
				}
			})
		}
	}
}

func TestMLDSAOptionsErrorCompatibilityAlias(t *testing.T) {
	if ErrUnsupportedMLDSAOptions != ErrMLDSAOptionsUnsupported {
		t.Fatal("ML-DSA options compatibility name must identify the same error")
	}
}

func TestMLDSASignerBadSignatureLengthIsPostOperationError(t *testing.T) {
	for _, algorithm := range mldsaTestAlgorithms {
		publicKey, _ := mldsaKATKey(t, algorithm)
		size, _ := MLDSASignatureLength(algorithm)
		for _, length := range []int{size - 1, size + 1} {
			card := emulator.NewCard()
			card.SetSuccessResponse(0x87, iso7816.EncodeTLV(0x7C, iso7816.EncodeTLV(0x82, make([]byte, length))))
			signer, err := NewMLDSASigner(NewClient(card), SlotSignature, algorithm,
				&OpaquePublicKey{Algorithm: algorithm, Raw: publicKey})
			if err != nil {
				t.Fatal(err)
			}
			if signature, err := signer.Sign(nil, []byte("message"), nil); signature != nil || !errors.Is(err, ErrInvalidSignatureResponse) {
				t.Fatalf("algorithm %02X length %d: got %v", algorithm, length, err)
			}
			if len(card.TransmittedCommands) != 1 {
				t.Fatal("bad ML-DSA response must not cause an automatic retry")
			}
		}
	}
}

func TestMLDSASignerPureOptionsPreserveMessage(t *testing.T) {
	for _, algorithm := range mldsaTestAlgorithms {
		publicKey, _ := mldsaKATKey(t, algorithm)
		for _, message := range [][]byte{nil, make([]byte, 32), bytes.Repeat([]byte{0x00, 0x7C, 0x81, 0xFF}, 256)} {
			for _, opts := range []crypto.SignerOpts{nil, crypto.Hash(0)} {
				t.Run(fmt.Sprintf("%02X/length_%d/options_%T", algorithm, len(message), opts), func(t *testing.T) {
					card := emulator.NewCard()
					size, _ := MLDSASignatureLength(algorithm)
					wantSignature := bytes.Repeat([]byte{0x5A}, size)
					card.SetSuccessResponse(0x87, iso7816.EncodeTLV(0x7C, iso7816.EncodeTLV(0x82, wantSignature)))
					signer, err := NewMLDSASigner(NewClient(card), SlotSignature, algorithm,
						&OpaquePublicKey{Algorithm: algorithm, Raw: publicKey})
					if err != nil {
						t.Fatal(err)
					}
					got, err := signer.Sign(mldsaPanickingReader{}, message, opts)
					if err != nil {
						t.Fatal(err)
					}
					if !bytes.Equal(got, wantSignature) || len(card.TransmittedCommands) != 1 {
						t.Fatalf("signature or APDU count differs: %d commands", len(card.TransmittedCommands))
					}
					if got := mldsaSignChallenge(t, card.TransmittedCommands[0]); !bytes.Equal(got, message) {
						t.Fatal("pure signing changed message bytes")
					}
				})
			}
		}
	}
}

// These signatures were produced and verified by OpenSSL, independently of
// CIRCL. See testdata/mldsa-openssl/README.md for commands and domain encodings.
func TestMLDSASignerIndependentPureVector(t *testing.T) {
	readFixture := func(name string) []byte {
		t.Helper()
		data, err := os.ReadFile(filepath.Join("testdata", "mldsa-openssl", name))
		if err != nil {
			t.Fatal(err)
		}
		return data
	}
	var spki mldsaSubjectPublicKeyInfo
	if rest, err := asn1.Unmarshal(readFixture("mldsa44-public.der"), &spki); err != nil || len(rest) != 0 {
		t.Fatalf("invalid independent public key: %v", err)
	}
	if !spki.Algorithm.Algorithm.Equal(MLDSAOID44) || !spki.Algorithm.paramsAbsent() {
		t.Fatal("independent public key does not identify ML-DSA-44")
	}
	publicKey := spki.SubjectPublicKey.Bytes
	message := []byte("piv-go independent ML-DSA signing options vector")
	digest := sha512.Sum512(message)
	for _, test := range []struct {
		name    string
		message []byte
		opts    crypto.SignerOpts
	}{
		{"pure-message.sig", message, nil},
		{"pure-sha512.sig", digest[:], crypto.Hash(0)},
	} {
		t.Run(test.name, func(t *testing.T) {
			want := readFixture(test.name)
			card := emulator.NewCard()
			card.SetSuccessResponse(0x87, iso7816.EncodeTLV(0x7C, iso7816.EncodeTLV(0x82, want)))
			signer, err := NewMLDSASigner(NewClient(card), SlotSignature, AlgMLDSA44,
				&OpaquePublicKey{Algorithm: AlgMLDSA44, Raw: publicKey})
			if err != nil {
				t.Fatal(err)
			}
			signature, err := signer.Sign(nil, test.message, test.opts)
			if err != nil {
				t.Fatal(err)
			}
			if len(card.TransmittedCommands) != 1 || !bytes.Equal(mldsaSignChallenge(t, card.TransmittedCommands[0]), test.message) {
				t.Fatal("independent vector input was changed")
			}
			if err := VerifyMLDSASignature(AlgMLDSA44, publicKey, test.message, signature); err != nil {
				t.Fatalf("OpenSSL pure signature failed verification: %v", err)
			}
		})
	}
	// HashML-DSA(SHA-512) uses a distinct internal domain. Its independently
	// generated signature must not verify as pure ML-DSA over SHA512(message).
	// Conversely, OpenSSL rejects pure-sha512.sig in that HashML-DSA domain;
	// that check is recorded in the fixture-generation instructions.
	if err := VerifyMLDSASignature(AlgMLDSA44, publicKey, digest[:], readFixture("hashmldsa-sha512.sig")); err == nil {
		t.Fatal("HashML-DSA signature accepted as pure ML-DSA over a hash")
	}
}
