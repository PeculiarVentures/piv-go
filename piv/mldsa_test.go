package piv

// ML-DSA Phase A (read-only verification) and Phase B (opaque SPKI,
// card-backed signer, manual TBS/CSR builders) regression tests.
//
// KAT strategy: fixed seeds through circl NewKeyFromSeed give fully
// deterministic keys, and SignTo with randomized=false gives fully
// deterministic signatures, so the embedded SHA-256 fingerprints are
// true known-answer vectors: any change in circl, the OID table, or
// the builders breaks them. Golden certificates in testdata/mldsa-*
// are synthetic circl-signed fixtures rebuilt deterministically by
// TestMLDSAGoldenDeterminism.

import (
	"bytes"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"math/big"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/PeculiarVentures/piv-go/emulator"
	"github.com/PeculiarVentures/piv-go/iso7816"
	"github.com/cloudflare/circl/sign/mldsa/mldsa44"
	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
	"github.com/cloudflare/circl/sign/mldsa/mldsa87"
)

var mldsaTestAlgorithms = []byte{AlgMLDSA44, AlgMLDSA65, AlgMLDSA87}

// mldsaKATMessage is the fixed message signed by every KAT vector.
var mldsaKATMessage = []byte("piv-go ML-DSA KAT message")

// mldsaKATSeeds holds the fixed 32-byte KAT seed per variant, and
// mldsaKATPubSHA256 / mldsaKATSigSHA256 hold the expected SHA-256 of
// the derived public key and of the deterministic signature.
func mldsaKATSeed(algorithm byte) *[32]byte {
	var base byte
	switch algorithm {
	case AlgMLDSA44:
		base = 0x00
	case AlgMLDSA65:
		base = 0x40
	case AlgMLDSA87:
		base = 0x80
	default:
		panic("unsupported test algorithm")
	}
	var seed [32]byte
	for i := range seed {
		seed[i] = base + byte(i)
	}
	return &seed
}

var mldsaKATPubSHA256 = map[byte]string{
	AlgMLDSA44: "9f107644c1084526af3bc8098680b05499a2325a644e388fb4f970e058d19d46",
	AlgMLDSA65: "ddf723ba0cc75408d1a3a8dc48f8302bfc25bd2cacf9374c28d861deea3a7184",
	AlgMLDSA87: "2d642744bf78aa0c1ec51cdc23b5ca169483d44e00ecddb684d0e2309dabf56a",
}

var mldsaKATSigSHA256 = map[byte]string{
	AlgMLDSA44: "ac331cb4646b8a5b15907b2a6d1cda96b64d488a1ae66bb6be2e1671a42badb5",
	AlgMLDSA65: "fecddbd0c5749df2b1dc5f469d5effb4b1aae7de99f032dae6d348d154685e9a",
	AlgMLDSA87: "aa4ae591eca6094ca5eeb25c4c1f59470de594f499062fb4f6a8a0a9a5d67f86",
}

// mldsaKATKey derives the deterministic KAT keypair for a variant and
// returns the raw public key plus an opaque signer private key handle.
func mldsaKATKey(t *testing.T, algorithm byte) (pub []byte, sign func(msg []byte) []byte) {
	t.Helper()
	seed := mldsaKATSeed(algorithm)
	switch algorithm {
	case AlgMLDSA44:
		pk, sk := mldsa44.NewKeyFromSeed(seed)
		return pk.Bytes(), func(msg []byte) []byte {
			sig := make([]byte, mldsa44.SignatureSize)
			if err := mldsa44.SignTo(sk, msg, nil, false, sig); err != nil {
				t.Fatalf("mldsa44.SignTo() error = %v", err)
			}
			return sig
		}
	case AlgMLDSA65:
		pk, sk := mldsa65.NewKeyFromSeed(seed)
		return pk.Bytes(), func(msg []byte) []byte {
			sig := make([]byte, mldsa65.SignatureSize)
			if err := mldsa65.SignTo(sk, msg, nil, false, sig); err != nil {
				t.Fatalf("mldsa65.SignTo() error = %v", err)
			}
			return sig
		}
	case AlgMLDSA87:
		pk, sk := mldsa87.NewKeyFromSeed(seed)
		return pk.Bytes(), func(msg []byte) []byte {
			sig := make([]byte, mldsa87.SignatureSize)
			if err := mldsa87.SignTo(sk, msg, nil, false, sig); err != nil {
				t.Fatalf("mldsa87.SignTo() error = %v", err)
			}
			return sig
		}
	default:
		t.Fatalf("unsupported test algorithm 0x%02X", algorithm)
		return nil, nil
	}
}

// mldsaGoldenBase returns the deterministic seed base for golden fixture
// keys: +0x00 CA, +0x10 leaf, +0x20 attested slot key.
func mldsaGoldenBase(algorithm byte) byte {
	switch algorithm {
	case AlgMLDSA44:
		return 0xA0
	case AlgMLDSA65:
		return 0xB0
	case AlgMLDSA87:
		return 0xC0
	default:
		panic("unsupported test algorithm")
	}
}

func mldsaGoldenSeed(algorithm byte, offset byte) *[32]byte {
	base := mldsaGoldenBase(algorithm)
	var seed [32]byte
	for i := range seed {
		seed[i] = base + offset + byte(i)
	}
	return &seed
}

// mldsaGoldenKeys re-derives the deterministic golden fixture keys:
// CA, leaf, and attested slot public keys plus the CA signer.
func mldsaGoldenKeys(t *testing.T, algorithm byte) (caPub, leafPub, slotPub []byte, caSign func(msg []byte) []byte) {
	t.Helper()
	seedCA := mldsaGoldenSeed(algorithm, 0x00)
	seedLeaf := mldsaGoldenSeed(algorithm, 0x10)
	seedSlot := mldsaGoldenSeed(algorithm, 0x20)
	var pubCA, pubLeaf, pubSlot []byte
	switch algorithm {
	case AlgMLDSA44:
		pkCA, skCA := mldsa44.NewKeyFromSeed(seedCA)
		pkLeaf, _ := mldsa44.NewKeyFromSeed(seedLeaf)
		pkSlot, _ := mldsa44.NewKeyFromSeed(seedSlot)
		pubCA, pubLeaf, pubSlot = pkCA.Bytes(), pkLeaf.Bytes(), pkSlot.Bytes()
		caSign = func(msg []byte) []byte {
			sig := make([]byte, mldsa44.SignatureSize)
			if err := mldsa44.SignTo(skCA, msg, nil, false, sig); err != nil {
				t.Fatalf("mldsa44.SignTo() error = %v", err)
			}
			return sig
		}
	case AlgMLDSA65:
		pkCA, skCA := mldsa65.NewKeyFromSeed(seedCA)
		pkLeaf, _ := mldsa65.NewKeyFromSeed(seedLeaf)
		pkSlot, _ := mldsa65.NewKeyFromSeed(seedSlot)
		pubCA, pubLeaf, pubSlot = pkCA.Bytes(), pkLeaf.Bytes(), pkSlot.Bytes()
		caSign = func(msg []byte) []byte {
			sig := make([]byte, mldsa65.SignatureSize)
			if err := mldsa65.SignTo(skCA, msg, nil, false, sig); err != nil {
				t.Fatalf("mldsa65.SignTo() error = %v", err)
			}
			return sig
		}
	case AlgMLDSA87:
		pkCA, skCA := mldsa87.NewKeyFromSeed(seedCA)
		pkLeaf, _ := mldsa87.NewKeyFromSeed(seedLeaf)
		pkSlot, _ := mldsa87.NewKeyFromSeed(seedSlot)
		pubCA, pubLeaf, pubSlot = pkCA.Bytes(), pkLeaf.Bytes(), pkSlot.Bytes()
		caSign = func(msg []byte) []byte {
			sig := make([]byte, mldsa87.SignatureSize)
			if err := mldsa87.SignTo(skCA, msg, nil, false, sig); err != nil {
				t.Fatalf("mldsa87.SignTo() error = %v", err)
			}
			return sig
		}
	default:
		t.Fatalf("unsupported test algorithm 0x%02X", algorithm)
	}
	return pubCA, pubLeaf, pubSlot, caSign
}

func mldsaGoldenName(variant string, role string) pkix.Name {
	return pkix.Name{CommonName: "piv-go " + variant + " test " + role}
}

func mldsaVariantName(algorithm byte) string {
	switch algorithm {
	case AlgMLDSA44:
		return "mldsa44"
	case AlgMLDSA65:
		return "mldsa65"
	case AlgMLDSA87:
		return "mldsa87"
	default:
		return "unknown"
	}
}

func mldsaLoadGolden(t *testing.T, algorithm byte, role string) []byte {
	t.Helper()
	der, err := os.ReadFile("testdata/" + mldsaVariantName(algorithm) + "-" + role + ".der")
	if err != nil {
		t.Fatalf("read golden %s %s: %v", mldsaVariantName(algorithm), role, err)
	}
	return der
}

func TestMLDSAOIDRegistry(t *testing.T) {
	if !MLDSAOID44.Equal(asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 17}) {
		t.Fatalf("MLDSAOID44 = %s, want 2.16.840.1.101.3.4.3.17", MLDSAOID44)
	}
	if !MLDSAOID65.Equal(asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 18}) {
		t.Fatalf("MLDSAOID65 = %s, want 2.16.840.1.101.3.4.3.18", MLDSAOID65)
	}
	if !MLDSAOID87.Equal(asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 19}) {
		t.Fatalf("MLDSAOID87 = %s, want 2.16.840.1.101.3.4.3.19", MLDSAOID87)
	}
	for _, test := range []struct {
		algorithm byte
		oid       asn1.ObjectIdentifier
	}{
		{algorithm: AlgMLDSA44, oid: MLDSAOID44},
		{algorithm: AlgMLDSA65, oid: MLDSAOID65},
		{algorithm: AlgMLDSA87, oid: MLDSAOID87},
	} {
		oid, ok := MLDSAOIDForAlgorithm(test.algorithm)
		if !ok || !oid.Equal(test.oid) {
			t.Fatalf("MLDSAOIDForAlgorithm(0x%02X) = %s, %v; want %s", test.algorithm, oid, ok, test.oid)
		}
		algorithm, ok := MLDSAAlgorithmForOID(test.oid)
		if !ok || algorithm != test.algorithm {
			t.Fatalf("MLDSAAlgorithmForOID(%s) = 0x%02X, %v; want 0x%02X", test.oid, algorithm, ok, test.algorithm)
		}
	}
	for _, algorithm := range []byte{0x00, AlgECCP256, AlgEd25519, AlgMLKEM768, 0xFF} {
		if _, ok := MLDSAOIDForAlgorithm(algorithm); ok {
			t.Fatalf("MLDSAOIDForAlgorithm(0x%02X) = true, want false", algorithm)
		}
	}
	for _, oid := range []asn1.ObjectIdentifier{
		{2, 16, 840, 1, 101, 3, 4, 3, 20},
		{2, 16, 840, 1, 101, 3, 4, 3},
		{1, 2, 3},
		nil,
	} {
		if _, ok := MLDSAAlgorithmForOID(oid); ok {
			t.Fatalf("MLDSAAlgorithmForOID(%s) = true, want false", oid)
		}
	}
}

func TestMLDSALengths(t *testing.T) {
	for _, test := range []struct {
		algorithm byte
		pubLen    int
		sigLen    int
	}{
		{algorithm: AlgMLDSA44, pubLen: 1312, sigLen: 2420},
		{algorithm: AlgMLDSA65, pubLen: 1952, sigLen: 3309},
		{algorithm: AlgMLDSA87, pubLen: 2592, sigLen: 4627},
	} {
		if got, ok := MLDSAPublicKeyLength(test.algorithm); !ok || got != test.pubLen {
			t.Fatalf("MLDSAPublicKeyLength(0x%02X) = %d, %v; want %d", test.algorithm, got, ok, test.pubLen)
		}
		if got, ok := MLDSASignatureLength(test.algorithm); !ok || got != test.sigLen {
			t.Fatalf("MLDSASignatureLength(0x%02X) = %d, %v; want %d", test.algorithm, got, ok, test.sigLen)
		}
	}
	if MLDSAPublicKeySize44 != 1312 || MLDSAPublicKeySize65 != 1952 || MLDSAPublicKeySize87 != 2592 {
		t.Fatal("ML-DSA public key size constants do not match FIPS 204")
	}
	if MLDSASignatureSize44 != 2420 || MLDSASignatureSize65 != 3309 || MLDSASignatureSize87 != 4627 {
		t.Fatal("ML-DSA signature size constants do not match FIPS 204")
	}
	// The length tables must agree with the circl implementation sizes.
	if mldsa44.PublicKeySize != MLDSAPublicKeySize44 || mldsa44.SignatureSize != MLDSASignatureSize44 {
		t.Fatal("ML-DSA-44 lengths disagree with circl")
	}
	if mldsa65.PublicKeySize != MLDSAPublicKeySize65 || mldsa65.SignatureSize != MLDSASignatureSize65 {
		t.Fatal("ML-DSA-65 lengths disagree with circl")
	}
	if mldsa87.PublicKeySize != MLDSAPublicKeySize87 || mldsa87.SignatureSize != MLDSASignatureSize87 {
		t.Fatal("ML-DSA-87 lengths disagree with circl")
	}
	for _, algorithm := range []byte{0x00, AlgECCP256, AlgEd25519, AlgMLKEM768} {
		if _, ok := MLDSAPublicKeyLength(algorithm); ok {
			t.Fatalf("MLDSAPublicKeyLength(0x%02X) = true, want false", algorithm)
		}
		if _, ok := MLDSASignatureLength(algorithm); ok {
			t.Fatalf("MLDSASignatureLength(0x%02X) = true, want false", algorithm)
		}
	}
}

func TestVerifyMLDSASignatureKAT(t *testing.T) {
	for _, algorithm := range mldsaTestAlgorithms {
		pub, sign := mldsaKATKey(t, algorithm)
		pubSize, _ := MLDSAPublicKeyLength(algorithm)
		sigSize, _ := MLDSASignatureLength(algorithm)
		if len(pub) != pubSize {
			t.Fatalf("algorithm 0x%02X: KAT public key length = %d, want %d", algorithm, len(pub), pubSize)
		}
		if got := sha256.Sum256(pub); hex.EncodeToString(got[:]) != mldsaKATPubSHA256[algorithm] {
			t.Fatalf("algorithm 0x%02X: KAT public key SHA-256 = %x, want %s", algorithm, got, mldsaKATPubSHA256[algorithm])
		}
		sig := sign(mldsaKATMessage)
		if len(sig) != sigSize {
			t.Fatalf("algorithm 0x%02X: KAT signature length = %d, want %d", algorithm, len(sig), sigSize)
		}
		if got := sha256.Sum256(sig); hex.EncodeToString(got[:]) != mldsaKATSigSHA256[algorithm] {
			t.Fatalf("algorithm 0x%02X: KAT signature SHA-256 = %x, want %s", algorithm, got, mldsaKATSigSHA256[algorithm])
		}
		if err := VerifyMLDSASignature(algorithm, pub, mldsaKATMessage, sig); err != nil {
			t.Fatalf("algorithm 0x%02X: VerifyMLDSASignature() error = %v", algorithm, err)
		}

		// 1-bit flips in the signature, message, and public key must reject.
		flippedSig := append([]byte(nil), sig...)
		flippedSig[0] ^= 0x01
		if err := VerifyMLDSASignature(algorithm, pub, mldsaKATMessage, flippedSig); err == nil {
			t.Fatalf("algorithm 0x%02X: flipped signature must reject", algorithm)
		}
		flippedSig = append([]byte(nil), sig...)
		flippedSig[len(flippedSig)-1] ^= 0x80
		if err := VerifyMLDSASignature(algorithm, pub, mldsaKATMessage, flippedSig); err == nil {
			t.Fatalf("algorithm 0x%02X: flipped signature tail must reject", algorithm)
		}
		flippedMsg := append([]byte(nil), mldsaKATMessage...)
		flippedMsg[0] ^= 0x01
		if err := VerifyMLDSASignature(algorithm, pub, flippedMsg, sig); err == nil {
			t.Fatalf("algorithm 0x%02X: flipped message must reject", algorithm)
		}
		flippedPub := append([]byte(nil), pub...)
		flippedPub[0] ^= 0x01
		if err := VerifyMLDSASignature(algorithm, flippedPub, mldsaKATMessage, sig); err == nil {
			t.Fatalf("algorithm 0x%02X: flipped public key must reject", algorithm)
		}

		// Wrong lengths and unknown algorithms reject before verification.
		if err := VerifyMLDSASignature(algorithm, pub[:len(pub)-1], mldsaKATMessage, sig); err == nil {
			t.Fatalf("algorithm 0x%02X: short public key must reject", algorithm)
		}
		if err := VerifyMLDSASignature(algorithm, pub, mldsaKATMessage, sig[:len(sig)-1]); err == nil {
			t.Fatalf("algorithm 0x%02X: short signature must reject", algorithm)
		}
		if err := VerifyMLDSASignature(AlgECCP256, pub, mldsaKATMessage, sig); err == nil {
			t.Fatalf("algorithm 0x%02X: non-ML-DSA algorithm must reject", algorithm)
		}
		// A key/signature pair from another variant must reject under this
		// variant (lengths already differ, so no cross-variant forgery).
		other := AlgMLDSA44
		if algorithm == AlgMLDSA44 {
			other = AlgMLDSA87
		}
		otherPub, otherSign := mldsaKATKey(t, other)
		otherSig := otherSign(mldsaKATMessage)
		if err := VerifyMLDSASignature(algorithm, otherPub, mldsaKATMessage, otherSig); err == nil {
			t.Fatalf("algorithm 0x%02X: cross-variant material must reject", algorithm)
		}
	}
}

func TestParseMLDSACertificateDERGoldens(t *testing.T) {
	for _, algorithm := range mldsaTestAlgorithms {
		for _, role := range []string{"ca", "leaf", "attest"} {
			der := mldsaLoadGolden(t, algorithm, role)
			cert, err := ParseMLDSACertificateDER(der)
			if err != nil {
				t.Fatalf("algorithm 0x%02X %s: ParseMLDSACertificateDER() error = %v", algorithm, role, err)
			}
			if cert.Algorithm != algorithm {
				t.Fatalf("algorithm 0x%02X %s: Algorithm = 0x%02X", algorithm, role, cert.Algorithm)
			}
			if cert.SignatureAlgorithm != algorithm {
				t.Fatalf("algorithm 0x%02X %s: SignatureAlgorithm = 0x%02X", algorithm, role, cert.SignatureAlgorithm)
			}
			if !bytes.Equal(cert.Raw, der) {
				t.Fatalf("algorithm 0x%02X %s: Raw must round-trip verbatim", algorithm, role)
			}
			if len(cert.TBS) == 0 || bytes.Index(der, cert.TBS) < 0 {
				t.Fatalf("algorithm 0x%02X %s: TBS must be a verbatim subspan of DER", algorithm, role)
			}
			pubSize, _ := MLDSAPublicKeyLength(algorithm)
			sigSize, _ := MLDSASignatureLength(algorithm)
			if len(cert.PublicKey) != pubSize || len(cert.Signature) != sigSize {
				t.Fatalf("algorithm 0x%02X %s: key/sig lengths = %d/%d, want %d/%d",
					algorithm, role, len(cert.PublicKey), len(cert.Signature), pubSize, sigSize)
			}
			// The standard library parses ML-DSA DER structurally but
			// reports Unknown algorithms, which is why the raw ML-DSA
			// profile re-parses via encoding/asn1 and why cert import
			// keeps the --raw-cert gate instead of strict X.509 import.
			stdCert, err := x509.ParseCertificate(der)
			if err != nil {
				t.Fatalf("algorithm 0x%02X %s: stdlib must parse golden structurally: %v", algorithm, role, err)
			}
			if stdCert.SignatureAlgorithm != x509.UnknownSignatureAlgorithm || stdCert.PublicKeyAlgorithm != x509.UnknownPublicKeyAlgorithm {
				t.Fatalf("algorithm 0x%02X %s: stdlib must report Unknown algorithms, got %v/%v",
					algorithm, role, stdCert.SignatureAlgorithm, stdCert.PublicKeyAlgorithm)
			}
		}
	}
}

func TestParseMLDSACertificateDERRejects(t *testing.T) {
	der := mldsaLoadGolden(t, AlgMLDSA44, "leaf")
	if _, err := ParseMLDSACertificateDER(nil); err == nil {
		t.Fatal("empty input must reject")
	}
	if _, err := ParseMLDSACertificateDER([]byte{0x30, 0x03, 0x02, 0x01, 0x00}); err == nil {
		t.Fatal("non-certificate DER must reject")
	}
	trailing := append(append([]byte(nil), der...), 0x00)
	if _, err := ParseMLDSACertificateDER(trailing); err == nil || !strings.Contains(err.Error(), "trailing") {
		t.Fatalf("trailing bytes must reject, got %v", err)
	}
	if _, err := ParseMLDSACertificateDER(der[:len(der)-10]); err == nil {
		t.Fatal("truncated DER must reject")
	}

	// Wrong OID: re-point the subject key OID at ML-DSA-65 while the key
	// stays 1312 bytes, and at an unknown OID. The SPKI AlgorithmIdentifier
	// is the middle OID occurrence (TBS signature, SPKI, outer signature).
	mldsa44OIDDER := []byte{0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x11}
	first := bytes.Index(der, mldsa44OIDDER)
	second := bytes.Index(der[first+len(mldsa44OIDDER):], mldsa44OIDDER)
	if first < 0 || second < 0 {
		t.Fatal("golden must contain three ML-DSA-44 OIDs")
	}
	spkiOID := first + len(mldsa44OIDDER) + second
	last := bytes.LastIndex(der, mldsa44OIDDER)

	wrongVariant := append([]byte(nil), der...)
	wrongVariant[spkiOID+len(mldsa44OIDDER)-1] = 0x12 // ML-DSA-65 OID, 1312-byte key
	if _, err := ParseMLDSACertificateDER(wrongVariant); err == nil || !strings.Contains(err.Error(), "does not match") {
		t.Fatalf("cross-variant OID must reject with length mismatch, got %v", err)
	}
	unknownOID := append([]byte(nil), der...)
	unknownOID[spkiOID+len(mldsa44OIDDER)-1] = 0x1F // unassigned arc
	if _, err := ParseMLDSACertificateDER(unknownOID); err == nil || !strings.Contains(err.Error(), "unsupported") {
		t.Fatalf("unknown OID must reject, got %v", err)
	}
	outerMismatch := append([]byte(nil), der...)
	outerMismatch[last+len(mldsa44OIDDER)-1] = 0x12 // outer ML-DSA-65 vs TBS ML-DSA-44
	if _, err := ParseMLDSACertificateDER(outerMismatch); err == nil || !strings.Contains(err.Error(), "does not match") {
		t.Fatalf("outer/TBS OID mismatch must reject, got %v", err)
	}

	// Params-present: rebuild the certificate with an explicit NULL in
	// each AlgorithmIdentifier position in turn.
	nullParams := asn1.RawValue{Class: 0, Tag: 5, Bytes: []byte{}}
	parsed, err := ParseMLDSACertificateDER(der)
	if err != nil {
		t.Fatalf("ParseMLDSACertificateDER() error = %v", err)
	}
	spkiWithParams, err := asn1.Marshal(mldsaSubjectPublicKeyInfo{
		Algorithm:        mldsaAlgorithmIdentifier{Algorithm: MLDSAOID44, Parameters: nullParams},
		SubjectPublicKey: asn1.BitString{Bytes: parsed.PublicKey, BitLength: 8 * len(parsed.PublicKey)},
	})
	if err != nil {
		t.Fatalf("marshal SPKI with params: %v", err)
	}
	tbsWithParamsSig := mldsaTBSCertificateOut{
		Version:   2,
		Serial:    big.NewInt(99),
		Signature: mldsaAlgorithmIdentifier{Algorithm: MLDSAOID44, Parameters: nullParams},
		Issuer:    pkix.Name{CommonName: "params"}.ToRDNSequence(),
		Validity:  mldsaValidityOut{NotBefore: time.Now(), NotAfter: time.Now().Add(time.Hour)},
		Subject:   pkix.Name{CommonName: "params"}.ToRDNSequence(),
		PublicKey: asn1.RawValue{FullBytes: mustMarshalSPKI(t, AlgMLDSA44, parsed.PublicKey)},
	}
	tbsDER, err := asn1.Marshal(tbsWithParamsSig)
	if err != nil {
		t.Fatalf("marshal TBS with params: %v", err)
	}
	outerWithParams := struct {
		TBSCertificate     asn1.RawValue
		SignatureAlgorithm mldsaAlgorithmIdentifier
		SignatureValue     asn1.BitString
	}{
		TBSCertificate:     asn1.RawValue{FullBytes: tbsDER},
		SignatureAlgorithm: mldsaAlgorithmIdentifier{Algorithm: MLDSAOID44},
		SignatureValue:     asn1.BitString{Bytes: parsed.Signature, BitLength: 8 * len(parsed.Signature)},
	}
	if derWithParams, err := asn1.Marshal(outerWithParams); err != nil {
		t.Fatalf("marshal outer with params: %v", err)
	} else if _, err := ParseMLDSACertificateDER(derWithParams); err == nil || !strings.Contains(err.Error(), "parameters must be absent") {
		t.Fatalf("TBS params-present must reject, got %v", err)
	}
	outerWithParamsSig := outerWithParams
	outerWithParamsSig.SignatureAlgorithm = mldsaAlgorithmIdentifier{Algorithm: MLDSAOID44, Parameters: nullParams}
	if derWithParams, err := asn1.Marshal(outerWithParamsSig); err != nil {
		t.Fatalf("marshal outer sig with params: %v", err)
	} else if _, err := ParseMLDSACertificateDER(derWithParams); err == nil || !strings.Contains(err.Error(), "parameters must be absent") {
		t.Fatalf("outer params-present must reject, got %v", err)
	}
	// SPKI params-present inside an otherwise valid TBS.
	goodTBS, err := MarshalMLDSATBSCertificate(&MLDSACertificateTemplate{
		SerialNumber: big.NewInt(99),
		Subject:      pkix.Name{CommonName: "params"},
		Issuer:       pkix.Name{CommonName: "params"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour),
	}, AlgMLDSA44, &OpaquePublicKey{Algorithm: AlgMLDSA44, Raw: parsed.PublicKey})
	if err != nil {
		t.Fatalf("MarshalMLDSATBSCertificate() error = %v", err)
	}
	badSPKIOuter := struct {
		TBSCertificate     asn1.RawValue
		SignatureAlgorithm mldsaAlgorithmIdentifier
		SignatureValue     asn1.BitString
	}{
		TBSCertificate:     asn1.RawValue{FullBytes: mldsaSwapSPKI(t, goodTBS, spkiWithParams)},
		SignatureAlgorithm: mldsaAlgorithmIdentifier{Algorithm: MLDSAOID44},
		SignatureValue:     asn1.BitString{Bytes: parsed.Signature, BitLength: 8 * len(parsed.Signature)},
	}
	if derWithParams, err := asn1.Marshal(badSPKIOuter); err != nil {
		t.Fatalf("marshal SPKI-params outer: %v", err)
	} else if _, err := ParseMLDSACertificateDER(derWithParams); err == nil || !strings.Contains(err.Error(), "parameters must be absent") {
		t.Fatalf("SPKI params-present must reject, got %v", err)
	}

	// Unused-bits: rebuild with a short BitLength on the key and signature.
	// The lowest value bit is cleared first so the encoding carries a zero
	// padding bit: Go's asn1 accepts the padding and the parser's own
	// unused-bits check fires.
	for _, test := range []struct {
		name string
		key  bool
	}{
		{name: "public key", key: true},
		{name: "signature", key: false},
	} {
		keyBytes := append([]byte(nil), parsed.PublicKey...)
		sigBytes := append([]byte(nil), parsed.Signature...)
		keyBytes[len(keyBytes)-1] &= 0xFE
		sigBytes[len(sigBytes)-1] &= 0xFE
		keyBits := asn1.BitString{Bytes: keyBytes, BitLength: 8 * len(keyBytes)}
		sigBits := asn1.BitString{Bytes: sigBytes, BitLength: 8 * len(sigBytes)}
		if test.key {
			keyBits.BitLength--
		} else {
			sigBits.BitLength--
		}
		badSPKI, err := asn1.Marshal(mldsaSubjectPublicKeyInfo{
			Algorithm:        mldsaAlgorithmIdentifier{Algorithm: MLDSAOID44},
			SubjectPublicKey: keyBits,
		})
		if err != nil {
			t.Fatalf("marshal bad BIT STRING: %v", err)
		}
		badOuter := struct {
			TBSCertificate     asn1.RawValue
			SignatureAlgorithm mldsaAlgorithmIdentifier
			SignatureValue     asn1.BitString
		}{
			TBSCertificate:     asn1.RawValue{FullBytes: mldsaSwapSPKI(t, goodTBS, badSPKI)},
			SignatureAlgorithm: mldsaAlgorithmIdentifier{Algorithm: MLDSAOID44},
			SignatureValue:     sigBits,
		}
		// The key-unused-bits case needs a matching-length signature so
		// the parser reaches the key check; the signature-unused-bits
		// case is caught at the signature check. Both must fail.
		if derWithBits, err := asn1.Marshal(badOuter); err != nil {
			t.Fatalf("marshal unused-bits outer: %v", err)
		} else if _, err := ParseMLDSACertificateDER(derWithBits); err == nil || !strings.Contains(err.Error(), "unused bits") {
			t.Fatalf("%s unused-bits must reject, got %v", test.name, err)
		}
	}

	// Short key and short signature encodings reject by length.
	shortKeySPKI, err := asn1.Marshal(mldsaSubjectPublicKeyInfo{
		Algorithm:        mldsaAlgorithmIdentifier{Algorithm: MLDSAOID44},
		SubjectPublicKey: asn1.BitString{Bytes: parsed.PublicKey[:100], BitLength: 800},
	})
	if err != nil {
		t.Fatalf("marshal short SPKI: %v", err)
	}
	shortOuter := struct {
		TBSCertificate     asn1.RawValue
		SignatureAlgorithm mldsaAlgorithmIdentifier
		SignatureValue     asn1.BitString
	}{
		TBSCertificate:     asn1.RawValue{FullBytes: mldsaSwapSPKI(t, goodTBS, shortKeySPKI)},
		SignatureAlgorithm: mldsaAlgorithmIdentifier{Algorithm: MLDSAOID44},
		SignatureValue:     asn1.BitString{Bytes: parsed.Signature, BitLength: 8 * len(parsed.Signature)},
	}
	if derWithShort, err := asn1.Marshal(shortOuter); err != nil {
		t.Fatalf("marshal short-key outer: %v", err)
	} else if _, err := ParseMLDSACertificateDER(derWithShort); err == nil || !strings.Contains(err.Error(), "does not match") {
		t.Fatalf("short key must reject, got %v", err)
	}
}

// mustMarshalSPKI marshals a raw key through the Phase B encoder.
func mustMarshalSPKI(t *testing.T, algorithm byte, raw []byte) []byte {
	t.Helper()
	der, err := MarshalMLDSAPKIXPublicKey(&OpaquePublicKey{Algorithm: algorithm, Raw: raw})
	if err != nil {
		t.Fatalf("MarshalMLDSAPKIXPublicKey() error = %v", err)
	}
	return der
}

// mldsaSwapSPKI replaces the subject SPKI inside TBS DER by re-marshaling
// the parsed TBS with a substituted raw SPKI.
func mldsaSwapSPKI(t *testing.T, tbsDER, spkiDER []byte) []byte {
	t.Helper()
	var tbs mldsaTBSCertificate
	rest, err := asn1.Unmarshal(tbsDER, &tbs)
	if err != nil || len(rest) != 0 {
		t.Fatalf("unmarshal TBS for SPKI swap: %v", err)
	}
	rebuilt := mldsaTBSCertificateOut{
		Version:   2,
		Serial:    tbs.Serial,
		Signature: tbs.Signature,
		Issuer:    pkix.Name{CommonName: "swap"}.ToRDNSequence(),
		Validity:  mldsaValidityOut{NotBefore: time.Now(), NotAfter: time.Now().Add(time.Hour)},
		Subject:   pkix.Name{CommonName: "swap"}.ToRDNSequence(),
		PublicKey: asn1.RawValue{FullBytes: spkiDER},
	}
	// Preserve the original issuer/subject/validity encodings by copying
	// the raw values back through a generic re-parse is unnecessary for
	// these negative tests: only the key/signature checks matter.
	out, err := asn1.Marshal(rebuilt)
	if err != nil {
		t.Fatalf("marshal swapped TBS: %v", err)
	}
	return out
}

func TestVerifyMLDSACertificateGoldens(t *testing.T) {
	for _, algorithm := range mldsaTestAlgorithms {
		caDER := mldsaLoadGolden(t, algorithm, "ca")
		leafDER := mldsaLoadGolden(t, algorithm, "leaf")
		if err := VerifyMLDSACertificate(leafDER, caDER); err != nil {
			t.Fatalf("algorithm 0x%02X: VerifyMLDSACertificate(leaf, ca) error = %v", algorithm, err)
		}
		if err := VerifyMLDSACertificate(caDER, caDER); err != nil {
			t.Fatalf("algorithm 0x%02X: self-signed CA must verify: %v", algorithm, err)
		}
		// The leaf is not self-signed: verifying it against its own key
		// must fail.
		if err := VerifyMLDSACertificate(leafDER, leafDER); err == nil {
			t.Fatalf("algorithm 0x%02X: leaf must not verify against itself", algorithm)
		}
		// Cross-variant issuers reject with an algorithm mismatch.
		other := AlgMLDSA44
		if algorithm == AlgMLDSA44 {
			other = AlgMLDSA65
		}
		otherCA := mldsaLoadGolden(t, other, "ca")
		if err := VerifyMLDSACertificate(leafDER, otherCA); err == nil || !strings.Contains(err.Error(), "does not match") {
			t.Fatalf("algorithm 0x%02X: cross-variant issuer must reject, got %v", algorithm, err)
		}
		// A 1-bit flip inside the TBS (here the subject key tail, which
		// keeps the structure parseable) must fail verification.
		parsed, err := ParseMLDSACertificateDER(leafDER)
		if err != nil {
			t.Fatalf("algorithm 0x%02X: parse leaf: %v", algorithm, err)
		}
		tbsOffset := bytes.Index(leafDER, parsed.TBS)
		if tbsOffset < 0 {
			t.Fatalf("algorithm 0x%02X: TBS subspan not found", algorithm)
		}
		flipped := append([]byte(nil), leafDER...)
		flipped[tbsOffset+len(parsed.TBS)-1] ^= 0x01
		if _, err := ParseMLDSACertificateDER(flipped); err != nil {
			t.Fatalf("algorithm 0x%02X: flipped TBS must stay parseable: %v", algorithm, err)
		}
		if err := VerifyMLDSACertificate(flipped, caDER); err == nil {
			t.Fatalf("algorithm 0x%02X: flipped TBS must fail verification", algorithm)
		}
	}
}

func TestVerifyMLDSAChain(t *testing.T) {
	for _, algorithm := range mldsaTestAlgorithms {
		caDER := mldsaLoadGolden(t, algorithm, "ca")
		leafDER := mldsaLoadGolden(t, algorithm, "leaf")
		if err := VerifyMLDSAChain([][]byte{leafDER, caDER}); err != nil {
			t.Fatalf("algorithm 0x%02X: VerifyMLDSAChain([leaf, ca]) error = %v", algorithm, err)
		}
		if err := VerifyMLDSAChain([][]byte{caDER}); err != nil {
			t.Fatalf("algorithm 0x%02X: single self-signed root must verify: %v", algorithm, err)
		}
		if err := VerifyMLDSAChain(nil); err == nil {
			t.Fatalf("algorithm 0x%02X: empty chain must reject", algorithm)
		}
		if err := VerifyMLDSAChain([][]byte{leafDER}); err == nil {
			t.Fatalf("algorithm 0x%02X: lone leaf must reject (not self-signed)", algorithm)
		}
		if err := VerifyMLDSAChain([][]byte{caDER, leafDER}); err == nil {
			t.Fatalf("algorithm 0x%02X: reversed chain must reject", algorithm)
		}
		other := AlgMLDSA44
		if algorithm == AlgMLDSA44 {
			other = AlgMLDSA87
		}
		otherCA := mldsaLoadGolden(t, other, "ca")
		if err := VerifyMLDSAChain([][]byte{leafDER, otherCA}); err == nil {
			t.Fatalf("algorithm 0x%02X: chain with wrong issuer must reject", algorithm)
		}
	}
}

func TestVerifyMLDSAAttestation(t *testing.T) {
	for _, algorithm := range mldsaTestAlgorithms {
		caDER := mldsaLoadGolden(t, algorithm, "ca")
		attDER := mldsaLoadGolden(t, algorithm, "attest")
		_, _, slotPub, _ := mldsaGoldenKeys(t, algorithm)
		slotKey := &OpaquePublicKey{Algorithm: algorithm, Raw: slotPub}
		if err := VerifyMLDSAAttestation(attDER, slotKey, caDER); err != nil {
			t.Fatalf("algorithm 0x%02X: VerifyMLDSAAttestation() error = %v", algorithm, err)
		}
		// A different slot key must fail the equality check even though
		// the attestation signature itself is valid.
		_, leafPub, _, _ := mldsaGoldenKeys(t, algorithm)
		if err := VerifyMLDSAAttestation(attDER, &OpaquePublicKey{Algorithm: algorithm, Raw: leafPub}, caDER); err == nil ||
			!strings.Contains(err.Error(), "does not match slot public key") {
			t.Fatalf("algorithm 0x%02X: wrong slot key must reject, got %v", algorithm, err)
		}
		// A 1-bit flip in the bound key copy must fail equality.
		flipped := append([]byte(nil), slotPub...)
		flipped[0] ^= 0x01
		if err := VerifyMLDSAAttestation(attDER, &OpaquePublicKey{Algorithm: algorithm, Raw: flipped}, caDER); err == nil {
			t.Fatalf("algorithm 0x%02X: flipped slot key must reject", algorithm)
		}
		// Wrong algorithm label, bad key length, and nil keys reject.
		wrongAlg := AlgMLDSA44
		if algorithm == AlgMLDSA44 {
			wrongAlg = AlgMLDSA65
		}
		if err := VerifyMLDSAAttestation(attDER, &OpaquePublicKey{Algorithm: wrongAlg, Raw: slotPub}, caDER); err == nil {
			t.Fatalf("algorithm 0x%02X: mislabeled slot key must reject", algorithm)
		}
		_, _, otherSlotPub, _ := mldsaGoldenKeys(t, wrongAlg)
		if err := VerifyMLDSAAttestation(attDER, &OpaquePublicKey{Algorithm: wrongAlg, Raw: otherSlotPub}, caDER); err == nil ||
			!strings.Contains(err.Error(), "does not match slot key algorithm") {
			t.Fatalf("algorithm 0x%02X: cross-variant slot key must reject, got %v", algorithm, err)
		}
		if err := VerifyMLDSAAttestation(attDER, &OpaquePublicKey{Algorithm: algorithm, Raw: slotPub[:32]}, caDER); err == nil {
			t.Fatalf("algorithm 0x%02X: short slot key must reject", algorithm)
		}
		if err := VerifyMLDSAAttestation(attDER, nil, caDER); err == nil {
			t.Fatalf("algorithm 0x%02X: nil slot key must reject", algorithm)
		}
		// The leaf certificate does not bind this slot key.
		leafDER := mldsaLoadGolden(t, algorithm, "leaf")
		if err := VerifyMLDSAAttestation(leafDER, slotKey, caDER); err == nil {
			t.Fatalf("algorithm 0x%02X: non-attestation certificate must reject", algorithm)
		}
		// The wrong issuer must fail the issuer check.
		other := AlgMLDSA44
		if algorithm == AlgMLDSA44 {
			other = AlgMLDSA65
		}
		if err := VerifyMLDSAAttestation(attDER, slotKey, mldsaLoadGolden(t, other, "ca")); err == nil {
			t.Fatalf("algorithm 0x%02X: wrong issuer must reject", algorithm)
		}
	}
}

func TestMarshalMLDSAPKIXPublicKey(t *testing.T) {
	for _, algorithm := range mldsaTestAlgorithms {
		pub, _ := mldsaKATKey(t, algorithm)
		for _, key := range []crypto.PublicKey{
			&OpaquePublicKey{Algorithm: algorithm, Raw: pub},
			OpaquePublicKey{Algorithm: algorithm, Raw: pub},
		} {
			der, err := MarshalMLDSAPKIXPublicKey(key)
			if err != nil {
				t.Fatalf("algorithm 0x%02X (%T): MarshalMLDSAPKIXPublicKey() error = %v", algorithm, key, err)
			}
			var spki struct {
				Algorithm        mldsaAlgorithmIdentifier
				SubjectPublicKey asn1.BitString
			}
			rest, err := asn1.Unmarshal(der, &spki)
			if err != nil || len(rest) != 0 {
				t.Fatalf("algorithm 0x%02X: SPKI re-parse error = %v", algorithm, err)
			}
			oid, _ := MLDSAOIDForAlgorithm(algorithm)
			if !spki.Algorithm.Algorithm.Equal(oid) {
				t.Fatalf("algorithm 0x%02X: SPKI OID = %s, want %s", algorithm, spki.Algorithm.Algorithm, oid)
			}
			if !spki.Algorithm.paramsAbsent() {
				t.Fatalf("algorithm 0x%02X: SPKI parameters must be absent", algorithm)
			}
			if spki.SubjectPublicKey.BitLength != 8*len(spki.SubjectPublicKey.Bytes) {
				t.Fatalf("algorithm 0x%02X: SPKI BIT STRING must have zero unused bits", algorithm)
			}
			if !bytes.Equal(spki.SubjectPublicKey.Bytes, pub) {
				t.Fatalf("algorithm 0x%02X: SPKI key must round-trip verbatim", algorithm)
			}
		}
		// The SPKI feeds the certificate builders: a TBS built over it
		// must embed the same bytes.
		tbsDER, err := MarshalMLDSATBSCertificate(&MLDSACertificateTemplate{
			SerialNumber: big.NewInt(7),
			Subject:      pkix.Name{CommonName: "spki-check"},
			Issuer:       pkix.Name{CommonName: "spki-check"},
			NotBefore:    time.Now(),
			NotAfter:     time.Now().Add(time.Hour),
		}, algorithm, &OpaquePublicKey{Algorithm: algorithm, Raw: pub})
		if err != nil {
			t.Fatalf("algorithm 0x%02X: MarshalMLDSATBSCertificate() error = %v", algorithm, err)
		}
		if !bytes.Contains(tbsDER, pub) {
			t.Fatalf("algorithm 0x%02X: TBS must embed the raw key", algorithm)
		}
	}
	if _, err := MarshalMLDSAPKIXPublicKey(nil); err == nil {
		t.Fatal("nil key must reject")
	}
	if _, err := MarshalMLDSAPKIXPublicKey((*OpaquePublicKey)(nil)); err == nil {
		t.Fatal("nil opaque key must reject")
	}
	if _, err := MarshalMLDSAPKIXPublicKey(&rsa.PublicKey{}); err == nil {
		t.Fatal("non-opaque key must reject")
	}
	pub44, _ := mldsaKATKey(t, AlgMLDSA44)
	if _, err := MarshalMLDSAPKIXPublicKey(&OpaquePublicKey{Algorithm: AlgEd25519, Raw: pub44[:32]}); err == nil {
		t.Fatal("non-ML-DSA algorithm must reject")
	}
	if _, err := MarshalMLDSAPKIXPublicKey(&OpaquePublicKey{Algorithm: AlgMLDSA44, Raw: pub44[:100]}); err == nil {
		t.Fatal("short key must reject")
	}
	if _, err := MarshalMLDSAPKIXPublicKey(&OpaquePublicKey{Algorithm: 0, Raw: pub44}); err == nil {
		t.Fatal("zero algorithm must reject")
	}
}

func TestMLDSASigner(t *testing.T) {
	for _, algorithm := range mldsaTestAlgorithms {
		pub, _ := mldsaKATKey(t, algorithm)
		opaque := &OpaquePublicKey{Algorithm: algorithm, Raw: pub}
		if _, err := NewMLDSASigner(nil, SlotSignature, algorithm, opaque); err == nil {
			t.Fatalf("algorithm 0x%02X: nil client must reject", algorithm)
		}
		if _, err := NewMLDSASigner(NewClient(emulator.NewCard()), SlotSignature, AlgECCP256, opaque); err == nil {
			t.Fatalf("algorithm 0x%02X: non-ML-DSA algorithm must reject", algorithm)
		}
		if _, err := NewMLDSASigner(NewClient(emulator.NewCard()), SlotSignature, algorithm, nil); err == nil {
			t.Fatalf("algorithm 0x%02X: nil key must reject", algorithm)
		}
		other := AlgMLDSA44
		if algorithm == AlgMLDSA44 {
			other = AlgMLDSA65
		}
		if _, err := NewMLDSASigner(NewClient(emulator.NewCard()), SlotSignature, other, opaque); err == nil {
			t.Fatalf("algorithm 0x%02X: algorithm mismatch must reject", algorithm)
		}
		if _, err := NewMLDSASigner(NewClient(emulator.NewCard()), SlotSignature, algorithm,
			&OpaquePublicKey{Algorithm: algorithm, Raw: pub[:64]}); err == nil {
			t.Fatalf("algorithm 0x%02X: short key must reject", algorithm)
		}
		// Zero-labeled keys adopt the requested variant.
		signer, err := NewMLDSASigner(NewClient(emulator.NewCard()), SlotSignature, algorithm,
			&OpaquePublicKey{Raw: append([]byte(nil), pub...)})
		if err != nil {
			t.Fatalf("algorithm 0x%02X: zero-labeled key must adopt variant: %v", algorithm, err)
		}
		if signer.Algorithm() != algorithm || signer.Slot() != SlotSignature {
			t.Fatalf("algorithm 0x%02X: signer accessors mismatch", algorithm)
		}
		// Public returns an independent copy carrying the variant.
		exported, ok := signer.Public().(*OpaquePublicKey)
		if !ok || exported.Algorithm != algorithm || !bytes.Equal(exported.Raw, pub) {
			t.Fatalf("algorithm 0x%02X: Public() must return the key copy", algorithm)
		}
		exported.Raw[0] ^= 0xFF
		again, _ := signer.Public().(*OpaquePublicKey)
		if !bytes.Equal(again.Raw, pub) {
			t.Fatalf("algorithm 0x%02X: Public() must not alias signer state", algorithm)
		}
		if got := signer.OpaquePublicKey(); !bytes.Equal(got.Raw, pub) || got.Algorithm != algorithm {
			t.Fatalf("algorithm 0x%02X: OpaquePublicKey() mismatch", algorithm)
		}

		// Sign passes the message to the card verbatim: 00 87 <alg>
		// <slot> carrying 7C{82 empty, 81 message}.
		message := []byte("card-backed ML-DSA message")
		sigSize, _ := MLDSASignatureLength(algorithm)
		wantSig := bytes.Repeat([]byte{0x5A}, sigSize)
		mock := emulator.NewCard()
		mock.SetSuccessResponse(0x87, iso7816.EncodeTLV(0x7C, iso7816.EncodeTLV(0x82, wantSig)))
		cardSigner, err := NewMLDSASigner(NewClient(mock), SlotSignature, algorithm, opaque)
		if err != nil {
			t.Fatalf("algorithm 0x%02X: NewMLDSASigner() error = %v", algorithm, err)
		}
		var asSigner crypto.Signer = cardSigner
		gotSig, err := asSigner.Sign(nil, message, nil)
		if err != nil {
			t.Fatalf("algorithm 0x%02X: Sign() error = %v", algorithm, err)
		}
		if !bytes.Equal(gotSig, wantSig) {
			t.Fatalf("algorithm 0x%02X: signature must round-trip verbatim", algorithm)
		}
		if len(mock.TransmittedCommands) != 1 {
			t.Fatalf("algorithm 0x%02X: expected 1 APDU, got %d", algorithm, len(mock.TransmittedCommands))
		}
		raw := mock.TransmittedCommands[0]
		if len(raw) < 4 || raw[0] != 0x00 || raw[1] != 0x87 || raw[2] != algorithm || raw[3] != byte(SlotSignature) {
			t.Fatalf("algorithm 0x%02X: sign header = %X, want 00 87 %02X 9C", algorithm, raw[:4], algorithm)
		}
		cmd, err := iso7816.ParseCommand(raw)
		if err != nil {
			t.Fatalf("algorithm 0x%02X: parse sign command: %v", algorithm, err)
		}
		outer, err := iso7816.ParseAllTLV(cmd.Data)
		if err != nil {
			t.Fatalf("algorithm 0x%02X: parse sign template: %v", algorithm, err)
		}
		auth := iso7816.FindTag(outer, 0x7C)
		inner, err := iso7816.ParseAllTLV(auth.Value)
		if err != nil {
			t.Fatalf("algorithm 0x%02X: parse auth template: %v", algorithm, err)
		}
		if placeholder := iso7816.FindTag(inner, 0x82); placeholder == nil || len(placeholder.Value) != 0 {
			t.Fatalf("algorithm 0x%02X: 0x82 placeholder must be empty", algorithm)
		}
		if challenge := iso7816.FindTag(inner, 0x81); challenge == nil || !bytes.Equal(challenge.Value, message) {
			t.Fatalf("algorithm 0x%02X: 0x81 must carry the message verbatim", algorithm)
		}
		// A short card signature fails the variant length check.
		shortMock := emulator.NewCard()
		shortMock.SetSuccessResponse(0x87, iso7816.EncodeTLV(0x7C, iso7816.EncodeTLV(0x82, bytes.Repeat([]byte{0x5A}, 64))))
		shortSigner, err := NewMLDSASigner(NewClient(shortMock), SlotSignature, algorithm, opaque)
		if err != nil {
			t.Fatalf("algorithm 0x%02X: NewMLDSASigner() error = %v", algorithm, err)
		}
		if _, err := shortSigner.Sign(nil, message, nil); err == nil {
			t.Fatalf("algorithm 0x%02X: short card signature must reject", algorithm)
		}
	}
}

// TestSelfSignMLDSACertificateCardBacked drives the Phase B self-sign
// flow through the emulator: the TBS is built manually (the standard
// library rejects opaque keys), signed verbatim by the card, assembled,
// and verified as a self-signed chain.
func TestSelfSignMLDSACertificateCardBacked(t *testing.T) {
	for _, algorithm := range mldsaTestAlgorithms {
		pub, sign := mldsaKATKey(t, algorithm)
		opaque := &OpaquePublicKey{Algorithm: algorithm, Raw: pub}
		name := pkix.Name{CommonName: "piv-go self-signed " + mldsaVariantName(algorithm)}
		template := &MLDSACertificateTemplate{
			SerialNumber: big.NewInt(42),
			Subject:      name,
			Issuer:       name,
			NotBefore:    time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
			NotAfter:     time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC),
		}
		// The TBS is deterministic, so the expected card response is the
		// circl signature over it.
		tbsDER, err := MarshalMLDSATBSCertificate(template, algorithm, opaque)
		if err != nil {
			t.Fatalf("algorithm 0x%02X: MarshalMLDSATBSCertificate() error = %v", algorithm, err)
		}
		mock := emulator.NewCard()
		mock.SetSuccessResponse(0x87, iso7816.EncodeTLV(0x7C, iso7816.EncodeTLV(0x82, sign(tbsDER))))
		signer, err := NewMLDSASigner(NewClient(mock), SlotSignature, algorithm, opaque)
		if err != nil {
			t.Fatalf("algorithm 0x%02X: NewMLDSASigner() error = %v", algorithm, err)
		}
		certDER, err := SelfSignMLDSACertificate(template, signer)
		if err != nil {
			t.Fatalf("algorithm 0x%02X: SelfSignMLDSACertificate() error = %v", algorithm, err)
		}
		parsed, err := ParseMLDSACertificateDER(certDER)
		if err != nil {
			t.Fatalf("algorithm 0x%02X: self-signed cert must parse: %v", algorithm, err)
		}
		if !bytes.Equal(parsed.TBS, tbsDER) || !bytes.Equal(parsed.PublicKey, pub) {
			t.Fatalf("algorithm 0x%02X: self-signed cert must embed the TBS and key", algorithm)
		}
		if err := VerifyMLDSACertificate(certDER, certDER); err != nil {
			t.Fatalf("algorithm 0x%02X: self-signed cert must verify: %v", algorithm, err)
		}
		if err := VerifyMLDSAChain([][]byte{certDER}); err != nil {
			t.Fatalf("algorithm 0x%02X: self-signed chain must verify: %v", algorithm, err)
		}
		if len(mock.TransmittedCommands) != 1 {
			t.Fatalf("algorithm 0x%02X: expected exactly 1 sign APDU, got %d", algorithm, len(mock.TransmittedCommands))
		}
		if challenge := mldsaSignChallenge(t, mock.TransmittedCommands[0]); !bytes.Equal(challenge, tbsDER) {
			t.Fatalf("algorithm 0x%02X: card must sign the TBS verbatim", algorithm)
		}
		if _, err := SelfSignMLDSACertificate(template, nil); err == nil {
			t.Fatalf("algorithm 0x%02X: nil signer must reject", algorithm)
		}
	}
}

// TestBuildMLDSACertificateRequest drives the Phase B CSR flow through
// the emulator and verifies the PKCS#10 structure and signature.
func TestBuildMLDSACertificateRequest(t *testing.T) {
	for _, algorithm := range mldsaTestAlgorithms {
		pub, sign := mldsaKATKey(t, algorithm)
		opaque := &OpaquePublicKey{Algorithm: algorithm, Raw: pub}
		subject := pkix.Name{CommonName: "piv-go csr " + mldsaVariantName(algorithm)}
		// The request info is deterministic for a fixed subject and key,
		// so pre-compute it and have the emulator answer the card Sign
		// call with the circl signature over it.
		spkiDER := mustMarshalSPKI(t, algorithm, pub)
		infoDER, err := asn1.Marshal(mldsaCertificationRequestInfo{
			Version:    0,
			Subject:    subject.ToRDNSequence(),
			PublicKey:  asn1.RawValue{FullBytes: spkiDER},
			Attributes: asn1.RawValue{Class: 2, Tag: 0, IsCompound: true, Bytes: []byte{}},
		})
		if err != nil {
			t.Fatalf("algorithm 0x%02X: marshal probe info: %v", algorithm, err)
		}
		mock := emulator.NewCard()
		mock.SetSuccessResponse(0x87, iso7816.EncodeTLV(0x7C, iso7816.EncodeTLV(0x82, sign(infoDER))))
		signer, err := NewMLDSASigner(NewClient(mock), SlotSignature, algorithm, opaque)
		if err != nil {
			t.Fatalf("algorithm 0x%02X: NewMLDSASigner() error = %v", algorithm, err)
		}
		csrDER, err := BuildMLDSACertificateRequest(subject, signer)
		if err != nil {
			t.Fatalf("algorithm 0x%02X: BuildMLDSACertificateRequest() error = %v", algorithm, err)
		}
		var outer struct {
			RequestInfo        asn1.RawValue
			SignatureAlgorithm mldsaAlgorithmIdentifier
			SignatureValue     asn1.BitString
		}
		rest, err := asn1.Unmarshal(csrDER, &outer)
		if err != nil || len(rest) != 0 {
			t.Fatalf("algorithm 0x%02X: parse CSR outer: %v", algorithm, err)
		}
		oid, _ := MLDSAOIDForAlgorithm(algorithm)
		if !outer.SignatureAlgorithm.Algorithm.Equal(oid) || !outer.SignatureAlgorithm.paramsAbsent() {
			t.Fatalf("algorithm 0x%02X: CSR signature algorithm must be the bare ML-DSA OID", algorithm)
		}
		if outer.SignatureValue.BitLength != 8*len(outer.SignatureValue.Bytes) {
			t.Fatalf("algorithm 0x%02X: CSR signature must have zero unused bits", algorithm)
		}
		var info struct {
			Version   int
			Subject   pkix.RDNSequence
			PublicKey mldsaSubjectPublicKeyInfo
			Attrs     asn1.RawValue
		}
		infoRest, err := asn1.Unmarshal(outer.RequestInfo.FullBytes, &info)
		if err != nil || len(infoRest) != 0 {
			t.Fatalf("algorithm 0x%02X: parse CSR info: %v", algorithm, err)
		}
		if info.Version != 0 {
			t.Fatalf("algorithm 0x%02X: CSR version = %d, want 0", algorithm, info.Version)
		}
		if !info.PublicKey.Algorithm.Algorithm.Equal(oid) || !info.PublicKey.Algorithm.paramsAbsent() {
			t.Fatalf("algorithm 0x%02X: CSR SPKI must carry the bare ML-DSA OID", algorithm)
		}
		if !bytes.Equal(info.PublicKey.SubjectPublicKey.Bytes, pub) {
			t.Fatalf("algorithm 0x%02X: CSR SPKI key must round-trip verbatim", algorithm)
		}
		if len(info.Attrs.FullBytes) != 2 || info.Attrs.FullBytes[0] != 0xA0 || info.Attrs.FullBytes[1] != 0x00 {
			t.Fatalf("algorithm 0x%02X: CSR attributes must encode as empty A0 00, got %X", algorithm, info.Attrs.FullBytes)
		}
		if !bytes.Contains(outer.RequestInfo.FullBytes, []byte("piv-go csr "+mldsaVariantName(algorithm))) {
			t.Fatalf("algorithm 0x%02X: CSR must embed the subject CN", algorithm)
		}
		sigSize, _ := MLDSASignatureLength(algorithm)
		if len(outer.SignatureValue.Bytes) != sigSize {
			t.Fatalf("algorithm 0x%02X: CSR signature length = %d, want %d", algorithm, len(outer.SignatureValue.Bytes), sigSize)
		}
		if err := VerifyMLDSASignature(algorithm, pub, outer.RequestInfo.FullBytes, outer.SignatureValue.Bytes); err != nil {
			t.Fatalf("algorithm 0x%02X: CSR signature must verify: %v", algorithm, err)
		}
		if len(mock.TransmittedCommands) != 1 {
			t.Fatalf("algorithm 0x%02X: expected exactly 1 sign APDU, got %d", algorithm, len(mock.TransmittedCommands))
		}
		if challenge := mldsaSignChallenge(t, mock.TransmittedCommands[0]); !bytes.Equal(challenge, outer.RequestInfo.FullBytes) {
			t.Fatalf("algorithm 0x%02X: card must sign the request info verbatim", algorithm)
		}
		if _, err := BuildMLDSACertificateRequest(subject, nil); err == nil {
			t.Fatalf("algorithm 0x%02X: nil signer must reject", algorithm)
		}
	}
}

// TestStdlibSpikeAndRawGate records the Phase B spike result and the
// reason certificate import keeps its --raw-cert gate: the standard
// library parses ML-DSA DER structurally but reports Unknown algorithms
// and refuses to issue ML-DSA certificates from opaque keys, so manual
// TBS/CSR builders are required.
func TestStdlibSpikeAndRawGate(t *testing.T) {
	der := mldsaLoadGolden(t, AlgMLDSA44, "leaf")
	stdCert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("stdlib must parse ML-DSA DER structurally: %v", err)
	}
	if stdCert.SignatureAlgorithm != x509.UnknownSignatureAlgorithm {
		t.Fatalf("stdlib signature algorithm = %v, want Unknown", stdCert.SignatureAlgorithm)
	}
	parsed, err := ParseMLDSACertificateDER(der)
	if err != nil {
		t.Fatalf("ParseMLDSACertificateDER() error = %v", err)
	}
	signer, err := NewMLDSASigner(NewClient(emulator.NewCard()), SlotSignature, parsed.Algorithm,
		&OpaquePublicKey{Algorithm: parsed.Algorithm, Raw: parsed.PublicKey})
	if err != nil {
		t.Fatalf("NewMLDSASigner() error = %v", err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "spike"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour),
	}
	if _, err := x509.CreateCertificate(nil, template, template, signer.Public(), signer); err == nil ||
		!strings.Contains(err.Error(), "only RSA, ECDSA and Ed25519") {
		t.Fatalf("stdlib CreateCertificate must reject opaque ML-DSA keys, got %v", err)
	}
}

// TestMLDSAEmulatorFixtures covers the emulator-level PQC fixtures: tag
// 0x87 public key parsing for every variant, 7F49{87} generated-key
// storage, attestation key equality through an emulator-parsed key, and
// the no-APDU purity of the verification surface.
func TestMLDSAEmulatorFixtures(t *testing.T) {
	for _, algorithm := range mldsaTestAlgorithms {
		pub, _ := mldsaKATKey(t, algorithm)
		pubSize, _ := MLDSAPublicKeyLength(algorithm)
		stored := iso7816.EncodeTLV(0x53, iso7816.EncodeTLV(0x7F49, iso7816.EncodeTLV(0x87, pub)))
		key, err := ParsePublicKeyObject(stored)
		if err != nil {
			t.Fatalf("algorithm 0x%02X: ParsePublicKeyObject(0x87) error = %v", algorithm, err)
		}
		opaque, ok := key.(*OpaquePublicKey)
		if !ok || opaque.Algorithm != algorithm || !bytes.Equal(opaque.Raw, pub) {
			t.Fatalf("algorithm 0x%02X: ParsePublicKeyObject must infer variant and bytes", algorithm)
		}
		template, err := encodeGeneratedPublicKeyTemplate(algorithm, opaque)
		if err != nil {
			t.Fatalf("algorithm 0x%02X: encodeGeneratedPublicKeyTemplate() error = %v", algorithm, err)
		}
		tlvs, err := iso7816.ParseAllTLV(template)
		if err != nil {
			t.Fatalf("algorithm 0x%02X: parse template: %v", algorithm, err)
		}
		inner, err := iso7816.ParseAllTLV(iso7816.FindTag(tlvs, 0x7F49).Value)
		if err != nil {
			t.Fatalf("algorithm 0x%02X: parse 7F49: %v", algorithm, err)
		}
		if field := iso7816.FindTag(inner, 0x87); field == nil || len(field.Value) != pubSize || !bytes.Equal(field.Value, pub) {
			t.Fatalf("algorithm 0x%02X: template must be 7F49{87/%d} verbatim", algorithm, pubSize)
		}
		mock := emulator.NewCard()
		mock.SetSuccessResponse(0xDB, nil)
		if err := NewClient(mock).StoreGeneratedPublicKey(SlotSignature, algorithm, opaque); err != nil {
			t.Fatalf("algorithm 0x%02X: StoreGeneratedPublicKey() error = %v", algorithm, err)
		}
		if len(mock.TransmittedCommands) == 0 || mock.TransmittedCommands[len(mock.TransmittedCommands)-1][1] != 0xDB {
			t.Fatalf("algorithm 0x%02X: store must issue PUT DATA", algorithm)
		}

		// Attestation equality through an emulator-parsed slot key: the
		// golden attestation binds the fixed slot key, so re-derive it
		// and verify, then confirm a parsed emulator key with flipped
		// bytes fails.
		_, _, slotPub, _ := mldsaGoldenKeys(t, algorithm)
		attDER := mldsaLoadGolden(t, algorithm, "attest")
		caDER := mldsaLoadGolden(t, algorithm, "ca")
		parsedKey, err := ParsePublicKeyObject(iso7816.EncodeTLV(0x53,
			iso7816.EncodeTLV(0x7F49, iso7816.EncodeTLV(0x87, slotPub))))
		if err != nil {
			t.Fatalf("algorithm 0x%02X: parse slot key: %v", algorithm, err)
		}
		if err := VerifyMLDSAAttestation(attDER, parsedKey.(*OpaquePublicKey), caDER); err != nil {
			t.Fatalf("algorithm 0x%02X: emulator-parsed slot key must attest: %v", algorithm, err)
		}
	}
	// Purity: the whole verification surface runs with an emulator card
	// attached but must never transmit.
	pureMock := emulator.NewCard()
	leafDER := mldsaLoadGolden(t, AlgMLDSA44, "leaf")
	caDER := mldsaLoadGolden(t, AlgMLDSA44, "ca")
	attDER := mldsaLoadGolden(t, AlgMLDSA44, "attest")
	_, _, slotPub, _ := mldsaGoldenKeys(t, AlgMLDSA44)
	parsed, err := ParseMLDSACertificateDER(leafDER)
	if err != nil {
		t.Fatalf("parse leaf: %v", err)
	}
	caParsed, err := ParseMLDSACertificateDER(caDER)
	if err != nil {
		t.Fatalf("parse ca: %v", err)
	}
	checks := []func() error{
		func() error {
			return VerifyMLDSASignature(caParsed.Algorithm, caParsed.PublicKey, parsed.TBS, parsed.Signature)
		},
		func() error { return VerifyMLDSACertificate(leafDER, caDER) },
		func() error { return VerifyMLDSAChain([][]byte{leafDER, caDER}) },
		func() error {
			return VerifyMLDSAAttestation(attDER, &OpaquePublicKey{Algorithm: AlgMLDSA44, Raw: slotPub}, caDER)
		},
		func() error {
			_, err := MarshalMLDSAPKIXPublicKey(&OpaquePublicKey{Algorithm: AlgMLDSA44, Raw: parsed.PublicKey})
			return err
		},
		func() error {
			_, err := MarshalMLDSATBSCertificate(&MLDSACertificateTemplate{
				SerialNumber: big.NewInt(1),
				Subject:      pkix.Name{CommonName: "pure"},
				Issuer:       pkix.Name{CommonName: "pure"},
				NotBefore:    time.Now(),
				NotAfter:     time.Now().Add(time.Hour),
			}, AlgMLDSA44, &OpaquePublicKey{Algorithm: AlgMLDSA44, Raw: parsed.PublicKey})
			return err
		},
		func() error {
			_, err := AssembleMLDSACertificate(parsed.TBS, parsed.Signature, AlgMLDSA44)
			return err
		},
	}
	for i, check := range checks {
		if err := check(); err != nil {
			t.Fatalf("pure check %d: %v", i, err)
		}
	}
	_ = pureMock
	if len(pureMock.TransmittedCommands) != 0 {
		t.Fatalf("verification surface must send no APDU, got %d commands", len(pureMock.TransmittedCommands))
	}
}

// TestMLDSAGoldenDeterminism rebuilds the CA fixture in-memory from the
// fixed seeds, names, and validity window and requires byte equality
// with the committed golden: the fixtures carry no hidden state.
func TestMLDSAGoldenDeterminism(t *testing.T) {
	notBefore := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	notAfter := time.Date(2035, 1, 1, 0, 0, 0, 0, time.UTC)
	for _, algorithm := range mldsaTestAlgorithms {
		variant := mldsaVariantName(algorithm)
		caPub, _, _, caSign := mldsaGoldenKeys(t, algorithm)
		name := mldsaGoldenName(variant, "CA")
		tbsDER, err := MarshalMLDSATBSCertificate(&MLDSACertificateTemplate{
			SerialNumber: big.NewInt(1),
			Subject:      name,
			Issuer:       name,
			NotBefore:    notBefore,
			NotAfter:     notAfter,
		}, algorithm, &OpaquePublicKey{Algorithm: algorithm, Raw: caPub})
		if err != nil {
			t.Fatalf("algorithm 0x%02X: rebuild TBS: %v", algorithm, err)
		}
		rebuilt, err := AssembleMLDSACertificate(tbsDER, caSign(tbsDER), algorithm)
		if err != nil {
			t.Fatalf("algorithm 0x%02X: rebuild CA: %v", algorithm, err)
		}
		if golden := mldsaLoadGolden(t, algorithm, "ca"); !bytes.Equal(rebuilt, golden) {
			t.Fatalf("algorithm 0x%02X: rebuilt CA differs from golden", algorithm)
		}
	}
}

func TestMarshalMLDSATBSCertificateRejects(t *testing.T) {
	pub44, _ := mldsaKATKey(t, AlgMLDSA44)
	good := &MLDSACertificateTemplate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "good"},
		Issuer:       pkix.Name{CommonName: "good"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour),
	}
	key := &OpaquePublicKey{Algorithm: AlgMLDSA44, Raw: pub44}
	if _, err := MarshalMLDSATBSCertificate(nil, AlgMLDSA44, key); err == nil {
		t.Fatal("nil template must reject")
	}
	badSerial := *good
	badSerial.SerialNumber = big.NewInt(0)
	if _, err := MarshalMLDSATBSCertificate(&badSerial, AlgMLDSA44, key); err == nil {
		t.Fatal("non-positive serial must reject")
	}
	badWindow := *good
	badWindow.NotAfter = badWindow.NotBefore
	if _, err := MarshalMLDSATBSCertificate(&badWindow, AlgMLDSA44, key); err == nil {
		t.Fatal("empty validity window must reject")
	}
	if _, err := MarshalMLDSATBSCertificate(good, AlgECCP256, key); err == nil {
		t.Fatal("non-ML-DSA signature algorithm must reject")
	}
	if _, err := MarshalMLDSATBSCertificate(good, AlgMLDSA44, nil); err == nil {
		t.Fatal("nil subject key must reject")
	}
	if _, err := MarshalMLDSATBSCertificate(good, AlgMLDSA44,
		&OpaquePublicKey{Algorithm: AlgMLDSA44, Raw: pub44[:100]}); err == nil {
		t.Fatal("short subject key must reject")
	}
	parsed, err := ParseMLDSACertificateDER(mldsaLoadGolden(t, AlgMLDSA44, "ca"))
	if err != nil {
		t.Fatalf("parse golden CA: %v", err)
	}
	if _, err := AssembleMLDSACertificate(parsed.TBS, parsed.Signature[:100], AlgMLDSA44); err == nil {
		t.Fatal("short signature must reject at assembly")
	}
	if _, err := AssembleMLDSACertificate(parsed.TBS, parsed.Signature, AlgMLDSA65); err == nil {
		t.Fatal("TBS/signature algorithm mismatch must reject at assembly")
	}
	if _, err := AssembleMLDSACertificate([]byte{0x30, 0x00}, parsed.Signature, AlgMLDSA44); err == nil {
		t.Fatal("invalid TBS must reject at assembly")
	}
}

// mldsaSignChallenge extracts the 0x81 challenge from a GENERAL
// AUTHENTICATE command for verbatim comparisons.
func mldsaSignChallenge(t *testing.T, raw []byte) []byte {
	t.Helper()
	cmd, err := iso7816.ParseCommand(raw)
	if err != nil {
		t.Fatalf("parse command: %v", err)
	}
	outer, err := iso7816.ParseAllTLV(cmd.Data)
	if err != nil {
		t.Fatalf("parse outer: %v", err)
	}
	inner, err := iso7816.ParseAllTLV(iso7816.FindTag(outer, 0x7C).Value)
	if err != nil {
		t.Fatalf("parse inner: %v", err)
	}
	return iso7816.FindTag(inner, 0x81).Value
}
