package piv

// ML-DSA (FIPS 204) verification library and card-backed signing helpers.
//
// Phase A is strictly read-only and off-card: OID registry, DER parsing,
// and signature/certificate/chain/attestation verification run without
// touching the card (no APDU is possible: none of the verification
// functions take a Client). Verification is implemented with
// github.com/cloudflare/circl/sign/mldsa.
//
// Phase B adds host-side encodings for opaque ML-DSA public keys and a
// card-backed crypto.Signer used by the manual TBS/CSR builders. The
// standard library x509 package parses ML-DSA DER structurally but
// reports Unknown algorithms and x509.CreateCertificate rejects opaque
// keys, so certificate and certification-request bytes are assembled
// manually with encoding/asn1 instead.
//
// Certificate import strictness is unchanged: ML-DSA slot certificates
// still require cert import --raw-cert (see internal/cli/app/mutation.go);
// this package only verifies raw bytes.

import (
	"bytes"
	"crypto"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"io"
	"math/big"
	"time"

	"github.com/cloudflare/circl/sign/mldsa/mldsa44"
	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
	"github.com/cloudflare/circl/sign/mldsa/mldsa87"
)

// ML-DSA signature algorithm object identifiers (NIST FIPS 204).
var (
	// MLDSAOID44 identifies ML-DSA-44 (2.16.840.1.101.3.4.3.17).
	MLDSAOID44 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 17}
	// MLDSAOID65 identifies ML-DSA-65 (2.16.840.1.101.3.4.3.18).
	MLDSAOID65 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 18}
	// MLDSAOID87 identifies ML-DSA-87 (2.16.840.1.101.3.4.3.19).
	MLDSAOID87 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 19}
)

// MLDSAOIDForAlgorithm returns the signature algorithm OID for an ML-DSA
// PIV algorithm identifier (AlgMLDSA44/65/87). It reports false for any
// other algorithm.
func MLDSAOIDForAlgorithm(algorithm byte) (asn1.ObjectIdentifier, bool) {
	switch algorithm {
	case AlgMLDSA44:
		return MLDSAOID44, true
	case AlgMLDSA65:
		return MLDSAOID65, true
	case AlgMLDSA87:
		return MLDSAOID87, true
	default:
		return nil, false
	}
}

// MLDSAAlgorithmForOID returns the PIV algorithm identifier for an ML-DSA
// signature algorithm OID. It reports false for any other OID, including
// OIDs with a different length or arc values.
func MLDSAAlgorithmForOID(oid asn1.ObjectIdentifier) (byte, bool) {
	switch {
	case oid.Equal(MLDSAOID44):
		return AlgMLDSA44, true
	case oid.Equal(MLDSAOID65):
		return AlgMLDSA65, true
	case oid.Equal(MLDSAOID87):
		return AlgMLDSA87, true
	default:
		return 0, false
	}
}

// ML-DSA raw key and signature sizes (FIPS 204).
const (
	// MLDSAPublicKeySize44 is the packed ML-DSA-44 public key size.
	MLDSAPublicKeySize44 = 1312
	// MLDSAPublicKeySize65 is the packed ML-DSA-65 public key size.
	MLDSAPublicKeySize65 = 1952
	// MLDSAPublicKeySize87 is the packed ML-DSA-87 public key size.
	MLDSAPublicKeySize87 = 2592
	// MLDSASignatureSize44 is the ML-DSA-44 signature size.
	MLDSASignatureSize44 = 2420
	// MLDSASignatureSize65 is the ML-DSA-65 signature size.
	MLDSASignatureSize65 = 3309
	// MLDSASignatureSize87 is the ML-DSA-87 signature size (FIPS 204).
	MLDSASignatureSize87 = 4627
)

// MLDSAPublicKeyLength returns the packed public key size for an ML-DSA
// PIV algorithm identifier. It reports false for any other algorithm.
func MLDSAPublicKeyLength(algorithm byte) (int, bool) {
	switch algorithm {
	case AlgMLDSA44:
		return MLDSAPublicKeySize44, true
	case AlgMLDSA65:
		return MLDSAPublicKeySize65, true
	case AlgMLDSA87:
		return MLDSAPublicKeySize87, true
	default:
		return 0, false
	}
}

// MLDSASignatureLength returns the signature size for an ML-DSA PIV
// algorithm identifier. It reports false for any other algorithm.
func MLDSASignatureLength(algorithm byte) (int, bool) {
	switch algorithm {
	case AlgMLDSA44:
		return MLDSASignatureSize44, true
	case AlgMLDSA65:
		return MLDSASignatureSize65, true
	case AlgMLDSA87:
		return MLDSASignatureSize87, true
	default:
		return 0, false
	}
}

// mldsaAlgorithmIdentifier is an X.509 AlgorithmIdentifier. ML-DSA
// algorithm identifiers carry no parameters: any present parameters
// (including an explicit NULL) are rejected by paramsAbsent.
type mldsaAlgorithmIdentifier struct {
	Algorithm  asn1.ObjectIdentifier
	Parameters asn1.RawValue `asn1:"optional"`
}

// paramsAbsent reports whether the AlgorithmIdentifier carries no
// parameters. encoding/asn1 leaves FullBytes empty when the optional
// parameters field is absent, so any encoded parameters are detected.
func (id mldsaAlgorithmIdentifier) paramsAbsent() bool {
	return len(id.Parameters.FullBytes) == 0
}

// mldsaSubjectPublicKeyInfo is an X.509 SubjectPublicKeyInfo carrying a
// raw ML-DSA public key in the BIT STRING.
type mldsaSubjectPublicKeyInfo struct {
	Algorithm        mldsaAlgorithmIdentifier
	SubjectPublicKey asn1.BitString
}

// mldsaCertificateRaw is the outer X.509 Certificate. The TBSCertificate
// is captured as an asn1.RawValue so FullBytes holds the verbatim TBS DER
// that the signature covers.
type mldsaCertificateRaw struct {
	TBSCertificate     asn1.RawValue
	SignatureAlgorithm mldsaAlgorithmIdentifier
	SignatureValue     asn1.BitString
}

// mldsaExtension mirrors pkix.Extension for the optional TBSCertificate
// extensions ([3] EXPLICIT). Real-world ML-DSA certificates commonly
// carry extensions (subject/authority key identifiers, basic
// constraints), so the parser accepts and skips them.
type mldsaExtension struct {
	Id       asn1.ObjectIdentifier
	Critical bool `asn1:"optional"`
	Value    []byte
}

// mldsaTBSCertificate models the TBSCertificate prefix through the
// subject public key, with the optional trailing fields accepted and
// ignored. Only the signature algorithm and subject public key are used;
// names and validity are available to callers through the verbatim TBS.
type mldsaTBSCertificate struct {
	Version    int `asn1:"optional,explicit,default:0,tag:0"`
	Serial     *big.Int
	Signature  mldsaAlgorithmIdentifier
	Issuer     asn1.RawValue
	Validity   asn1.RawValue
	Subject    asn1.RawValue
	PublicKey  mldsaSubjectPublicKeyInfo
	IssuerUID  asn1.BitString   `asn1:"optional,tag:1"`
	SubjectUID asn1.BitString   `asn1:"optional,tag:2"`
	Extensions []mldsaExtension `asn1:"optional,explicit,tag:3"`
}

// MLDSACertificate is a parsed ML-DSA X.509 certificate.
//
// Raw holds the full DER, TBS holds the verbatim TBSCertificate DER
// (the exact bytes the signature covers), Algorithm is the subject key
// variant (PIV identifier), SignatureAlgorithm is the outer signature
// variant, PublicKey is the raw subject public key, and Signature is the
// raw signature over TBS.
type MLDSACertificate struct {
	Raw                []byte
	TBS                []byte
	Algorithm          byte
	SignatureAlgorithm byte
	PublicKey          []byte
	Signature          []byte
}

// ParseMLDSACertificateDER parses DER-encoded X.509 certificate bytes
// carrying ML-DSA keys and signatures. It is strict:
//
//   - the outer and TBS signature AlgorithmIdentifiers must both carry a
//     known ML-DSA OID with absent parameters, and must agree with each
//     other;
//   - the subjectPublicKeyInfo algorithm must carry a known ML-DSA OID
//     with absent parameters;
//   - the subjectPublicKey and signatureValue BIT STRINGs must have zero
//     unused bits, and their lengths must match their variants;
//   - no trailing bytes are allowed after the outer SEQUENCE.
//
// TBS bytes are preserved verbatim from the input for signature
// verification. The function is pure and off-card: it never sends an
// APDU.
func ParseMLDSACertificateDER(der []byte) (*MLDSACertificate, error) {
	var outer mldsaCertificateRaw
	rest, err := asn1.Unmarshal(der, &outer)
	if err != nil {
		return nil, fmt.Errorf("piv: parse ML-DSA certificate: %w", err)
	}
	if len(rest) != 0 {
		return nil, fmt.Errorf("piv: parse ML-DSA certificate: %d trailing bytes", len(rest))
	}
	if outer.TBSCertificate.Class != 0 || outer.TBSCertificate.Tag != 16 || !outer.TBSCertificate.IsCompound {
		return nil, fmt.Errorf("piv: parse ML-DSA certificate: TBSCertificate is not a SEQUENCE")
	}
	if !outer.SignatureAlgorithm.paramsAbsent() {
		return nil, fmt.Errorf("piv: parse ML-DSA certificate: outer signature parameters must be absent")
	}
	sigAlgorithm, ok := MLDSAAlgorithmForOID(outer.SignatureAlgorithm.Algorithm)
	if !ok {
		return nil, fmt.Errorf("piv: parse ML-DSA certificate: unsupported outer signature OID %s", outer.SignatureAlgorithm.Algorithm)
	}
	var tbs mldsaTBSCertificate
	tbsRest, err := asn1.Unmarshal(outer.TBSCertificate.FullBytes, &tbs)
	if err != nil {
		return nil, fmt.Errorf("piv: parse ML-DSA certificate TBS: %w", err)
	}
	if len(tbsRest) != 0 {
		return nil, fmt.Errorf("piv: parse ML-DSA certificate TBS: %d trailing bytes", len(tbsRest))
	}
	if !tbs.Signature.paramsAbsent() {
		return nil, fmt.Errorf("piv: parse ML-DSA certificate: TBS signature parameters must be absent")
	}
	tbsSigAlgorithm, ok := MLDSAAlgorithmForOID(tbs.Signature.Algorithm)
	if !ok {
		return nil, fmt.Errorf("piv: parse ML-DSA certificate: unsupported TBS signature OID %s", tbs.Signature.Algorithm)
	}
	if tbsSigAlgorithm != sigAlgorithm {
		return nil, fmt.Errorf("piv: parse ML-DSA certificate: outer signature OID %s does not match TBS signature OID %s",
			outer.SignatureAlgorithm.Algorithm, tbs.Signature.Algorithm)
	}
	if !tbs.PublicKey.Algorithm.paramsAbsent() {
		return nil, fmt.Errorf("piv: parse ML-DSA certificate: subject public key parameters must be absent")
	}
	keyAlgorithm, ok := MLDSAAlgorithmForOID(tbs.PublicKey.Algorithm.Algorithm)
	if !ok {
		return nil, fmt.Errorf("piv: parse ML-DSA certificate: unsupported subject public key OID %s", tbs.PublicKey.Algorithm.Algorithm)
	}
	publicKey, err := mldsaBitStringBytes("subject public key", tbs.PublicKey.SubjectPublicKey)
	if err != nil {
		return nil, err
	}
	if size, _ := MLDSAPublicKeyLength(keyAlgorithm); len(publicKey) != size {
		return nil, fmt.Errorf("piv: parse ML-DSA certificate: subject public key length %d does not match algorithm 0x%02X (want %d)", len(publicKey), keyAlgorithm, size)
	}
	signature, err := mldsaBitStringBytes("signature value", outer.SignatureValue)
	if err != nil {
		return nil, err
	}
	if size, _ := MLDSASignatureLength(sigAlgorithm); len(signature) != size {
		return nil, fmt.Errorf("piv: parse ML-DSA certificate: signature length %d does not match algorithm 0x%02X (want %d)", len(signature), sigAlgorithm, size)
	}
	return &MLDSACertificate{
		Raw:                append([]byte(nil), der...),
		TBS:                append([]byte(nil), outer.TBSCertificate.FullBytes...),
		Algorithm:          keyAlgorithm,
		SignatureAlgorithm: sigAlgorithm,
		PublicKey:          publicKey,
		Signature:          signature,
	}, nil
}

// mldsaBitStringBytes enforces the BIT STRING unused-bits check shared by
// the subject public key and the signature value: ML-DSA values are always
// whole bytes, so any unused bits indicate a malformed encoding.
func mldsaBitStringBytes(name string, value asn1.BitString) ([]byte, error) {
	if value.BitLength != 8*len(value.Bytes) {
		return nil, fmt.Errorf("piv: parse ML-DSA certificate: %s BIT STRING has %d unused bits, must be zero", name, 8*len(value.Bytes)-value.BitLength)
	}
	return append([]byte(nil), value.Bytes...), nil
}

// VerifyMLDSASignature verifies a raw ML-DSA signature over a message
// with a raw public key. The algorithm selects the variant and both the
// key and signature lengths are enforced before verification. The empty
// ML-DSA context (nil ctx) is used, matching card signatures over the
// raw message. It returns nil when the signature is valid. The function
// is pure and off-card: it never sends an APDU.
func VerifyMLDSASignature(algorithm byte, publicKey, message, signature []byte) error {
	if !IsMLDSAAlgorithm(algorithm) {
		return fmt.Errorf("piv: verify ML-DSA signature: unsupported algorithm 0x%02X", algorithm)
	}
	keySize, _ := MLDSAPublicKeyLength(algorithm)
	if len(publicKey) != keySize {
		return fmt.Errorf("piv: verify ML-DSA signature: public key length %d does not match algorithm 0x%02X (want %d)", len(publicKey), algorithm, keySize)
	}
	sigSize, _ := MLDSASignatureLength(algorithm)
	if len(signature) != sigSize {
		return fmt.Errorf("piv: verify ML-DSA signature: signature length %d does not match algorithm 0x%02X (want %d)", len(signature), algorithm, sigSize)
	}
	var valid bool
	switch algorithm {
	case AlgMLDSA44:
		var pk mldsa44.PublicKey
		if err := pk.UnmarshalBinary(publicKey); err != nil {
			return fmt.Errorf("piv: verify ML-DSA-44 signature: invalid public key: %w", err)
		}
		valid = mldsa44.Verify(&pk, message, nil, signature)
	case AlgMLDSA65:
		var pk mldsa65.PublicKey
		if err := pk.UnmarshalBinary(publicKey); err != nil {
			return fmt.Errorf("piv: verify ML-DSA-65 signature: invalid public key: %w", err)
		}
		valid = mldsa65.Verify(&pk, message, nil, signature)
	case AlgMLDSA87:
		var pk mldsa87.PublicKey
		if err := pk.UnmarshalBinary(publicKey); err != nil {
			return fmt.Errorf("piv: verify ML-DSA-87 signature: invalid public key: %w", err)
		}
		valid = mldsa87.Verify(&pk, message, nil, signature)
	}
	if !valid {
		return fmt.Errorf("piv: verify ML-DSA signature: invalid signature for algorithm 0x%02X", algorithm)
	}
	return nil
}

// VerifyMLDSACertificate verifies that certificateDER is signed by the
// key in issuerDER. Both blobs are parsed with ParseMLDSACertificateDER;
// the certificate's signature variant must match the issuer's key
// variant, and the issuer's raw public key must verify the certificate's
// verbatim TBS. The function is pure and off-card: it never sends an
// APDU.
func VerifyMLDSACertificate(certificateDER, issuerDER []byte) error {
	cert, err := ParseMLDSACertificateDER(certificateDER)
	if err != nil {
		return err
	}
	issuer, err := ParseMLDSACertificateDER(issuerDER)
	if err != nil {
		return fmt.Errorf("piv: verify ML-DSA certificate issuer: %w", err)
	}
	if cert.SignatureAlgorithm != issuer.Algorithm {
		return fmt.Errorf("piv: verify ML-DSA certificate: signature algorithm 0x%02X does not match issuer key algorithm 0x%02X",
			cert.SignatureAlgorithm, issuer.Algorithm)
	}
	if err := VerifyMLDSASignature(issuer.Algorithm, issuer.PublicKey, cert.TBS, cert.Signature); err != nil {
		return fmt.Errorf("piv: verify ML-DSA certificate signature: %w", err)
	}
	return nil
}

// VerifyMLDSAChain verifies an ML-DSA certificate chain ordered leaf
// first and root last: every certificate must be signed by the next one,
// and the root must be self-signed. A single self-signed certificate is
// a valid chain of length one. Name binding is out of scope for the raw
// ML-DSA profile: only signature coverage is checked. The function is
// pure and off-card: it never sends an APDU.
func VerifyMLDSAChain(chain [][]byte) error {
	if len(chain) == 0 {
		return fmt.Errorf("piv: verify ML-DSA chain: empty chain")
	}
	for i := 0; i+1 < len(chain); i++ {
		if err := VerifyMLDSACertificate(chain[i], chain[i+1]); err != nil {
			return fmt.Errorf("piv: verify ML-DSA chain element %d: %w", i, err)
		}
	}
	root := chain[len(chain)-1]
	if err := VerifyMLDSACertificate(root, root); err != nil {
		return fmt.Errorf("piv: verify ML-DSA chain root: %w", err)
	}
	return nil
}

// VerifyMLDSAAttestation verifies an ML-DSA key attestation off-card: the
// attestation certificate must bind the slot's public key (variant and
// raw bytes must both match) and must be signed by the issuer (for
// example the YubiKey attestation CA). The function is pure and off-card:
// it never sends an APDU.
func VerifyMLDSAAttestation(attestationDER []byte, slotKey *OpaquePublicKey, issuerDER []byte) error {
	if slotKey == nil {
		return fmt.Errorf("piv: verify ML-DSA attestation: nil slot key")
	}
	if !IsMLDSAAlgorithm(slotKey.Algorithm) {
		return fmt.Errorf("piv: verify ML-DSA attestation: unsupported slot key algorithm 0x%02X", slotKey.Algorithm)
	}
	if size, _ := MLDSAPublicKeyLength(slotKey.Algorithm); len(slotKey.Raw) != size {
		return fmt.Errorf("piv: verify ML-DSA attestation: slot key length %d does not match algorithm 0x%02X (want %d)",
			len(slotKey.Raw), slotKey.Algorithm, size)
	}
	attestation, err := ParseMLDSACertificateDER(attestationDER)
	if err != nil {
		return err
	}
	if attestation.Algorithm != slotKey.Algorithm {
		return fmt.Errorf("piv: verify ML-DSA attestation: certificate key algorithm 0x%02X does not match slot key algorithm 0x%02X",
			attestation.Algorithm, slotKey.Algorithm)
	}
	if !bytes.Equal(attestation.PublicKey, slotKey.Raw) {
		return fmt.Errorf("piv: verify ML-DSA attestation: certificate public key does not match slot public key")
	}
	if err := VerifyMLDSACertificate(attestationDER, issuerDER); err != nil {
		return fmt.Errorf("piv: verify ML-DSA attestation issuer: %w", err)
	}
	return nil
}

// MarshalMLDSAPKIXPublicKey encodes an opaque ML-DSA public key as a DER
// SubjectPublicKeyInfo: SEQUENCE { SEQUENCE { OID }, BIT STRING key }.
// The algorithm identifier carries no parameters. Only *OpaquePublicKey
// and OpaquePublicKey values selecting an ML-DSA variant with the exact
// FIPS 204 key length are accepted; anything else is rejected before any
// encoding. The function is pure and off-card: it never sends an APDU.
func MarshalMLDSAPKIXPublicKey(publicKey crypto.PublicKey) ([]byte, error) {
	var algorithm byte
	var raw []byte
	switch key := publicKey.(type) {
	case *OpaquePublicKey:
		if key == nil {
			return nil, fmt.Errorf("piv: marshal ML-DSA public key: nil opaque key")
		}
		algorithm, raw = key.Algorithm, key.Raw
	case OpaquePublicKey:
		algorithm, raw = key.Algorithm, key.Raw
	default:
		return nil, fmt.Errorf("piv: marshal ML-DSA public key: unsupported public key type %T", publicKey)
	}
	if !IsMLDSAAlgorithm(algorithm) {
		return nil, fmt.Errorf("piv: marshal ML-DSA public key: unsupported algorithm 0x%02X", algorithm)
	}
	if size, _ := MLDSAPublicKeyLength(algorithm); len(raw) != size {
		return nil, fmt.Errorf("piv: marshal ML-DSA public key: key length %d does not match algorithm 0x%02X (want %d)", len(raw), algorithm, size)
	}
	oid, _ := MLDSAOIDForAlgorithm(algorithm)
	spki := struct {
		Algorithm        mldsaAlgorithmIdentifier
		SubjectPublicKey asn1.BitString
	}{
		Algorithm:        mldsaAlgorithmIdentifier{Algorithm: oid},
		SubjectPublicKey: asn1.BitString{Bytes: append([]byte(nil), raw...), BitLength: 8 * len(raw)},
	}
	der, err := asn1.Marshal(spki)
	if err != nil {
		return nil, fmt.Errorf("piv: marshal ML-DSA public key: %w", err)
	}
	return der, nil
}

// MLDSASigner is a card-backed crypto.Signer for an ML-DSA slot key. It
// holds only the client, slot, algorithm, and a copy of the public key:
// private key material never leaves the card and nothing is exported.
// Sign passes the message to Client.Sign verbatim (ML-DSA signs the raw
// message; no hashing or padding is applied) and validates the returned
// signature length against the variant.
type MLDSASigner struct {
	client    *Client
	slot      Slot
	algorithm byte
	publicKey *OpaquePublicKey
}

// NewMLDSASigner creates a card-backed signer for an ML-DSA slot key.
// The public key bytes are copied. The algorithm must select an ML-DSA
// variant, the key must carry that variant (or zero, which adopts the
// requested variant), and the key length must match FIPS 204. All checks
// run before any APDU is sent.
func NewMLDSASigner(client *Client, slot Slot, algorithm byte, publicKey *OpaquePublicKey) (*MLDSASigner, error) {
	if client == nil {
		return nil, fmt.Errorf("piv: new ML-DSA signer: nil client")
	}
	if !IsMLDSAAlgorithm(algorithm) {
		return nil, fmt.Errorf("piv: new ML-DSA signer: unsupported algorithm 0x%02X", algorithm)
	}
	if publicKey == nil {
		return nil, fmt.Errorf("piv: new ML-DSA signer: nil public key")
	}
	if publicKey.Algorithm != 0 && publicKey.Algorithm != algorithm {
		return nil, fmt.Errorf("piv: new ML-DSA signer: key algorithm 0x%02X does not match requested algorithm 0x%02X", publicKey.Algorithm, algorithm)
	}
	if size, _ := MLDSAPublicKeyLength(algorithm); len(publicKey.Raw) != size {
		return nil, fmt.Errorf("piv: new ML-DSA signer: key length %d does not match algorithm 0x%02X (want %d)", len(publicKey.Raw), algorithm, size)
	}
	return &MLDSASigner{
		client:    client,
		slot:      slot,
		algorithm: algorithm,
		publicKey: &OpaquePublicKey{Algorithm: algorithm, Raw: append([]byte(nil), publicKey.Raw...)},
	}, nil
}

// Public returns a copy of the signer's opaque ML-DSA public key.
func (s *MLDSASigner) Public() crypto.PublicKey {
	return &OpaquePublicKey{Algorithm: s.algorithm, Raw: append([]byte(nil), s.publicKey.Raw...)}
}

// Algorithm returns the signer's ML-DSA PIV algorithm identifier.
func (s *MLDSASigner) Algorithm() byte {
	return s.algorithm
}

// Slot returns the signer's PIV slot.
func (s *MLDSASigner) Slot() Slot {
	return s.slot
}

// OpaquePublicKey returns a copy of the signer's opaque public key.
func (s *MLDSASigner) OpaquePublicKey() *OpaquePublicKey {
	return &OpaquePublicKey{Algorithm: s.algorithm, Raw: append([]byte(nil), s.publicKey.Raw...)}
}

// Sign signs digest with the card's slot key by calling Client.Sign
// verbatim: digest is the ML-DSA message (already hashed by the caller
// when a pre-hash is desired) and opts are intentionally ignored because
// the card performs pure ML-DSA over the raw bytes. The returned
// signature length is validated against the variant. The RSA hash mode is
// irrelevant for ML-DSA and passes RSASignHashNone.
func (s *MLDSASigner) Sign(_ io.Reader, digest []byte, _ crypto.SignerOpts) ([]byte, error) {
	signature, err := s.client.Sign(s.algorithm, s.slot, digest, RSASignHashNone)
	if err != nil {
		return nil, fmt.Errorf("piv: ML-DSA sign with slot %s: %w", s.slot, err)
	}
	if size, _ := MLDSASignatureLength(s.algorithm); len(signature) != size {
		return nil, fmt.Errorf("piv: ML-DSA sign with slot %s: signature length %d does not match algorithm 0x%02X (want %d)",
			s.slot, len(signature), s.algorithm, size)
	}
	return signature, nil
}

// Compile-time proof that the card-backed signer satisfies crypto.Signer.
var _ crypto.Signer = (*MLDSASigner)(nil)

// MLDSACertificateTemplate carries the subject/issuer metadata for the
// manual TBS builder. SerialNumber and the validity window are required;
// Subject and Issuer are encoded as X.509 Names (self-sign callers pass
// the same name twice).
type MLDSACertificateTemplate struct {
	SerialNumber *big.Int
	Subject      pkix.Name
	Issuer       pkix.Name
	NotBefore    time.Time
	NotAfter     time.Time
}

// mldsaValidityOut is the X.509 Validity SEQUENCE.
type mldsaValidityOut struct {
	NotBefore time.Time
	NotAfter  time.Time
}

// mldsaTBSCertificateOut is the manually built TBSCertificate: version v3
// (INTEGER 2 in explicit [0]), serial, signature algorithm (no parameters), issuer,
// validity, subject, and the subject SPKI embedded verbatim. No
// extensions are emitted.
type mldsaTBSCertificateOut struct {
	Version   int `asn1:"explicit,tag:0"`
	Serial    *big.Int
	Signature mldsaAlgorithmIdentifier
	Issuer    pkix.RDNSequence
	Validity  mldsaValidityOut
	Subject   pkix.RDNSequence
	PublicKey asn1.RawValue
}

// MarshalMLDSATBSCertificate builds a DER TBSCertificate for an ML-DSA
// subject key without using x509.CreateCertificate (which rejects opaque
// keys). signatureAlgorithm selects the outer signature variant and must
// match the issuer key that will sign the TBS; for self-signed
// certificates it equals the subject key variant. The function is pure
// and off-card: it never sends an APDU.
func MarshalMLDSATBSCertificate(template *MLDSACertificateTemplate, signatureAlgorithm byte, subjectKey *OpaquePublicKey) ([]byte, error) {
	if template == nil {
		return nil, fmt.Errorf("piv: marshal ML-DSA TBS: nil template")
	}
	if template.SerialNumber == nil || template.SerialNumber.Sign() <= 0 {
		return nil, fmt.Errorf("piv: marshal ML-DSA TBS: positive serial number is required")
	}
	if template.NotBefore.IsZero() || template.NotAfter.IsZero() {
		return nil, fmt.Errorf("piv: marshal ML-DSA TBS: validity window is required")
	}
	if !template.NotAfter.After(template.NotBefore) {
		return nil, fmt.Errorf("piv: marshal ML-DSA TBS: NotAfter must be after NotBefore")
	}
	if !IsMLDSAAlgorithm(signatureAlgorithm) {
		return nil, fmt.Errorf("piv: marshal ML-DSA TBS: unsupported signature algorithm 0x%02X", signatureAlgorithm)
	}
	if subjectKey == nil {
		return nil, fmt.Errorf("piv: marshal ML-DSA TBS: nil subject key")
	}
	if !IsMLDSAAlgorithm(subjectKey.Algorithm) {
		return nil, fmt.Errorf("piv: marshal ML-DSA TBS: unsupported subject key algorithm 0x%02X", subjectKey.Algorithm)
	}
	if size, _ := MLDSAPublicKeyLength(subjectKey.Algorithm); len(subjectKey.Raw) != size {
		return nil, fmt.Errorf("piv: marshal ML-DSA TBS: subject key length %d does not match algorithm 0x%02X (want %d)",
			len(subjectKey.Raw), subjectKey.Algorithm, size)
	}
	spkiDER, err := MarshalMLDSAPKIXPublicKey(subjectKey)
	if err != nil {
		return nil, err
	}
	sigOID, _ := MLDSAOIDForAlgorithm(signatureAlgorithm)
	tbs := mldsaTBSCertificateOut{
		Version:   2,
		Serial:    new(big.Int).Set(template.SerialNumber),
		Signature: mldsaAlgorithmIdentifier{Algorithm: sigOID},
		Issuer:    template.Issuer.ToRDNSequence(),
		Validity:  mldsaValidityOut{NotBefore: template.NotBefore, NotAfter: template.NotAfter},
		Subject:   template.Subject.ToRDNSequence(),
		PublicKey: asn1.RawValue{FullBytes: spkiDER},
	}
	tbsDER, err := asn1.Marshal(tbs)
	if err != nil {
		return nil, fmt.Errorf("piv: marshal ML-DSA TBS: %w", err)
	}
	return tbsDER, nil
}

// AssembleMLDSACertificate wraps a TBS and its ML-DSA signature into a
// DER X.509 Certificate: SEQUENCE { TBS, AlgorithmIdentifier{OID},
// BIT STRING signature }. The TBS signature algorithm is re-parsed and
// must match signatureAlgorithm, and the signature length must match the
// variant. The result always round-trips through
// ParseMLDSACertificateDER. The function is pure and off-card: it never
// sends an APDU.
func AssembleMLDSACertificate(tbsDER, signature []byte, signatureAlgorithm byte) ([]byte, error) {
	if !IsMLDSAAlgorithm(signatureAlgorithm) {
		return nil, fmt.Errorf("piv: assemble ML-DSA certificate: unsupported algorithm 0x%02X", signatureAlgorithm)
	}
	if size, _ := MLDSASignatureLength(signatureAlgorithm); len(signature) != size {
		return nil, fmt.Errorf("piv: assemble ML-DSA certificate: signature length %d does not match algorithm 0x%02X (want %d)",
			len(signature), signatureAlgorithm, size)
	}
	tbsSigAlgorithm, err := mldsaTBSSignatureAlgorithm(tbsDER)
	if err != nil {
		return nil, err
	}
	if tbsSigAlgorithm != signatureAlgorithm {
		return nil, fmt.Errorf("piv: assemble ML-DSA certificate: TBS signature algorithm 0x%02X does not match requested algorithm 0x%02X",
			tbsSigAlgorithm, signatureAlgorithm)
	}
	sigOID, _ := MLDSAOIDForAlgorithm(signatureAlgorithm)
	cert := struct {
		TBSCertificate     asn1.RawValue
		SignatureAlgorithm mldsaAlgorithmIdentifier
		SignatureValue     asn1.BitString
	}{
		TBSCertificate:     asn1.RawValue{FullBytes: append([]byte(nil), tbsDER...)},
		SignatureAlgorithm: mldsaAlgorithmIdentifier{Algorithm: sigOID},
		SignatureValue:     asn1.BitString{Bytes: append([]byte(nil), signature...), BitLength: 8 * len(signature)},
	}
	der, err := asn1.Marshal(cert)
	if err != nil {
		return nil, fmt.Errorf("piv: assemble ML-DSA certificate: %w", err)
	}
	return der, nil
}

// mldsaTBSSignatureAlgorithm extracts the TBS signature variant from TBS
// DER so the assembler can enforce TBS/signature agreement.
func mldsaTBSSignatureAlgorithm(tbsDER []byte) (byte, error) {
	var tbs mldsaTBSCertificate
	rest, err := asn1.Unmarshal(tbsDER, &tbs)
	if err != nil {
		return 0, fmt.Errorf("piv: assemble ML-DSA certificate: invalid TBS: %w", err)
	}
	if len(rest) != 0 {
		return 0, fmt.Errorf("piv: assemble ML-DSA certificate: invalid TBS: %d trailing bytes", len(rest))
	}
	if !tbs.Signature.paramsAbsent() {
		return 0, fmt.Errorf("piv: assemble ML-DSA certificate: TBS signature parameters must be absent")
	}
	algorithm, ok := MLDSAAlgorithmForOID(tbs.Signature.Algorithm)
	if !ok {
		return 0, fmt.Errorf("piv: assemble ML-DSA certificate: unsupported TBS signature OID %s", tbs.Signature.Algorithm)
	}
	return algorithm, nil
}

// SelfSignMLDSACertificate builds a self-signed ML-DSA certificate with
// the card-backed signer: the TBS is built from the template and the
// signer's public key, signed verbatim by the card, and assembled into a
// Certificate. The template Issuer should equal Subject; TBS/signature
// agreement is enforced by construction. Only the Sign call touches the
// card.
func SelfSignMLDSACertificate(template *MLDSACertificateTemplate, signer *MLDSASigner) ([]byte, error) {
	if signer == nil {
		return nil, fmt.Errorf("piv: self-sign ML-DSA certificate: nil signer")
	}
	tbsDER, err := MarshalMLDSATBSCertificate(template, signer.Algorithm(), signer.OpaquePublicKey())
	if err != nil {
		return nil, err
	}
	signature, err := signer.Sign(nil, tbsDER, nil)
	if err != nil {
		return nil, err
	}
	return AssembleMLDSACertificate(tbsDER, signature, signer.Algorithm())
}

// mldsaCertificationRequestInfo is the PKCS#10 CertificationRequestInfo
// with the subject SPKI embedded verbatim and an empty attribute set
// ([0] IMPLICIT, A0 00).
type mldsaCertificationRequestInfo struct {
	Version    int
	Subject    pkix.RDNSequence
	PublicKey  asn1.RawValue
	Attributes asn1.RawValue
}

// BuildMLDSACertificateRequest builds a PKCS#10 certification request for
// an ML-DSA slot key without using the standard library (which rejects
// opaque keys): the request info is built manually with the signer's
// SPKI, signed verbatim by the card, and assembled with the ML-DSA
// signature AlgorithmIdentifier. Only the Sign call touches the card.
func BuildMLDSACertificateRequest(subject pkix.Name, signer *MLDSASigner) ([]byte, error) {
	if signer == nil {
		return nil, fmt.Errorf("piv: build ML-DSA certificate request: nil signer")
	}
	spkiDER, err := MarshalMLDSAPKIXPublicKey(signer.OpaquePublicKey())
	if err != nil {
		return nil, err
	}
	info := mldsaCertificationRequestInfo{
		Version:    0,
		Subject:    subject.ToRDNSequence(),
		PublicKey:  asn1.RawValue{FullBytes: spkiDER},
		Attributes: asn1.RawValue{Class: 2, Tag: 0, IsCompound: true, Bytes: []byte{}},
	}
	infoDER, err := asn1.Marshal(info)
	if err != nil {
		return nil, fmt.Errorf("piv: build ML-DSA certificate request: %w", err)
	}
	signature, err := signer.Sign(nil, infoDER, nil)
	if err != nil {
		return nil, err
	}
	if size, _ := MLDSASignatureLength(signer.Algorithm()); len(signature) != size {
		return nil, fmt.Errorf("piv: build ML-DSA certificate request: signature length %d does not match algorithm 0x%02X (want %d)",
			len(signature), signer.Algorithm(), size)
	}
	sigOID, _ := MLDSAOIDForAlgorithm(signer.Algorithm())
	csr := struct {
		RequestInfo        asn1.RawValue
		SignatureAlgorithm mldsaAlgorithmIdentifier
		SignatureValue     asn1.BitString
	}{
		RequestInfo:        asn1.RawValue{FullBytes: infoDER},
		SignatureAlgorithm: mldsaAlgorithmIdentifier{Algorithm: sigOID},
		SignatureValue:     asn1.BitString{Bytes: signature, BitLength: 8 * len(signature)},
	}
	csrDER, err := asn1.Marshal(csr)
	if err != nil {
		return nil, fmt.Errorf("piv: build ML-DSA certificate request: %w", err)
	}
	return csrDER, nil
}
