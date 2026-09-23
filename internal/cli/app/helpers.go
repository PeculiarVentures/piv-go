package app

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"io"
	"os"
	"sort"
	"strconv"
	"strings"

	"github.com/PeculiarVentures/piv-go/adapters/yubikey"
	"github.com/PeculiarVentures/piv-go/iso7816"
	"github.com/PeculiarVentures/piv-go/piv"
)

var primarySlots = []piv.Slot{
	piv.SlotAuthentication,
	piv.SlotSignature,
	piv.SlotKeyManagement,
	piv.SlotCardAuth,
}

var slotNameMap = map[string]piv.Slot{
	"auth":      piv.SlotAuthentication,
	"9a":        piv.SlotAuthentication,
	"sign":      piv.SlotSignature,
	"9c":        piv.SlotSignature,
	"key-mgmt":  piv.SlotKeyManagement,
	"keymgmt":   piv.SlotKeyManagement,
	"key_mgmt":  piv.SlotKeyManagement,
	"9d":        piv.SlotKeyManagement,
	"card-auth": piv.SlotCardAuth,
	"cardauth":  piv.SlotCardAuth,
	"card_auth": piv.SlotCardAuth,
	"9e":        piv.SlotCardAuth,
	"mgmt":      piv.SlotManagement,
	"9b":        piv.SlotManagement,
}

var objectNameMap = func() map[string]uint {
	result := make(map[string]uint)
	for _, object := range piv.KnownObjects() {
		key := strings.ToLower(strings.ReplaceAll(object.Name, " ", "-"))
		key = strings.ReplaceAll(key, "(", "")
		key = strings.ReplaceAll(key, ")", "")
		result[key] = object.Tag
	}
	result["chuid"] = piv.ObjectCHUID
	result["ccc"] = piv.ObjectCCC
	return result
}()

// ParseSlot resolves a canonical or hexadecimal slot selector.
//
// The YubiKey attestation aliases "attestation" and "f9" resolve to the
// vendor attestation slot (0xF9) served from the attestation certificate
// object; use them with piv cert export to read the long-lived attestation
// certificate. Commands that modify the token must use ParseSlotForMutation
// instead so the read-only attestation slot is rejected before any APDU.
func ParseSlot(value string) (piv.Slot, error) {
	normalized := strings.ToLower(strings.TrimSpace(value))
	if slot, ok := slotNameMap[normalized]; ok {
		return slot, nil
	}
	if normalized == "attestation" || normalized == "f9" {
		return yubikey.SlotAttestation, nil
	}
	normalized = strings.TrimPrefix(normalized, "0x")
	parsed, err := strconv.ParseUint(normalized, 16, 8)
	if err != nil {
		return 0, UsageError(fmt.Sprintf("unsupported slot %q", value), "use auth, sign, key-mgmt, card-auth, or a hexadecimal alias such as 9a")
	}
	slot := piv.Slot(parsed)
	switch slot {
	case piv.SlotAuthentication, piv.SlotManagement, piv.SlotSignature, piv.SlotKeyManagement, piv.SlotCardAuth, yubikey.SlotAttestation:
		return slot, nil
	default:
		return 0, UsageError(fmt.Sprintf("unsupported slot %q", value), "use auth, sign, key-mgmt, card-auth, or a hexadecimal alias such as 9a")
	}
}

// ParseSlotForMutation resolves a slot selector for commands that modify the
// token. The YubiKey attestation slot (F9) is read-only and is rejected before
// any APDU reaches the token: overwriting it would destroy the factory
// attestation key.
func ParseSlotForMutation(value string) (piv.Slot, error) {
	slot, err := ParseSlot(value)
	if err != nil {
		return 0, err
	}
	if err := rejectAttestationSlot(slot); err != nil {
		return 0, err
	}
	return slot, nil
}

// isAttestationSlot reports whether the slot is the read-only YubiKey
// attestation slot (0xF9).
func isAttestationSlot(slot piv.Slot) bool {
	return slot == yubikey.SlotAttestation
}

// rejectAttestationSlot rejects the read-only YubiKey attestation slot for
// token-modifying operations. Callers must invoke it before opening the
// target so a rejected slot never produces an APDU.
func rejectAttestationSlot(slot piv.Slot) error {
	if isAttestationSlot(slot) {
		return UsageError("attestation slot F9 is read-only", "use cert export to read the attestation certificate")
	}
	return nil
}

// SlotName returns the canonical human-readable slot name.
func SlotName(slot piv.Slot) string {
	switch slot {
	case piv.SlotAuthentication:
		return "auth"
	case piv.SlotManagement:
		return "mgmt"
	case piv.SlotSignature:
		return "sign"
	case piv.SlotKeyManagement:
		return "key-mgmt"
	case piv.SlotCardAuth:
		return "card-auth"
	default:
		return strings.ToLower(slot.String())
	}
}

// SlotHex returns the stable hexadecimal form of a slot selector.
func SlotHex(slot piv.Slot) string {
	return strings.ToLower(slot.String())
}

// ParseKeyAlgorithm resolves a key generation algorithm name. Names are
// case-insensitive and accept rsa1024, rsa2048, rsa3072, rsa4096, eccp256,
// eccp384 (with p256 and p384 aliases), ed25519, x25519, mldsa44, mldsa65,
// mldsa87 (YubiKey 6 preview), and mlkem512, mlkem768, mlkem1024. ML-KEM
// names select on-card decapsulation keys (generate/import/decapsulate);
// signing, on-card encapsulation, and certificate import stay unsupported.
func ParseKeyAlgorithm(value string) (byte, string, error) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "p256", "eccp256":
		return piv.AlgECCP256, "p256", nil
	case "p384", "eccp384":
		return piv.AlgECCP384, "p384", nil
	case "rsa1024":
		return piv.AlgRSA1024, "rsa1024", nil
	case "rsa2048":
		return piv.AlgRSA2048, "rsa2048", nil
	case "rsa3072":
		return piv.AlgRSA3072, "rsa3072", nil
	case "rsa4096":
		return piv.AlgRSA4096, "rsa4096", nil
	case "ed25519":
		return piv.AlgEd25519, "ed25519", nil
	case "x25519":
		return piv.AlgX25519, "x25519", nil
	case "mldsa44":
		return piv.AlgMLDSA44, "mldsa44", nil
	case "mldsa65":
		return piv.AlgMLDSA65, "mldsa65", nil
	case "mldsa87":
		return piv.AlgMLDSA87, "mldsa87", nil
	case "mlkem512":
		return piv.AlgMLKEM512, "mlkem512", nil
	case "mlkem768":
		return piv.AlgMLKEM768, "mlkem768", nil
	case "mlkem1024":
		return piv.AlgMLKEM1024, "mlkem1024", nil
	default:
		return 0, "", UsageError(fmt.Sprintf("unsupported key algorithm %q", value), "use one of p256, p384, rsa1024, rsa2048, rsa3072, rsa4096, ed25519, x25519, mldsa44, mldsa65, mldsa87, mlkem512, mlkem768, or mlkem1024 (ml-dsa/ml-kem preview)")
	}
}

// ParsePINPolicy resolves a slot PIN policy name to its YubiKey policy byte.
// An empty value selects the default, which omits the policy tag so the
// device applies its own default instead of preserving the slot's policy.
func ParsePINPolicy(value string) (byte, error) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "", "default":
		return piv.PinPolicyDefault, nil
	case "never":
		return piv.PinPolicyNever, nil
	case "once":
		return piv.PinPolicyOnce, nil
	case "always":
		return piv.PinPolicyAlways, nil
	default:
		return 0, UsageError(fmt.Sprintf("unsupported PIN policy %q", value), "use one of default, never, once, or always")
	}
}

// ParseTouchPolicy resolves a slot touch policy name to its YubiKey policy byte.
// An empty value selects the default, which omits the policy tag so the
// device applies its own default instead of preserving the slot's policy.
func ParseTouchPolicy(value string) (byte, error) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "", "default":
		return piv.TouchPolicyDefault, nil
	case "never":
		return piv.TouchPolicyNever, nil
	case "always":
		return piv.TouchPolicyAlways, nil
	case "cached":
		return piv.TouchPolicyCached, nil
	default:
		return 0, UsageError(fmt.Sprintf("unsupported touch policy %q", value), "use one of default, never, always, or cached")
	}
}

// ParsePrivateKeyData accepts PEM or DER private key input and returns the
// parsed private key. PKCS #8, SEC 1 EC, and PKCS #1 RSA encodings are
// supported.
func ParsePrivateKeyData(data []byte) (crypto.PrivateKey, error) {
	trimmed := bytes.TrimSpace(data)
	if bytes.HasPrefix(trimmed, []byte("-----BEGIN")) {
		block, _ := pem.Decode(data)
		if block == nil {
			return nil, IOError("unable to parse PEM private key", "provide a PEM or DER encoded private key", nil)
		}
		return parsePrivateKeyDER(block.Bytes)
	}
	return parsePrivateKeyDER(data)
}

func parsePrivateKeyDER(data []byte) (crypto.PrivateKey, error) {
	if key, err := x509.ParsePKCS8PrivateKey(data); err == nil {
		return key, nil
	}
	if key, err := x509.ParseECPrivateKey(data); err == nil {
		return key, nil
	}
	if key, err := x509.ParsePKCS1PrivateKey(data); err == nil {
		return key, nil
	}
	return nil, IOError("unable to parse private key input", "provide a PKCS #8, SEC 1, or PKCS #1 encoded private key", nil)
}

// ParsePrivateKeyForAlgorithm parses private key input for a key import with
// algorithm context. Baseline algorithms use ParsePrivateKeyData directly.
// Ed25519/X25519 first try the PEM/DER encodings (PKCS #8 round-trips for
// both); when that fails they fall back to a raw 32-byte seed supplied as
// binary, hex (64 characters), or base64 (44 characters), returned as
// *piv.OpaquePrivateKey. ML-KEM accepts only the raw 64-byte seed
// (FIPS 203 d||z, identical for all variants) supplied as binary, hex, or
// base64, returned as *piv.OpaquePrivateKey. Document the raw fallback for
// --in handling.
func ParsePrivateKeyForAlgorithm(data []byte, algorithm byte) (crypto.PrivateKey, error) {
	if piv.IsMLKEMAlgorithm(algorithm) {
		raw, err := parseRawKeyBytes(data, piv.MLKEMSeedLength)
		if err != nil {
			return nil, IOError("unable to parse private key input", fmt.Sprintf("provide a raw %d-byte seed (binary, hex, or base64) for %s", piv.MLKEMSeedLength, AlgorithmName(algorithm)), err)
		}
		return &piv.OpaquePrivateKey{Algorithm: algorithm, Raw: raw}, nil
	}
	if algorithm != piv.AlgEd25519 && algorithm != piv.AlgX25519 {
		return ParsePrivateKeyData(data)
	}
	if key, err := ParsePrivateKeyData(data); err == nil {
		return key, nil
	}
	raw, err := parseRawSeed(data)
	if err != nil {
		return nil, IOError("unable to parse private key input", "provide a PKCS #8 private key or a raw 32-byte seed (binary, hex, or base64) for ed25519/x25519", err)
	}
	return &piv.OpaquePrivateKey{Algorithm: algorithm, Raw: raw}, nil
}

func parseRawSeed(data []byte) ([]byte, error) {
	return parseRawKeyBytes(data, 32)
}

func parseRawKeyBytes(data []byte, want int) ([]byte, error) {
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == want {
		return append([]byte(nil), trimmed...), nil
	}
	text := strings.TrimSpace(string(trimmed))
	compact := strings.ReplaceAll(strings.ReplaceAll(text, " ", ""), "\n", "")
	compact = strings.ReplaceAll(compact, "\t", "")
	compact = strings.ReplaceAll(compact, "\r", "")
	if decoded, err := hex.DecodeString(compact); err == nil && len(decoded) == want {
		return decoded, nil
	}
	if decoded, err := base64.StdEncoding.DecodeString(compact); err == nil && len(decoded) == want {
		return decoded, nil
	}
	if decoded, err := base64.RawStdEncoding.DecodeString(compact); err == nil && len(decoded) == want {
		return decoded, nil
	}
	return nil, fmt.Errorf("expected %d raw key bytes, got %d input bytes", want, len(trimmed))
}

// ParseManagementAlgorithm resolves a management-key algorithm name.
func ParseManagementAlgorithm(value string) (byte, string, error) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "auto", "":
		return 0, "auto", nil
	case "3des":
		return piv.Alg3DES, "3des", nil
	case "aes128":
		return piv.AlgAES128, "aes128", nil
	case "aes192":
		return piv.AlgAES192, "aes192", nil
	case "aes256":
		return piv.AlgAES256, "aes256", nil
	default:
		return 0, "", UsageError(fmt.Sprintf("unsupported management key algorithm %q", value), "use auto, 3des, aes128, aes192, or aes256")
	}
}

// AlgorithmName returns the stable name of a PIV algorithm identifier.
func AlgorithmName(value byte) string {
	switch value {
	case piv.AlgECCP256:
		return "p256"
	case piv.AlgECCP384:
		return "p384"
	case piv.AlgRSA1024:
		return "rsa1024"
	case piv.AlgRSA2048:
		return "rsa2048"
	case piv.AlgRSA3072:
		return "rsa3072"
	case piv.AlgRSA4096:
		return "rsa4096"
	case piv.AlgEd25519:
		return "ed25519"
	case piv.AlgX25519:
		return "x25519"
	case piv.AlgMLDSA44:
		return "mldsa44"
	case piv.AlgMLDSA65:
		return "mldsa65"
	case piv.AlgMLDSA87:
		return "mldsa87"
	case piv.AlgMLKEM512:
		return "mlkem512"
	case piv.AlgMLKEM768:
		return "mlkem768"
	case piv.AlgMLKEM1024:
		return "mlkem1024"
	case piv.Alg3DES:
		return "3des"
	case piv.AlgAES128:
		return "aes128"
	case piv.AlgAES192:
		return "aes192"
	case piv.AlgAES256:
		return "aes256"
	default:
		return fmt.Sprintf("0x%02x", value)
	}
}

// InferPublicKeyAlgorithm resolves a PIV algorithm identifier from a public key.
func InferPublicKeyAlgorithm(publicKey crypto.PublicKey) (byte, string, error) {
	switch key := publicKey.(type) {
	case *ecdsa.PublicKey:
		switch key.Curve {
		case elliptic.P256():
			return piv.AlgECCP256, "p256", nil
		case elliptic.P384():
			return piv.AlgECCP384, "p384", nil
		default:
			return 0, "", UnsupportedError("the selected slot uses an unsupported elliptic curve", "use piv key public to inspect the slot")
		}
	case *rsa.PublicKey:
		bits := key.N.BitLen()
		if bits <= 1024 {
			return piv.AlgRSA1024, "rsa1024", nil
		}
		if bits <= 2048 {
			return piv.AlgRSA2048, "rsa2048", nil
		}
		if bits <= 3072 {
			return piv.AlgRSA3072, "rsa3072", nil
		}
		if bits <= 4096 {
			return piv.AlgRSA4096, "rsa4096", nil
		}
		return 0, "", UnsupportedError("the selected slot uses an unsupported RSA key size", "use a slot backed by rsa1024, rsa2048, rsa3072, or rsa4096")
	case *piv.OpaquePublicKey:
		return inferOpaqueKeyAlgorithm(key.Algorithm, publicKey)
	case piv.OpaquePublicKey:
		return inferOpaqueKeyAlgorithm(key.Algorithm, publicKey)
	default:
		return 0, "", UnsupportedError(fmt.Sprintf("unsupported public key type %T", publicKey), "use piv key public to inspect the slot")
	}
}

// inferOpaqueKeyAlgorithm resolves a PIV algorithm identifier from a
// YubiKey 6 opaque public key. Only recognized extension algorithms resolve;
// anything else stays an unsupported capability.
func inferOpaqueKeyAlgorithm(algorithm byte, publicKey crypto.PublicKey) (byte, string, error) {
	if piv.IsYubiKey6Algorithm(algorithm) {
		return algorithm, AlgorithmName(algorithm), nil
	}
	return 0, "", UnsupportedError(fmt.Sprintf("unsupported public key type %T", publicKey), "use piv key public to inspect the slot")
}

// ed25519OpaqueRaw extracts the 32-byte raw key from an Ed25519 opaque
// public key in either pointer or value form.
func ed25519OpaqueRaw(publicKey crypto.PublicKey) ([]byte, bool) {
	var algorithm byte
	var raw []byte
	switch key := publicKey.(type) {
	case *piv.OpaquePublicKey:
		if key == nil {
			return nil, false
		}
		algorithm, raw = key.Algorithm, key.Raw
	case piv.OpaquePublicKey:
		algorithm, raw = key.Algorithm, key.Raw
	default:
		return nil, false
	}
	if algorithm != piv.AlgEd25519 || len(raw) != 32 {
		return nil, false
	}
	return append([]byte(nil), raw...), true
}

// opaquePublicKeyAlgorithm extracts the algorithm identifier from a YubiKey 6
// opaque public key in either pointer or value form.
func opaquePublicKeyAlgorithm(publicKey crypto.PublicKey) (byte, bool) {
	switch key := publicKey.(type) {
	case *piv.OpaquePublicKey:
		if key == nil {
			return 0, false
		}
		return key.Algorithm, true
	case piv.OpaquePublicKey:
		return key.Algorithm, true
	default:
		return 0, false
	}
}

// isPostQuantumAlgorithm reports whether the identifier selects an ML-DSA
// or ML-KEM algorithm without a PEM/DER encoding in this release.
func isPostQuantumAlgorithm(algorithm byte) bool {
	switch algorithm {
	case piv.AlgMLDSA44, piv.AlgMLDSA65, piv.AlgMLDSA87,
		piv.AlgMLKEM512, piv.AlgMLKEM768, piv.AlgMLKEM1024:
		return true
	default:
		return false
	}
}

// EncodeCertificate serializes a DER certificate as PEM or DER.
func EncodeCertificate(certDER []byte, format string) ([]byte, error) {
	switch strings.ToLower(strings.TrimSpace(format)) {
	case "", "pem":
		return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER}), nil
	case "der":
		return append([]byte(nil), certDER...), nil
	default:
		return nil, UsageError(fmt.Sprintf("unsupported certificate format %q", format), "use pem or der")
	}
}

// ParseCertificateData accepts PEM or DER certificate input and returns DER bytes.
func ParseCertificateData(data []byte) ([]byte, error) {
	trimmed := strings.TrimSpace(string(data))
	if strings.HasPrefix(trimmed, "-----BEGIN") {
		block, _ := pem.Decode(data)
		if block == nil || block.Type != "CERTIFICATE" {
			return nil, IOError("unable to parse PEM certificate", "provide a PEM or DER encoded X.509 certificate", nil)
		}
		data = block.Bytes
	}
	if _, err := x509.ParseCertificate(data); err != nil {
		return nil, IOError("unable to parse certificate input", "provide a PEM or DER encoded X.509 certificate", err)
	}
	return append([]byte(nil), data...), nil
}

// ParseCertificateDataRaw accepts PEM or DER certificate input and returns
// DER bytes without X.509 validation. Use it with --raw-cert for
// post-quantum (ML-DSA) slot certificates that have no strict X.509 profile
// in this release. X25519 slots have no X.509 profile at all and reject
// certificate import even in raw mode.
func ParseCertificateDataRaw(data []byte) ([]byte, error) {
	trimmed := strings.TrimSpace(string(data))
	if strings.HasPrefix(trimmed, "-----BEGIN") {
		block, _ := pem.Decode(data)
		if block == nil {
			return nil, IOError("unable to parse PEM certificate", "provide a PEM or DER encoded certificate with --raw-cert", nil)
		}
		if len(block.Bytes) == 0 {
			return nil, IOError("unable to parse certificate input", "provide a PEM or DER encoded certificate with --raw-cert", nil)
		}
		return append([]byte(nil), block.Bytes...), nil
	}
	raw := append([]byte(nil), bytes.TrimSpace(data)...)
	if len(raw) == 0 {
		return nil, IOError("unable to parse certificate input", "provide a PEM or DER encoded certificate with --raw-cert", nil)
	}
	return raw, nil
}

// EncodePublicKey serializes a public key as PEM or DER.
//
// Post-quantum YubiKey 6 keys (ML-DSA/ML-KEM), X25519, and ambiguous opaque
// keys have no PEM/DER encoding here and report an unsupported capability
// instead of panicking inside x509. Ed25519 opaque keys (32-byte raw) encode
// through the standard library.
func EncodePublicKey(publicKey crypto.PublicKey, format string) ([]byte, error) {
	if algorithm, ok := opaquePublicKeyAlgorithm(publicKey); ok && isPostQuantumAlgorithm(algorithm) {
		return nil, UnsupportedError("the selected slot uses a post-quantum algorithm without PEM or DER encoding support", "use piv key public --format raw, base64, or hex for the opaque key bytes")
	}
	if raw, ok := ed25519OpaqueRaw(publicKey); ok {
		der, err := x509.MarshalPKIXPublicKey(ed25519.PublicKey(raw))
		if err != nil {
			return nil, InternalError("unable to encode public key", "inspect the slot and retry", err)
		}
		switch strings.ToLower(strings.TrimSpace(format)) {
		case "", "pem":
			return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), nil
		case "der":
			return der, nil
		default:
			return nil, UsageError(fmt.Sprintf("unsupported public key format %q", format), "use pem or der")
		}
	}
	if _, ok := opaquePublicKeyAlgorithm(publicKey); ok {
		return nil, UnsupportedError("the selected slot uses an opaque key without PEM or DER encoding support", "use piv key public --format raw, base64, or hex for the opaque key bytes")
	}
	der, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return nil, InternalError("unable to encode public key", "inspect the slot and retry", err)
	}
	switch strings.ToLower(strings.TrimSpace(format)) {
	case "", "pem":
		return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), nil
	case "der":
		return der, nil
	default:
		return nil, UsageError(fmt.Sprintf("unsupported public key format %q", format), "use pem or der")
	}
}

// EncodeBinary renders bytes using the requested encoding.
func EncodeBinary(data []byte, encoding string) ([]byte, string, error) {
	switch strings.ToLower(strings.TrimSpace(encoding)) {
	case "", "base64":
		return []byte(base64.StdEncoding.EncodeToString(data) + "\n"), "base64", nil
	case "hex":
		return []byte(strings.ToUpper(hex.EncodeToString(data)) + "\n"), "hex", nil
	case "raw":
		return append([]byte(nil), data...), "raw", nil
	default:
		return nil, "", UsageError(fmt.Sprintf("unsupported output encoding %q", encoding), "use base64, hex, or raw")
	}
}

// ReadInputFile loads an input file or stdin when path is "-".
func ReadInputFile(path string, stdin io.Reader) ([]byte, error) {
	if path == "-" {
		data, err := io.ReadAll(stdin)
		if err != nil {
			return nil, IOError("unable to read stdin", "provide valid input on stdin", err)
		}
		return data, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, IOError(fmt.Sprintf("unable to read %s", path), "check the file path and permissions", err)
	}
	return data, nil
}

// ParseObjectSelector resolves a known object name or hexadecimal tag.
func ParseObjectSelector(value string) (uint, string, error) {
	normalized := strings.ToLower(strings.TrimSpace(value))
	if tag, ok := objectNameMap[normalized]; ok {
		return tag, objectName(tag), nil
	}
	normalized = strings.TrimPrefix(normalized, "0x")
	parsed, err := strconv.ParseUint(normalized, 16, 32)
	if err != nil {
		return 0, "", UsageError(fmt.Sprintf("unsupported object selector %q", value), "use a known object name such as chuid or a hexadecimal tag such as 5fc102")
	}
	tag := uint(parsed)
	return tag, objectName(tag), nil
}

func objectName(tag uint) string {
	for _, object := range piv.KnownObjects() {
		if object.Tag == tag {
			return object.Name
		}
	}
	return ""
}

// BuildTLVNodes decodes a BER-TLV payload into a JSON-friendly tree.
func BuildTLVNodes(data []byte) ([]TLVNode, error) {
	tlvs, err := iso7816.ParseAllTLV(data)
	if err != nil {
		return nil, IOError("unable to decode TLV payload", "provide BER-TLV encoded input", err)
	}
	nodes := make([]TLVNode, 0, len(tlvs))
	for _, tlv := range tlvs {
		node, err := buildTLVNode(tlv)
		if err != nil {
			return nil, err
		}
		nodes = append(nodes, node)
	}
	return nodes, nil
}

func buildTLVNode(tlv *iso7816.TLV) (TLVNode, error) {
	if tlv == nil {
		return TLVNode{}, InternalError("unable to decode TLV payload", "provide BER-TLV encoded input", nil)
	}
	constructed := isConstructedTag(tlv.Tag)
	node := TLVNode{
		Tag:         strings.ToUpper(hex.EncodeToString(iso7816.EncodeTag(tlv.Tag))),
		Length:      len(tlv.Value),
		Constructed: constructed,
	}
	if !constructed || len(tlv.Value) == 0 {
		node.ValueHex = strings.ToUpper(hex.EncodeToString(tlv.Value))
		return node, nil
	}
	children, err := BuildTLVNodes(tlv.Value)
	if err != nil {
		node.ValueHex = strings.ToUpper(hex.EncodeToString(tlv.Value))
		return node, nil
	}
	node.Children = children
	return node, nil
}

func isConstructedTag(tag uint) bool {
	tagBytes := iso7816.EncodeTag(tag)
	return len(tagBytes) > 0 && tagBytes[0]&0x20 != 0
}

func sortedConfigValues(values []ConfigValueView) []ConfigValueView {
	result := append([]ConfigValueView(nil), values...)
	sort.Slice(result, func(left int, right int) bool {
		return result[left].Key < result[right].Key
	})
	return result
}
