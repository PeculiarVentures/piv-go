package app

import (
	"crypto"
	"crypto/ecdsa"
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
func ParseSlot(value string) (piv.Slot, error) {
	normalized := strings.ToLower(strings.TrimSpace(value))
	if slot, ok := slotNameMap[normalized]; ok {
		return slot, nil
	}
	normalized = strings.TrimPrefix(normalized, "0x")
	parsed, err := strconv.ParseUint(normalized, 16, 8)
	if err != nil {
		return 0, UsageError(fmt.Sprintf("unsupported slot %q", value), "use auth, sign, key-mgmt, card-auth, or a hexadecimal alias such as 9a")
	}
	slot := piv.Slot(parsed)
	switch slot {
	case piv.SlotAuthentication, piv.SlotManagement, piv.SlotSignature, piv.SlotKeyManagement, piv.SlotCardAuth:
		return slot, nil
	default:
		return 0, UsageError(fmt.Sprintf("unsupported slot %q", value), "use auth, sign, key-mgmt, card-auth, or a hexadecimal alias such as 9a")
	}
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

// ParseKeyAlgorithm resolves a key generation algorithm name.
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
	default:
		return 0, "", UsageError(fmt.Sprintf("unsupported key algorithm %q", value), "use one of p256, p384, rsa1024, or rsa2048")
	}
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
		return 0, "", UnsupportedError("the selected slot uses an unsupported RSA key size", "use a slot backed by rsa1024 or rsa2048")
	default:
		return 0, "", UnsupportedError(fmt.Sprintf("unsupported public key type %T", publicKey), "use piv key public to inspect the slot")
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

// EncodePublicKey serializes a public key as PEM or DER.
func EncodePublicKey(publicKey crypto.PublicKey, format string) ([]byte, error) {
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
