package piv

import (
	"crypto"
	"crypto/aes"
	"crypto/des"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"fmt"
	"math/big"

	internalutil "github.com/PeculiarVentures/piv-go/internal"
	"github.com/PeculiarVentures/piv-go/iso7816"
)

// AuthenticateManagementKey authenticates to the card using the provided
// management key. The algorithm is inferred from the key length.
func (c *Client) AuthenticateManagementKey(key []byte) error {
	algorithm, err := managementAlgorithmFromKey(key)
	if err != nil {
		return err
	}
	return c.AuthenticateManagementKeyWithAlgorithm(algorithm, key)
}

// AuthenticateManagementKeyWithAlgorithm authenticates to the card using the
// provided management key and explicit algorithm.
func (c *Client) AuthenticateManagementKeyWithAlgorithm(algorithm byte, key []byte) error {
	block, err := managementCipher(algorithm, key)
	if err != nil {
		return fmt.Errorf("piv: management authenticate: %w", err)
	}

	request := iso7816.EncodeTLV(0x7C, iso7816.EncodeTLV(0x81, nil))
	resp, err := c.sendCommand(managementAuthenticateCommand(algorithm, request))
	if err != nil {
		return fmt.Errorf("piv: management authenticate: %w", err)
	}
	if err := resp.Err(); err != nil {
		return fmt.Errorf("piv: management authenticate: %w", err)
	}

	challenge, err := parseManagementChallenge(resp.Data)
	if err != nil {
		return fmt.Errorf("piv: management authenticate: %w", err)
	}
	if len(challenge) != block.BlockSize() {
		return fmt.Errorf("piv: management authenticate: challenge length %d does not match block size %d", len(challenge), block.BlockSize())
	}

	encrypted := make([]byte, len(challenge))
	block.Encrypt(encrypted, challenge)

	response := iso7816.EncodeTLV(0x7C, iso7816.EncodeTLV(0x82, encrypted))
	resp, err = c.sendCommand(managementAuthenticateCommand(algorithm, response))
	if err != nil {
		return fmt.Errorf("piv: management authenticate: %w", err)
	}
	if err := resp.Err(); err != nil {
		return fmt.Errorf("piv: management authenticate: %w", err)
	}

	return nil
}

// GenerateKeyPair generates an asymmetric key pair in the specified slot and
// returns the corresponding public key.
func (c *Client) GenerateKeyPair(slot Slot, algorithm byte) (crypto.PublicKey, error) {
	resp, err := c.sendCommand(generateAsymmetricKeyPairCommand(slot, algorithm))
	if err != nil {
		return nil, fmt.Errorf("piv: generate key pair in slot %s: %w", slot, err)
	}
	if err := resp.Err(); err != nil {
		return nil, fmt.Errorf("piv: generate key pair in slot %s: %w", slot, err)
	}

	publicKey, err := parseGeneratedPublicKey(algorithm, resp.Data)
	if err != nil {
		return nil, fmt.Errorf("piv: generate key pair in slot %s: %w", slot, err)
	}
	return publicKey, nil
}

func managementAlgorithmFromKey(key []byte) (byte, error) {
	switch len(key) {
	case 16:
		return AlgAES128, nil
	case 24:
		return Alg3DES, nil
	case 32:
		return AlgAES256, nil
	default:
		return 0, fmt.Errorf("unsupported management key length %d", len(key))
	}
}

func managementCipher(algorithm byte, key []byte) (cipherBlock, error) {
	switch algorithm {
	case Alg3DES:
		if len(key) != 24 {
			return nil, fmt.Errorf("3DES management key must be 24 bytes, got %d", len(key))
		}
		return des.NewTripleDESCipher(key)
	case AlgAES128:
		if len(key) != 16 {
			return nil, fmt.Errorf("AES-128 management key must be 16 bytes, got %d", len(key))
		}
		return aes.NewCipher(key)
	case AlgAES192:
		if len(key) != 24 {
			return nil, fmt.Errorf("AES-192 management key must be 24 bytes, got %d", len(key))
		}
		return aes.NewCipher(key)
	case AlgAES256:
		if len(key) != 32 {
			return nil, fmt.Errorf("AES-256 management key must be 32 bytes, got %d", len(key))
		}
		return aes.NewCipher(key)
	default:
		return nil, fmt.Errorf("unsupported management algorithm 0x%02X", algorithm)
	}
}

type cipherBlock interface {
	BlockSize() int
	Encrypt(dst, src []byte)
}

func parseManagementChallenge(data []byte) ([]byte, error) {
	tlvs, err := iso7816.ParseAllTLV(data)
	if err != nil {
		return nil, fmt.Errorf("parse challenge response: %w", err)
	}
	authTLV := iso7816.FindTag(tlvs, 0x7C)
	if authTLV == nil {
		return nil, fmt.Errorf("auth response tag 0x7C not found")
	}

	innerTLVs, err := iso7816.ParseAllTLV(authTLV.Value)
	if err != nil {
		return nil, fmt.Errorf("parse auth template: %w", err)
	}

	challengeTLV := iso7816.FindTag(innerTLVs, 0x81)
	if challengeTLV == nil {
		challengeTLV = iso7816.FindTag(innerTLVs, 0x80)
	}
	if challengeTLV == nil {
		return nil, fmt.Errorf("challenge tag not found")
	}

	challenge := make([]byte, len(challengeTLV.Value))
	copy(challenge, challengeTLV.Value)
	return challenge, nil
}

func parseGeneratedPublicKey(algorithm byte, data []byte) (crypto.PublicKey, error) {
	tlvs, err := iso7816.ParseAllTLV(data)
	if err != nil {
		return nil, fmt.Errorf("parse key generation response: %w", err)
	}
	keyTLV := iso7816.FindTag(tlvs, 0x7F49)
	if keyTLV == nil {
		return nil, fmt.Errorf("public key tag 0x7F49 not found")
	}

	innerTLVs, err := iso7816.ParseAllTLV(keyTLV.Value)
	if err != nil {
		return nil, fmt.Errorf("parse public key template: %w", err)
	}

	switch algorithm {
	case AlgRSA1024, AlgRSA2048:
		modulusTLV := iso7816.FindTag(innerTLVs, 0x81)
		exponentTLV := iso7816.FindTag(innerTLVs, 0x82)
		if modulusTLV == nil || exponentTLV == nil {
			return nil, fmt.Errorf("RSA public key fields are incomplete")
		}

		exponent := new(big.Int).SetBytes(exponentTLV.Value)
		if !exponent.IsInt64() {
			return nil, fmt.Errorf("RSA exponent is too large")
		}

		return &rsa.PublicKey{
			N: new(big.Int).SetBytes(modulusTLV.Value),
			E: int(exponent.Int64()),
		}, nil
	case AlgECCP256:
		return parseECDSAPublicKey(elliptic.P256(), innerTLVs)
	case AlgECCP384:
		return parseECDSAPublicKey(elliptic.P384(), innerTLVs)
	default:
		return nil, fmt.Errorf("unsupported key generation algorithm 0x%02X", algorithm)
	}
}

// StoreGeneratedPublicKey stores the generated public key in the slot's PIV
// data object using the same 0x53 wrapper shape used by SafeNet's PKCS#11
// interface after on-device key generation.
func (c *Client) StoreGeneratedPublicKey(slot Slot, algorithm byte, publicKey crypto.PublicKey) error {
	tag := slotToObjectID(slot)
	if tag == 0 {
		return fmt.Errorf("unsupported slot %s", slot)
	}

	publicKeyTemplate, err := encodeGeneratedPublicKeyTemplate(algorithm, publicKey)
	if err != nil {
		return err
	}

	data := append([]byte{}, publicKeyTemplate...)
	data = append(data, iso7816.EncodeTLV(0x71, []byte{0x00})...)
	data = append(data, iso7816.EncodeTLV(0xFE, nil)...)

	if err := c.PutData(tag, iso7816.EncodeTLV(0x53, data)); err != nil {
		return fmt.Errorf("piv: store generated public key for slot %s: %w", slot, err)
	}
	return nil
}

func parseECDSAPublicKey(curve elliptic.Curve, tlvs []*iso7816.TLV) (crypto.PublicKey, error) {
	pointTLV := iso7816.FindTag(tlvs, 0x86)
	if pointTLV == nil {
		return nil, fmt.Errorf("EC public key point tag 0x86 not found")
	}

	x, y, err := internalutil.DecodeUncompressedPoint(curve, pointTLV.Value)
	if err != nil {
		return nil, fmt.Errorf("invalid EC public key point")
	}

	return &ecdsa.PublicKey{Curve: curve, X: x, Y: y}, nil
}

func encodeGeneratedPublicKeyTemplate(algorithm byte, publicKey crypto.PublicKey) ([]byte, error) {
	switch algorithm {
	case AlgRSA1024, AlgRSA2048:
		rsaKey, ok := publicKey.(*rsa.PublicKey)
		if !ok {
			return nil, fmt.Errorf("expected RSA public key, got %T", publicKey)
		}

		template := iso7816.EncodeTLV(0x81, rsaKey.N.Bytes())
		template = append(template, iso7816.EncodeTLV(0x82, big.NewInt(int64(rsaKey.E)).Bytes())...)
		return iso7816.EncodeTLV(0x7F49, template), nil
	case AlgECCP256, AlgECCP384:
		ecdsaKey, ok := publicKey.(*ecdsa.PublicKey)
		if !ok {
			return nil, fmt.Errorf("expected ECDSA public key, got %T", publicKey)
		}

		point, err := ecdsaKey.Bytes()
		if err != nil {
			return nil, err
		}
		return iso7816.EncodeTLV(0x7F49, iso7816.EncodeTLV(0x86, point)), nil
	default:
		return nil, fmt.Errorf("unsupported key algorithm 0x%02X", algorithm)
	}
}
