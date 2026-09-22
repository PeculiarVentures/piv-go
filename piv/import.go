package piv

import (
	"crypto"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"fmt"
	"math/big"

	"github.com/PeculiarVentures/piv-go/iso7816"
)

// YubiKey PIN policy values for key generation and import.
const (
	// PinPolicyDefault omits the PIN policy tag, so the device applies its
	// own default policy instead of preserving the slot's previous policy.
	PinPolicyDefault byte = 0x00
	// PinPolicyNever disables PIN authentication for the slot key.
	PinPolicyNever byte = 0x01
	// PinPolicyOnce requires PIN verification once per session.
	PinPolicyOnce byte = 0x02
	// PinPolicyAlways requires PIN verification for each operation.
	PinPolicyAlways byte = 0x03
)

// YubiKey touch policy values for key generation and import.
const (
	// TouchPolicyDefault omits the touch policy tag, so the device applies
	// its own default policy instead of preserving the slot's previous policy.
	TouchPolicyDefault byte = 0x00
	// TouchPolicyNever disables touch confirmation for the slot key.
	TouchPolicyNever byte = 0x01
	// TouchPolicyAlways requires touch confirmation for each operation.
	TouchPolicyAlways byte = 0x02
	// TouchPolicyCached allows a cached touch confirmation.
	TouchPolicyCached byte = 0x03
)

// YubiKey IMPORT KEY (INS 0xFE) and policy extension tags.
const (
	// InsImportKey imports a private key into a PIV slot.
	InsImportKey byte = 0xFE
	// TagPinPolicy carries the slot PIN policy in generate/import payloads.
	TagPinPolicy uint = 0xAA
	// TagTouchPolicy carries the slot touch policy in generate/import payloads.
	TagTouchPolicy uint = 0xAB
)

// ImportKey imports a private key into the specified slot using the YubiKey
// IMPORT KEY command (00 FE <key_type> <slot>). Only two-prime RSA keys with
// exponent 65537 and ECDSA keys are supported for the baseline algorithms;
// YubiKey 6 RSA-3072/4096 use the same RSA halves encoding with half lengths
// 192/256, and Ed25519/X25519 import a 32-byte raw seed via tags 0x07/0x08.
// Ed25519 accepts ed25519.PrivateKey (seed taken from the first 32 bytes),
// X25519 accepts *ecdh.PrivateKey, and both accept *OpaquePrivateKey,
// OpaquePrivateKey, or a raw 32-byte []byte. ML-DSA and ML-KEM have no import
// APDU and gap-reject without sending a command. The algorithm byte
// selects the key type and must match the private key. Policy value 0x00
// (default) omits the corresponding tag, in which case the device applies its
// own default policy instead of preserving the slot's previous policy; values
// above 0x03 are rejected.
func (c *Client) ImportKey(slot Slot, algorithm byte, privateKey crypto.PrivateKey, pinPolicy byte, touchPolicy byte) error {
	if IsMLKEMAlgorithm(algorithm) || IsMLDSAAlgorithm(algorithm) {
		return unsupportedExtendedAlgorithmError("import", algorithm)
	}
	data, err := encodeImportKeyData(algorithm, privateKey, pinPolicy, touchPolicy)
	if err != nil {
		return err
	}
	cmd := &iso7816.Command{
		Cla:  0x00,
		Ins:  InsImportKey,
		P1:   algorithm,
		P2:   byte(slot),
		Data: data,
		Le:   -1,
	}
	resp, err := c.sendCommand(cmd)
	if err != nil {
		return fmt.Errorf("piv: import key into slot %s: %w", slot, err)
	}
	if err := resp.Err(); err != nil {
		return fmt.Errorf("piv: import key into slot %s: %w", slot, err)
	}
	return nil
}

func encodeImportKeyData(algorithm byte, privateKey crypto.PrivateKey, pinPolicy byte, touchPolicy byte) ([]byte, error) {
	if err := checkPolicyValue("PIN policy", pinPolicy); err != nil {
		return nil, err
	}
	if err := checkPolicyValue("touch policy", touchPolicy); err != nil {
		return nil, err
	}
	var data []byte
	switch key := privateKey.(type) {
	case *rsa.PrivateKey:
		if key.E != 65537 {
			return nil, fmt.Errorf("piv: unsupported RSA exponent %d, must be 65537", key.E)
		}
		if len(key.Primes) != 2 {
			return nil, fmt.Errorf("piv: unsupported RSA key with %d primes, exactly 2 primes are required", len(key.Primes))
		}
		if key.Precomputed.Dp == nil || key.Precomputed.Dq == nil || key.Precomputed.Qinv == nil {
			key.Precompute()
		}
		halfLen, err := rsaImportHalfLength(algorithm, key)
		if err != nil {
			return nil, err
		}
		data = append(data, iso7816.EncodeTLV(0x01, paddedBigInt(key.Primes[0], halfLen))...)
		data = append(data, iso7816.EncodeTLV(0x02, paddedBigInt(key.Primes[1], halfLen))...)
		data = append(data, iso7816.EncodeTLV(0x03, paddedBigInt(key.Precomputed.Dp, halfLen))...)
		data = append(data, iso7816.EncodeTLV(0x04, paddedBigInt(key.Precomputed.Dq, halfLen))...)
		data = append(data, iso7816.EncodeTLV(0x05, paddedBigInt(key.Precomputed.Qinv, halfLen))...)
	case *ecdsa.PrivateKey:
		scalarLen, err := ecdsaImportScalarLength(algorithm, key)
		if err != nil {
			return nil, err
		}
		data = iso7816.EncodeTLV(0x06, paddedBigInt(key.D, scalarLen))
	case ed25519.PrivateKey:
		if algorithm != AlgEd25519 {
			return nil, fmt.Errorf("piv: unsupported import algorithm 0x%02X for Ed25519 private key", algorithm)
		}
		if len(key) != ed25519.PrivateKeySize {
			return nil, fmt.Errorf("piv: unsupported Ed25519 private key length %d", len(key))
		}
		data = iso7816.EncodeTLV(0x07, append([]byte(nil), key.Seed()...))
	case *ecdh.PrivateKey:
		if algorithm != AlgX25519 {
			return nil, fmt.Errorf("piv: unsupported import algorithm 0x%02X for X25519 private key", algorithm)
		}
		if key.Curve() != ecdh.X25519() {
			return nil, fmt.Errorf("piv: unsupported ECDH curve for X25519 import")
		}
		raw := key.Bytes()
		if len(raw) != 32 {
			return nil, fmt.Errorf("piv: unsupported X25519 private key length %d", len(raw))
		}
		data = iso7816.EncodeTLV(0x08, raw)
	case *OpaquePrivateKey:
		raw, tag, err := opaqueImportFields(algorithm, key.Algorithm, key.Raw)
		if err != nil {
			return nil, err
		}
		data = iso7816.EncodeTLV(tag, raw)
	case OpaquePrivateKey:
		raw, tag, err := opaqueImportFields(algorithm, key.Algorithm, key.Raw)
		if err != nil {
			return nil, err
		}
		data = iso7816.EncodeTLV(tag, raw)
	case []byte:
		raw, tag, err := opaqueImportFields(algorithm, algorithm, key)
		if err != nil {
			return nil, err
		}
		data = iso7816.EncodeTLV(tag, raw)
	default:
		return nil, fmt.Errorf("piv: unsupported private key type %T", privateKey)
	}
	if pinPolicy != PinPolicyDefault {
		data = append(data, iso7816.EncodeTLV(TagPinPolicy, []byte{pinPolicy})...)
	}
	if touchPolicy != TouchPolicyDefault {
		data = append(data, iso7816.EncodeTLV(TagTouchPolicy, []byte{touchPolicy})...)
	}
	return data, nil
}

func rsaImportHalfLength(algorithm byte, key *rsa.PrivateKey) (int, error) {
	switch algorithm {
	case AlgRSA1024:
		if key.N.BitLen() != 1024 {
			return 0, fmt.Errorf("piv: unsupported import: RSA-1024 requires a 1024-bit key, got %d bits", key.N.BitLen())
		}
		return 64, nil
	case AlgRSA2048:
		if key.N.BitLen() != 2048 {
			return 0, fmt.Errorf("piv: unsupported import: RSA-2048 requires a 2048-bit key, got %d bits", key.N.BitLen())
		}
		return 128, nil
	case AlgRSA3072:
		if key.N.BitLen() != 3072 {
			return 0, fmt.Errorf("piv: unsupported import: RSA-3072 requires a 3072-bit key, got %d bits", key.N.BitLen())
		}
		return 192, nil
	case AlgRSA4096:
		if key.N.BitLen() != 4096 {
			return 0, fmt.Errorf("piv: unsupported import: RSA-4096 requires a 4096-bit key, got %d bits", key.N.BitLen())
		}
		return 256, nil
	default:
		return 0, fmt.Errorf("piv: unsupported import algorithm 0x%02X", algorithm)
	}
}

func ecdsaImportScalarLength(algorithm byte, key *ecdsa.PrivateKey) (int, error) {
	switch algorithm {
	case AlgECCP256:
		if key.Curve.Params().BitSize != 256 {
			return 0, fmt.Errorf("piv: unsupported import: ECCP-256 requires a P-256 key")
		}
		return 32, nil
	case AlgECCP384:
		if key.Curve.Params().BitSize != 384 {
			return 0, fmt.Errorf("piv: unsupported import: ECCP-384 requires a P-384 key")
		}
		return 48, nil
	default:
		return 0, fmt.Errorf("piv: unsupported import algorithm 0x%02X", algorithm)
	}
}

func paddedBigInt(value *big.Int, length int) []byte {
	raw := value.Bytes()
	if len(raw) >= length {
		return raw
	}
	padded := make([]byte, length)
	copy(padded[length-len(raw):], raw)
	return padded
}

// opaqueImportFields validates a 32-byte raw seed for Ed25519/X25519 import
// and resolves the IMPORT KEY tag: 0x07 for Ed25519, 0x08 for X25519. A zero
// key algorithm defers to the requested algorithm.
func opaqueImportFields(requestedAlgorithm byte, keyAlgorithm byte, raw []byte) ([]byte, uint, error) {
	var tag uint
	switch requestedAlgorithm {
	case AlgEd25519:
		tag = 0x07
	case AlgX25519:
		tag = 0x08
	default:
		return nil, 0, fmt.Errorf("piv: unsupported import algorithm 0x%02X for raw private key", requestedAlgorithm)
	}
	if keyAlgorithm != 0 && keyAlgorithm != requestedAlgorithm {
		return nil, 0, fmt.Errorf("piv: unsupported import: key algorithm 0x%02X does not match requested algorithm 0x%02X", keyAlgorithm, requestedAlgorithm)
	}
	if len(raw) != 32 {
		return nil, 0, fmt.Errorf("piv: unsupported raw private key length %d, must be 32 bytes", len(raw))
	}
	return append([]byte(nil), raw...), tag, nil
}
