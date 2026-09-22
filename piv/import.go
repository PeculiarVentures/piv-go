package piv

import (
	"crypto"
	"crypto/ecdsa"
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
// exponent 65537 and ECDSA keys are supported; multi-prime RSA keys and other
// private key types are rejected as unsupported (deferred). The algorithm byte
// selects the key type and must be one of AlgRSA1024, AlgRSA2048, AlgECCP256, or AlgECCP384. Policy value 0x00
// (default) omits the corresponding tag, in which case the device applies its
// own default policy instead of preserving the slot's previous policy; values
// above 0x03 are rejected.
func (c *Client) ImportKey(slot Slot, algorithm byte, privateKey crypto.PrivateKey, pinPolicy byte, touchPolicy byte) error {
	if IsYubiKey6Algorithm(algorithm) {
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
