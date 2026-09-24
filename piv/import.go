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
// OpaquePrivateKey, or a raw 32-byte []byte. ML-KEM imports the 64-byte raw
// seed (FIPS 203 d||z, identical for all variants) via tag 0x0A, accepting
// *OpaquePrivateKey, OpaquePrivateKey, or a raw []byte; the card expands the
// seed into the full decapsulation key internally. ML-DSA has no import
// APDU and gap-rejects without sending a command. The
// algorithm byte selects the key type and must match the private key. Policy
// value 0x00 (default) omits the corresponding tag, in which case the device
// applies its own default policy instead of preserving the slot's previous
// policy; values above 0x03 are rejected.
func (c *Client) ImportKey(slot Slot, algorithm byte, privateKey crypto.PrivateKey, pinPolicy byte, touchPolicy byte) error {
	if IsMLDSAAlgorithm(algorithm) {
		return unsupportedExtendedAlgorithmError("import", algorithm)
	}
	data, err := encodeImportKeyData(algorithm, privateKey, pinPolicy, touchPolicy)
	if err != nil {
		return err
	}
	return c.sendImportKey(slot, algorithm, data)
}

// sendImportKey issues IMPORT KEY (INS 0xFE), splitting payloads above the
// short-APDU limit into chained commands (CLA 0x10 intermediates, CLA 0x00
// final), mirroring ykman and PutData. Legacy firmware without extended-APDU
// support (for example YubiKey NEO) rejects a single extended-length IMPORT
// KEY with 6700, while RSA-2048 payloads always exceed 255 bytes.
func (c *Client) sendImportKey(slot Slot, algorithm byte, data []byte) error {
	if len(data) <= 0xFF {
		return c.importKeyChunk(0x00, slot, algorithm, data)
	}
	const maxChunkSize = 216
	for len(data) > maxChunkSize {
		if err := c.importKeyChunk(0x10, slot, algorithm, data[:maxChunkSize]); err != nil {
			return err
		}
		data = data[maxChunkSize:]
	}
	return c.importKeyChunk(0x00, slot, algorithm, data)
}

func (c *Client) importKeyChunk(cla byte, slot Slot, algorithm byte, chunk []byte) error {
	cmd := &iso7816.Command{
		Cla:  cla,
		Ins:  InsImportKey,
		P1:   algorithm,
		P2:   byte(slot),
		Data: chunk,
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
	halfLengths := map[byte]int{AlgRSA1024: 64, AlgRSA2048: 128, AlgRSA3072: 192, AlgRSA4096: 256}
	halfLen, ok := halfLengths[algorithm]
	if !ok {
		return 0, fmt.Errorf("piv: unsupported import algorithm 0x%02X", algorithm)
	}
	wantBits := halfLen * 16
	// Generated keys may carry a modulus up to 7 bits short of the nominal
	// size (leading zero bits); the halves encoding pads each factor to the
	// fixed half length either way.
	bits := key.N.BitLen()
	if bits > wantBits || bits <= wantBits-8 {
		return 0, fmt.Errorf("piv: unsupported import: RSA-%d requires a %d-bit key, got %d bits: not supported", wantBits, wantBits, bits)
	}
	return halfLen, nil
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

// opaqueImportFields validates raw private key material for Ed25519/X25519
// and ML-KEM import and resolves the IMPORT KEY tag: 0x07 for Ed25519,
// 0x08 for X25519, and 0x0A for ML-KEM. Ed25519/X25519 take a 32-byte raw
// seed; ML-KEM takes the 64-byte raw seed (FIPS 203 d||z, identical for all
// variants), which the card expands into the full decapsulation key. A zero
// key algorithm defers to the requested algorithm. Algorithm mismatch and
// wrong lengths are rejected before any APDU is sent.
func opaqueImportFields(requestedAlgorithm byte, keyAlgorithm byte, raw []byte) ([]byte, uint, error) {
	var tag uint
	wantLen := 32
	switch requestedAlgorithm {
	case AlgEd25519:
		tag = 0x07
	case AlgX25519:
		tag = 0x08
	case AlgMLKEM512, AlgMLKEM768, AlgMLKEM1024:
		tag = 0x0A
		wantLen = MLKEMSeedLength
	default:
		return nil, 0, fmt.Errorf("piv: unsupported import algorithm 0x%02X for raw private key", requestedAlgorithm)
	}
	if keyAlgorithm != 0 && keyAlgorithm != requestedAlgorithm {
		return nil, 0, fmt.Errorf("piv: unsupported import: key algorithm 0x%02X does not match requested algorithm 0x%02X", keyAlgorithm, requestedAlgorithm)
	}
	if len(raw) != wantLen {
		return nil, 0, fmt.Errorf("piv: unsupported raw private key length %d for algorithm 0x%02X, must be %d bytes", len(raw), requestedAlgorithm, wantLen)
	}
	return append([]byte(nil), raw...), tag, nil
}
