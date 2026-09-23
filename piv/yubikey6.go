package piv

import (
	"crypto/mlkem"
	"fmt"
)

// OpaquePublicKey carries the raw public key bytes for YubiKey 6 algorithms
// without a Go standard-library representation (Ed25519/X25519 raw keys and
// ML-DSA/ML-KEM post-quantum keys).
//
// Algorithm holds the PIV algorithm identifier (for example AlgEd25519). It
// is zero when the key was parsed from a stored object without algorithm
// context: ParsePublicKeyObject cannot tell Ed25519 from X25519 from the
// 0x86 tag alone, so callers with algorithm context (slot metadata, key
// generation responses) fill it in. Raw holds the tag value bytes verbatim.
type OpaquePublicKey struct {
	Algorithm byte
	Raw       []byte
}

// UnsupportedPublicKeyError reports a public key encoding that has no
// supported representation. Parsing paths return it for unknown tags or
// lengths instead of panicking.
type UnsupportedPublicKeyError struct {
	// Tag is the inner TLV tag observed (0 when no candidate tag is present).
	Tag uint
	// Length is the observed tag value length (-1 when absent).
	Length int
	// Detail carries additional context (for example the expected shape).
	Detail string
}

// Error implements the error interface.
func (e *UnsupportedPublicKeyError) Error() string {
	if e == nil {
		return "piv: unsupported public key encoding"
	}
	if e.Detail != "" {
		return fmt.Sprintf("piv: unsupported public key encoding: %s", e.Detail)
	}
	return fmt.Sprintf("piv: unsupported public key encoding: tag 0x%X length %d", e.Tag, e.Length)
}

// IsYubiKey6Algorithm reports whether the algorithm identifier belongs to
// the YubiKey 6 extension set. Extension algorithms are recognized for key
// discovery and display; per the pqc-v1 matrix most card operations are
// implemented (RSA-3072/4096, Ed25519, X25519 key agreement, ML-DSA, and
// ML-KEM generate/import/decapsulation) while ML-KEM signing, on-card
// encapsulation, and certificate import remain gaps.
func IsYubiKey6Algorithm(algorithm byte) bool {
	switch algorithm {
	case AlgRSA3072, AlgRSA4096,
		AlgEd25519, AlgX25519,
		AlgMLDSA44, AlgMLDSA65, AlgMLDSA87,
		AlgMLKEM512, AlgMLKEM768, AlgMLKEM1024:
		return true
	default:
		return false
	}
}

// yubiKey6PublicKeyLength returns the expected raw public key size for a
// YubiKey 6 opaque algorithm: 32 bytes for Ed25519/X25519, FIPS 203 sizes
// for ML-KEM, and FIPS 204 sizes for ML-DSA.
func yubiKey6PublicKeyLength(algorithm byte) (int, bool) {
	switch algorithm {
	case AlgEd25519, AlgX25519:
		return 32, true
	case AlgMLDSA44:
		return 1312, true
	case AlgMLDSA65:
		return 1952, true
	case AlgMLDSA87:
		return 2592, true
	case AlgMLKEM512:
		return 800, true
	case AlgMLKEM768:
		return 1184, true
	case AlgMLKEM1024:
		return 1568, true
	default:
		return 0, false
	}
}

// inferOpaqueAlgorithm resolves a YubiKey 6 algorithm from a post-quantum
// public key tag and value length: tag 0x87 carries ML-DSA keys and tag
// 0x88 carries ML-KEM keys. Ed25519/X25519 share tag 0x86 with length 32
// and stay ambiguous (Algorithm zero) without caller context.
func inferOpaqueAlgorithm(tag uint, length int) (byte, bool) {
	var candidates []byte
	switch tag {
	case 0x87:
		candidates = []byte{AlgMLDSA44, AlgMLDSA65, AlgMLDSA87}
	case 0x88:
		candidates = []byte{AlgMLKEM512, AlgMLKEM768, AlgMLKEM1024}
	default:
		return 0, false
	}
	for _, algorithm := range candidates {
		if size, ok := yubiKey6PublicKeyLength(algorithm); ok && size == length {
			return algorithm, true
		}
	}
	return 0, false
}

// OpaquePrivateKey carries raw private key material for YubiKey 6 algorithms
// without a Go standard-library private key representation. Algorithm holds
// the PIV algorithm identifier (for example AlgEd25519) and Raw holds the
// card encoding verbatim: 32-byte raw seed for Ed25519/X25519, and the
// 64-byte raw seed (FIPS 203 d||z) for ML-KEM import.
type OpaquePrivateKey struct {
	Algorithm byte
	Raw       []byte
}

// IsMLKEMAlgorithm reports whether the identifier selects an ML-KEM variant.
// ML-KEM supports on-card generation, import, and decapsulation; signing,
// on-card encapsulation, and certificate import stay unsupported.
func IsMLKEMAlgorithm(algorithm byte) bool {
	switch algorithm {
	case AlgMLKEM512, AlgMLKEM768, AlgMLKEM1024:
		return true
	default:
		return false
	}
}

// IsMLDSAAlgorithm reports whether the identifier selects an ML-DSA variant.
func IsMLDSAAlgorithm(algorithm byte) bool {
	switch algorithm {
	case AlgMLDSA44, AlgMLDSA65, AlgMLDSA87:
		return true
	default:
		return false
	}
}

// MLKEMSeedLength is the raw seed size (FIPS 203 d||z) accepted by
// IMPORT KEY tag 0x0A for every ML-KEM variant. The card expands the seed
// into the full decapsulation key internally and reports the encapsulation
// key (tag 0x88) through slot metadata.
const MLKEMSeedLength = 64

// MLKEMCiphertextLength returns the ciphertext size for an ML-KEM variant:
// 768 bytes for ML-KEM-512, 1088 for ML-KEM-768, and 1568 for ML-KEM-1024
// (FIPS 203).
func MLKEMCiphertextLength(algorithm byte) (int, bool) {
	switch algorithm {
	case AlgMLKEM512:
		return 768, true
	case AlgMLKEM768:
		return 1088, true
	case AlgMLKEM1024:
		return 1568, true
	default:
		return 0, false
	}
}

// MLKEMEncapsulationKeyFromSeed derives the encapsulation (public) key from
// a raw ML-KEM seed (FIPS 203 d||z, 64 bytes) using the standard library.
// ML-KEM-768 and ML-KEM-1024 are supported; ML-KEM-512 has no standard
// library implementation and reports an unsupported-algorithm error so
// callers can gap-reject without sending an APDU. Unknown algorithms and
// wrong seed lengths are rejected before any use of the bytes.
func MLKEMEncapsulationKeyFromSeed(algorithm byte, seed []byte) ([]byte, error) {
	if !IsMLKEMAlgorithm(algorithm) {
		return nil, fmt.Errorf("piv: unsupported ML-KEM algorithm 0x%02X", algorithm)
	}
	if len(seed) != MLKEMSeedLength {
		return nil, fmt.Errorf("piv: unsupported ML-KEM seed length %d for algorithm 0x%02X, must be %d bytes", len(seed), algorithm, MLKEMSeedLength)
	}
	switch algorithm {
	case AlgMLKEM768:
		key, err := mlkem.NewDecapsulationKey768(seed)
		if err != nil {
			return nil, fmt.Errorf("piv: expand ML-KEM-768 seed: %w", err)
		}
		return key.EncapsulationKey().Bytes(), nil
	case AlgMLKEM1024:
		key, err := mlkem.NewDecapsulationKey1024(seed)
		if err != nil {
			return nil, fmt.Errorf("piv: expand ML-KEM-1024 seed: %w", err)
		}
		return key.EncapsulationKey().Bytes(), nil
	default:
		return nil, unsupportedExtendedAlgorithmError("ML-KEM public key derivation", algorithm)
	}
}

// x25519SignError reports the explicit rejection of X25519 signing. X25519 is
// a key-agreement algorithm: use CalculateSecret (ECDH) instead. The message
// keeps both the "x25519 cannot sign: use ECDH" hint and the "not supported"
// substring so the CLI error mapper classifies it as an unsupported
// capability (exit 4) instead of an internal error.
func x25519SignError(operation string) error {
	return fmt.Errorf("piv: x25519 cannot sign: use ECDH for %s: not supported by this release", operation)
}

// unsupportedExtendedAlgorithmError reports the explicit rejection of a
// YubiKey 6 extension algorithm on a card-touching operation. The message
// keeps the "not supported" substring so CLI error mapping classifies it as
// an unsupported capability.
func unsupportedExtendedAlgorithmError(operation string, algorithm byte) error {
	return fmt.Errorf("piv: unsupported %s for algorithm 0x%02X: not supported by this release", operation, algorithm)
}
