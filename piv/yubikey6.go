package piv

import "fmt"

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
// discovery and display only: generation, import, and signing reject them
// without sending an APDU.
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

// unsupportedExtendedAlgorithmError reports the explicit rejection of a
// YubiKey 6 extension algorithm on a card-touching operation. The message
// keeps the "not supported" substring so CLI error mapping classifies it as
// an unsupported capability.
func unsupportedExtendedAlgorithmError(operation string, algorithm byte) error {
	return fmt.Errorf("piv: unsupported %s for algorithm 0x%02X: not supported by this release", operation, algorithm)
}
