package piv

// Algorithm identifiers used in PIV operations.
const (
	AlgRSA1024 byte = 0x06
	AlgRSA2048 byte = 0x07
	AlgECCP256 byte = 0x11
	AlgECCP384 byte = 0x14
	Alg3DES    byte = 0x03
	AlgAES128  byte = 0x08
	AlgAES192  byte = 0x0A
	AlgAES256  byte = 0x0C
)

// YubiKey 6 extension algorithm identifiers.
//
// These identifiers are recognized for key discovery and display only.
// Key generation, import, and signing with these algorithms are explicitly
// rejected (see IsYubiKey6Algorithm): full cryptographic support, private
// key encodings, and KEM operations are out of scope for this release.
const (
	// AlgRSA3072 selects RSA-3072 (YubiKey 6 extension).
	AlgRSA3072 byte = 0x05
	// AlgRSA4096 selects RSA-4096 (YubiKey 6 extension).
	AlgRSA4096 byte = 0x16
	// AlgEd25519 selects Ed25519 (YubiKey 6 extension).
	AlgEd25519 byte = 0xE0
	// AlgX25519 selects X25519 (YubiKey 6 extension).
	AlgX25519 byte = 0xE1
	// AlgMLDSA44 selects ML-DSA-44 (YubiKey 6 extension).
	AlgMLDSA44 byte = 0xE2
	// AlgMLDSA65 selects ML-DSA-65 (YubiKey 6 extension).
	AlgMLDSA65 byte = 0xE3
	// AlgMLDSA87 selects ML-DSA-87 (YubiKey 6 extension).
	AlgMLDSA87 byte = 0xE4
	// AlgMLKEM512 selects ML-KEM-512 (YubiKey 6 extension).
	AlgMLKEM512 byte = 0xE5
	// AlgMLKEM768 selects ML-KEM-768 (YubiKey 6 extension).
	AlgMLKEM768 byte = 0xE6
	// AlgMLKEM1024 selects ML-KEM-1024 (YubiKey 6 extension).
	AlgMLKEM1024 byte = 0xE7
)
