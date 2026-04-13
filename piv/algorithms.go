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
