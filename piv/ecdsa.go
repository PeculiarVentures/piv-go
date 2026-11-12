package piv

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/asn1"
	"errors"
	"fmt"
	"math/big"
)

// ErrInvalidECDSAParameters identifies an invalid key, digest, or protocol
// algorithm for the additive ECDSA signing API.
var ErrInvalidECDSAParameters = errors.New("piv: invalid ECDSA signing parameters")

// PrepareECDSADigest converts a digest to the fixed-width, big-endian ECDSA
// representative expected by PIV cards. It takes the leftmost order-bit-length
// bits, then pads short digests on the left. It never hashes the input or
// infers the hash algorithm from its length. The public key must be a valid
// NIST P-256, P-384, or P-521 point. P-521 preparation is an off-card primitive;
// it does not establish device or transport support for that curve.
//
// This is the ECDSA hash-to-integer conversion used by crypto/ecdsa and FIPS
// 186-5. It is pure and can be called before requesting a PIN.
func PrepareECDSADigest(publicKey *ecdsa.PublicKey, digest []byte) ([]byte, error) {
	if publicKey == nil || publicKey.Curve == nil || publicKey.X == nil || publicKey.Y == nil {
		return nil, fmt.Errorf("%w: public key is required", ErrInvalidECDSAParameters)
	}
	switch publicKey.Curve {
	case elliptic.P256(), elliptic.P384(), elliptic.P521():
	default:
		return nil, fmt.Errorf("%w: unsupported named curve", ErrInvalidECDSAParameters)
	}
	if !publicKey.Curve.IsOnCurve(publicKey.X, publicKey.Y) {
		return nil, fmt.Errorf("%w: public point is not on the named curve", ErrInvalidECDSAParameters)
	}
	if len(digest) == 0 {
		return nil, fmt.Errorf("%w: digest must not be empty", ErrInvalidECDSAParameters)
	}
	orderBits := publicKey.Curve.Params().N.BitLen()
	width := (orderBits + 7) / 8
	if len(digest) > width {
		digest = digest[:width]
	}
	integer := new(big.Int).SetBytes(digest)
	if excess := len(digest)*8 - orderBits; excess > 0 {
		integer.Rsh(integer, uint(excess))
	}
	return integer.FillBytes(make([]byte, width)), nil
}

// ValidateECDSASignRequest checks the exact public key, digest and protocol
// algorithm accepted by SignECDSA without contacting a card. A consumer can
// call it before requesting a PIN. Device/firmware support, current private-key
// presence and application authorization remain separate responsibilities.
func ValidateECDSASignRequest(algorithm byte, publicKey *ecdsa.PublicKey, digest []byte) error {
	_, err := prepareECDSASignRequest(algorithm, publicKey, digest)
	return err
}

func prepareECDSASignRequest(algorithm byte, publicKey *ecdsa.PublicKey, digest []byte) ([]byte, error) {
	challenge, err := PrepareECDSADigest(publicKey, digest)
	if err != nil {
		return nil, err
	}
	if !(algorithm == AlgECCP256 && publicKey.Curve == elliptic.P256() || algorithm == AlgECCP384 && publicKey.Curve == elliptic.P384()) {
		return nil, fmt.Errorf("%w: protocol algorithm does not match the named curve", ErrInvalidECDSAParameters)
	}
	return challenge, nil
}

// SignECDSA signs an already computed digest using a P-256 or P-384 slot key.
// It validates the exact named curve against the protocol algorithm, converts
// the digest with PrepareECDSADigest and performs GENERAL AUTHENTICATE. The
// result is a DER ECDSA signature, not a fixed-width concatenation of r and s.
// No PIN verification or application authorization is performed. Adapters
// remain responsible for establishing device, firmware and slot support.
// The supplied public key is validated for its parameters, but the returned
// signature is not cryptographically verified against it. Call
// ecdsa.VerifyASN1 or a trusted higher-layer verifier before accepting it.
// Malformed or noncanonical DER signatures return
// ErrInvalidSignatureResponse after the private operation may have completed;
// callers must not automatically retry the operation on that error.
// Legacy Sign keeps its byte-for-byte challenge behavior.
func (c *Client) SignECDSA(algorithm byte, slot Slot, publicKey *ecdsa.PublicKey, digest []byte) ([]byte, error) {
	challenge, err := prepareECDSASignRequest(algorithm, publicKey, digest)
	if err != nil {
		return nil, err
	}
	if c == nil || c.card == nil {
		return nil, fmt.Errorf("%w: client card is required", ErrInvalidECDSAParameters)
	}
	signature, err := c.Authenticate(algorithm, slot, challenge)
	if err != nil {
		return nil, fmt.Errorf("piv: sign ECDSA with slot %s: %w", slot, err)
	}
	var values struct{ R, S *big.Int }
	rest, err := asn1.Unmarshal(signature, &values)
	if err != nil {
		return nil, fmt.Errorf("%w: ECDSA slot %s: invalid DER signature: %w", ErrInvalidSignatureResponse, slot, err)
	}
	if len(rest) != 0 || values.R == nil || values.S == nil || values.R.Sign() <= 0 || values.S.Sign() <= 0 || values.R.Cmp(publicKey.Params().N) >= 0 || values.S.Cmp(publicKey.Params().N) >= 0 {
		return nil, fmt.Errorf("%w: ECDSA slot %s: invalid DER signature values", ErrInvalidSignatureResponse, slot)
	}
	canonical, err := asn1.Marshal(values)
	if err != nil || !bytes.Equal(canonical, signature) {
		return nil, fmt.Errorf("%w: ECDSA slot %s: noncanonical DER signature", ErrInvalidSignatureResponse, slot)
	}
	return signature, nil
}
