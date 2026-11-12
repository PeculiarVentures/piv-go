package piv

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	_ "crypto/sha256"
	_ "crypto/sha512"
	"errors"
	"fmt"
	"io"
	"math/big"

	"github.com/PeculiarVentures/piv-go/internal/rsascheme"
)

// ErrInvalidRSAParameters identifies invalid RSA key, input, or scheme parameters.
var ErrInvalidRSAParameters = errors.New("piv: invalid RSA signing parameters")

// ErrUnsupportedRSAOptions identifies a scheme or hash not implemented by SignRSA.
var ErrUnsupportedRSAOptions = errors.New("piv: unsupported RSA signing options")

// RSASignOptions specifies one complete RSA signing operation. The implementations
// are RSAPKCS1v15DigestOptions, RSAPKCS1v15PayloadOptions, and RSAPSSOptions.
// Nil options are rejected: no scheme, hash, MGF, or salt default is inferred.
type RSASignOptions interface {
	rsaSignOptions()
}

// RSAPKCS1v15DigestOptions requests PKCS#1 v1.5 over a digest. SignRSA adds the
// DigestInfo for Hash. SHA-256, SHA-384, and SHA-512 are supported.
type RSAPKCS1v15DigestOptions struct {
	Hash crypto.Hash
}

func (RSAPKCS1v15DigestOptions) rsaSignOptions() {}

// RSAPKCS1v15PayloadOptions requests PKCS#1 v1.5 type-1 padding over exact input
// bytes. Input may contain a caller's DigestInfo; it is never parsed or rewritten.
// The payload is limited to the modulus width minus eleven bytes. This does not
// expose an unpadded RSA private-key primitive.
type RSAPKCS1v15PayloadOptions struct{}

func (RSAPKCS1v15PayloadOptions) rsaSignOptions() {}

// RSAPSSOptions requests PSS over an already computed digest. Hash and MGF1Hash
// must both be explicit supported SHA-2 hashes; this release supports only equal
// hash/MGF1-hash combinations. SaltLength is an exact nonnegative byte count:
// zero means empty salt, unlike crypto/rsa.PSSSaltLengthAuto. Negative sentinel
// values are rejected. To request hash-sized salt, set SaltLength to Hash.Size().
type RSAPSSOptions struct {
	Hash       crypto.Hash
	MGF1Hash   crypto.Hash
	SaltLength int
}

func (RSAPSSOptions) rsaSignOptions() {}

// ValidateRSASignRequest checks a SignRSA request without contacting a card or
// reading randomness. A consumer can call it before requesting a PIN. It verifies the
// protocol algorithm's modulus-size binding, not device/firmware support or key
// presence. Those remain adapter and application responsibilities.
func ValidateRSASignRequest(algorithm byte, publicKey *rsa.PublicKey, input []byte, options RSASignOptions) error {
	_, err := validateRSARequest(algorithm, publicKey, input, options)
	return err
}

// ValidateRSA is the compatibility name for ValidateRSASignRequest.
func ValidateRSA(algorithm byte, publicKey *rsa.PublicKey, input []byte, options RSASignOptions) error {
	return ValidateRSASignRequest(algorithm, publicKey, input, options)
}

func validateRSARequest(algorithm byte, publicKey *rsa.PublicKey, input []byte, options RSASignOptions) (resolvedRSAOptions, error) {
	if err := validateRSAPublicKey(publicKey); err != nil {
		return resolvedRSAOptions{}, err
	}
	k, ok := rsaModulusLength(algorithm)
	if !ok {
		return resolvedRSAOptions{}, fmt.Errorf("%w: algorithm 0x%02X is not an implemented RSA identifier", ErrUnsupportedRSAOptions, algorithm)
	}
	if publicKey.N.BitLen() != k*8 {
		return resolvedRSAOptions{}, fmt.Errorf("%w: algorithm 0x%02X requires a %d-bit modulus, got %d bits", ErrInvalidRSAParameters, algorithm, k*8, publicKey.N.BitLen())
	}
	return resolveRSAOptions(publicKey, input, options)
}

// SignRSA signs input with the requested scheme using GENERAL AUTHENTICATE.
// It validates and encodes on the host, then calls Authenticate exactly once
// (which may chain transport APDUs). It never calls legacy Sign, so there is no
// second PKCS#1 padding step. PSS salt comes from crypto/rand.Reader; randomness
// failures occur before any APDU. No caller-supplied encoded block or fixed salt
// is accepted. The returned signature is exactly the public modulus width.
//
// RSA-2048, RSA-3072, and RSA-4096 share this contract. RSA-1024 is retained only
// for legacy compatibility. The adapter must establish support for the chosen
// algorithm, firmware, and slot. SignRSA does not verify a PIN or authorize use.
// The supplied public key is validated for its parameters, but the returned
// signature is not cryptographically verified against it. Call VerifyRSA or a
// trusted higher-layer verifier before accepting the result. A response error
// can occur after the private operation; callers must not automatically retry it.
// An incorrect signature width wraps ErrInvalidSignatureResponse.
// Existing Sign callers can migrate by choosing digest or exact-payload options
// explicitly; Sign and RSASignHashNone retain their original behavior.
func (c *Client) SignRSA(algorithm byte, slot Slot, publicKey *rsa.PublicKey, input []byte, options RSASignOptions) ([]byte, error) {
	return c.signRSAWithRandom(algorithm, slot, publicKey, input, options, rand.Reader)
}

// The random source is private so production callers cannot supply fixed salts.
func (c *Client) signRSAWithRandom(algorithm byte, slot Slot, publicKey *rsa.PublicKey, input []byte, options RSASignOptions, random io.Reader) ([]byte, error) {
	resolved, err := validateRSARequest(algorithm, publicKey, input, options)
	if err != nil {
		return nil, err
	}
	if c == nil || c.card == nil {
		return nil, fmt.Errorf("%w: client card is required", ErrInvalidRSAParameters)
	}
	var encoded []byte
	if resolved.pss {
		salt := make([]byte, resolved.saltLength)
		if len(salt) != 0 {
			if random == nil {
				return nil, fmt.Errorf("piv: RSA PSS randomness: reader is nil")
			}
			if _, err := io.ReadFull(random, salt); err != nil {
				return nil, fmt.Errorf("piv: RSA PSS randomness: %w", err)
			}
		}
		encoded, err = rsascheme.EncodePSS(input, publicKey.N.BitLen()-1, salt, resolved.hash.New())
		if err == nil && len(encoded) < publicKey.Size() {
			encoded = new(big.Int).SetBytes(encoded).FillBytes(make([]byte, publicKey.Size()))
		}
	} else {
		encoded, err = rsascheme.EncodePKCS1v15(publicKey.Size(), resolved.hash, input)
	}
	if err != nil {
		return nil, fmt.Errorf("piv: encode RSA signing input: %w", err)
	}
	signature, err := c.Authenticate(algorithm, slot, encoded)
	if err != nil {
		return nil, fmt.Errorf("piv: sign RSA with slot %s: %w", slot, err)
	}
	if len(signature) != publicKey.Size() {
		return nil, fmt.Errorf("%w: RSA slot %s: signature length %d, want %d", ErrInvalidSignatureResponse, slot, len(signature), publicKey.Size())
	}
	return signature, nil
}

// VerifyRSA verifies a signature off-card using exactly the signing options.
// In particular, PSS verification requires the requested salt length, including
// zero; it never autodetects salt or substitutes an MGF hash. Signature mismatch
// errors wrap crypto/rsa.ErrVerification. Invalid requests use the same parameter
// errors as ValidateRSASignRequest. The public modulus may be non-byte-aligned;
// the card signing API still requires its algorithm's exact supported modulus size.
func VerifyRSA(publicKey *rsa.PublicKey, input, signature []byte, options RSASignOptions) error {
	if err := validateRSAPublicKey(publicKey); err != nil {
		return err
	}
	resolved, err := resolveRSAOptions(publicKey, input, options)
	if err != nil {
		return err
	}
	if len(signature) != publicKey.Size() {
		return fmt.Errorf("piv: verify RSA signature length: %w", rsa.ErrVerification)
	}
	s := new(big.Int).SetBytes(signature)
	if s.Cmp(publicKey.N) >= 0 {
		return fmt.Errorf("piv: verify RSA signature representative: %w", rsa.ErrVerification)
	}
	m := new(big.Int).Exp(s, big.NewInt(int64(publicKey.E)), publicKey.N)
	if resolved.pss {
		emBits := publicKey.N.BitLen() - 1
		emLen := (emBits + 7) / 8
		if m.BitLen() > emLen*8 {
			return fmt.Errorf("piv: verify RSA PSS representative: %w", rsa.ErrVerification)
		}
		em := m.FillBytes(make([]byte, emLen))
		if err := rsascheme.VerifyPSS(input, em, emBits, resolved.saltLength, resolved.hash.New()); err != nil {
			return fmt.Errorf("piv: verify RSA PSS: %w", err)
		}
		return nil
	}
	em := m.FillBytes(make([]byte, publicKey.Size()))
	want, err := rsascheme.EncodePKCS1v15(publicKey.Size(), resolved.hash, input)
	if err != nil {
		return err
	}
	if !bytes.Equal(em, want) {
		return fmt.Errorf("piv: verify RSA PKCS#1 v1.5: %w", rsa.ErrVerification)
	}
	return nil
}

type resolvedRSAOptions struct {
	hash       crypto.Hash
	pss        bool
	saltLength int
}

func resolveRSAOptions(publicKey *rsa.PublicKey, input []byte, options RSASignOptions) (resolvedRSAOptions, error) {
	var result resolvedRSAOptions
	switch value := options.(type) {
	case nil:
		return result, fmt.Errorf("%w: explicit scheme options are required", ErrInvalidRSAParameters)
	case RSAPKCS1v15DigestOptions:
		result.hash = value.Hash
	case *RSAPKCS1v15DigestOptions:
		if value == nil {
			return result, fmt.Errorf("%w: nil digest options", ErrInvalidRSAParameters)
		}
		result.hash = value.Hash
	case RSAPKCS1v15PayloadOptions:
		return result, validateRSAPayload(publicKey.Size(), input)
	case *RSAPKCS1v15PayloadOptions:
		if value == nil {
			return result, fmt.Errorf("%w: nil payload options", ErrInvalidRSAParameters)
		}
		return result, validateRSAPayload(publicKey.Size(), input)
	case RSAPSSOptions:
		return resolveRSAPSS(publicKey, input, value)
	case *RSAPSSOptions:
		if value == nil {
			return result, fmt.Errorf("%w: nil PSS options", ErrInvalidRSAParameters)
		}
		return resolveRSAPSS(publicKey, input, *value)
	default:
		return result, fmt.Errorf("%w: explicit scheme options are required", ErrUnsupportedRSAOptions)
	}
	if err := validateRSADigest(result.hash, input); err != nil {
		return result, err
	}
	if _, err := rsascheme.EncodePKCS1v15(publicKey.Size(), result.hash, input); err != nil {
		return result, fmt.Errorf("%w: %w", ErrInvalidRSAParameters, err)
	}
	return result, nil
}

func resolveRSAPSS(publicKey *rsa.PublicKey, input []byte, options RSAPSSOptions) (resolvedRSAOptions, error) {
	result := resolvedRSAOptions{hash: options.Hash, pss: true, saltLength: options.SaltLength}
	if err := validateRSADigest(options.Hash, input); err != nil {
		return result, err
	}
	if options.MGF1Hash != options.Hash {
		return result, fmt.Errorf("%w: MGF1 hash must explicitly equal the digest hash", ErrUnsupportedRSAOptions)
	}
	emLen := (publicKey.N.BitLen() - 1 + 7) / 8
	maxSalt := emLen - options.Hash.Size() - 2
	if options.SaltLength < 0 || options.SaltLength > maxSalt {
		return result, fmt.Errorf("%w: salt length %d is outside 0..%d", ErrInvalidRSAParameters, options.SaltLength, maxSalt)
	}
	return result, nil
}

func validateRSADigest(hash crypto.Hash, input []byte) error {
	switch hash {
	case crypto.SHA256, crypto.SHA384, crypto.SHA512:
	default:
		return fmt.Errorf("%w: hash %d; use SHA-256, SHA-384, or SHA-512", ErrUnsupportedRSAOptions, hash)
	}
	if len(input) != hash.Size() {
		return fmt.Errorf("%w: %s digest has %d bytes, want %d", ErrInvalidRSAParameters, hash, len(input), hash.Size())
	}
	return nil
}

func validateRSAPayload(k int, input []byte) error {
	if len(input) > k-11 {
		return fmt.Errorf("%w: %w (payload length %d, maximum %d)", ErrInvalidRSAParameters, rsa.ErrMessageTooLong, len(input), k-11)
	}
	return nil
}

func validateRSAPublicKey(publicKey *rsa.PublicKey) error {
	if publicKey == nil || publicKey.N == nil || publicKey.N.Sign() <= 0 {
		return fmt.Errorf("%w: a positive RSA modulus is required", ErrInvalidRSAParameters)
	}
	if bits := publicKey.N.BitLen(); bits < 1024 || bits > 4096 || publicKey.N.Bit(0) == 0 {
		return fmt.Errorf("%w: RSA modulus must be odd and between 1024 and 4096 bits", ErrInvalidRSAParameters)
	}
	if publicKey.E < 3 || publicKey.E > 1<<31-1 || publicKey.E%2 == 0 {
		return fmt.Errorf("%w: RSA exponent must be odd and between 3 and 2^31-1", ErrInvalidRSAParameters)
	}
	return nil
}
