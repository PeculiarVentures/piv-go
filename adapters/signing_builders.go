package adapters

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"errors"
	"fmt"

	"github.com/PeculiarVentures/piv-go/piv"
)

// ErrInvalidSigningKey identifies a malformed, unsupported or contradictory
// public-key description. It does not report whether a private key is present.
var ErrInvalidSigningKey = errors.New("adapters: invalid signing key")

// SigningKeyFromPublicKey describes exact supported public-key parameters
// without contacting a device. It accepts RSA-1024/2048/3072/4096, canonical
// NIST P-256/P-384/P-521, Ed25519 and explicitly tagged ML-DSA keys. P-521
// description is public preparation only; it does not add a native adapter.
// Unknown curves and unlabelled opaque keys are never inferred from bit size
// or byte length. Agreement/KEM keys are not signing keys.
func SigningKeyFromPublicKey(publicKey crypto.PublicKey) (SigningKey, error) {
	invalid := func(detail string) (SigningKey, error) {
		return SigningKey{}, fmt.Errorf("%w: %s", ErrInvalidSigningKey, detail)
	}
	switch key := publicKey.(type) {
	case *rsa.PublicKey:
		if key == nil || key.N == nil || key.N.Sign() <= 0 || key.N.Bit(0) == 0 || key.E < 3 || key.E > 1<<31-1 || key.E%2 == 0 {
			return invalid("a positive odd RSA modulus and valid odd exponent are required")
		}
		bits := key.N.BitLen()
		switch bits {
		case 1024, 2048, 3072, 4096:
			return SigningKey{Family: SigningKeyRSA, RSABits: bits}, nil
		default:
			return invalid(fmt.Sprintf("unsupported exact RSA modulus size %d", bits))
		}
	case *ecdsa.PublicKey:
		if key == nil || key.Curve == nil || key.X == nil || key.Y == nil {
			return invalid("a complete ECDSA public point is required")
		}
		var oid string
		switch key.Curve {
		case elliptic.P256():
			oid = SigningCurveP256
		case elliptic.P384():
			oid = SigningCurveP384
		case elliptic.P521():
			oid = SigningCurveP521
		default:
			return invalid("unsupported exact ECDSA named curve")
		}
		if !key.Curve.IsOnCurve(key.X, key.Y) {
			return invalid("ECDSA public point is not on its named curve")
		}
		return SigningKey{Family: SigningKeyEC, CurveOID: oid}, nil
	case ed25519.PublicKey:
		if len(key) != ed25519.PublicKeySize {
			return invalid("Ed25519 public key must contain 32 bytes")
		}
		return SigningKey{Family: SigningKeyEdDSA, CurveOID: SigningCurveEd25519}, nil
	case *piv.OpaquePublicKey:
		if key == nil {
			return invalid("opaque public key is nil")
		}
		return signingKeyFromOpaque(*key)
	case piv.OpaquePublicKey:
		return signingKeyFromOpaque(key)
	default:
		return invalid(fmt.Sprintf("unsupported public key type %T", publicKey))
	}
}

func signingKeyFromOpaque(key piv.OpaquePublicKey) (SigningKey, error) {
	invalid := func(detail string) (SigningKey, error) {
		return SigningKey{}, fmt.Errorf("%w: %s", ErrInvalidSigningKey, detail)
	}
	if key.Algorithm == piv.AlgEd25519 {
		if len(key.Raw) != ed25519.PublicKeySize {
			return invalid("Ed25519 public key must contain 32 bytes")
		}
		return SigningKey{Family: SigningKeyEdDSA, CurveOID: SigningCurveEd25519}, nil
	}
	if size, ok := piv.MLDSAPublicKeyLength(key.Algorithm); ok {
		if len(key.Raw) != size {
			return invalid(fmt.Sprintf("ML-DSA public key length %d does not match algorithm 0x%02X", len(key.Raw), key.Algorithm))
		}
		parameterSet := 0
		switch key.Algorithm {
		case piv.AlgMLDSA44:
			parameterSet = 44
		case piv.AlgMLDSA65:
			parameterSet = 65
		case piv.AlgMLDSA87:
			parameterSet = 87
		}
		return SigningKey{Family: SigningKeyMLDSA, MLDSAParameterSet: parameterSet}, nil
	}
	return invalid(fmt.Sprintf("opaque algorithm 0x%02X does not identify an implemented signing key", key.Algorithm))
}

// SigningKeyEvidenceFromSlot converts a passive slot observation without I/O.
// current is the caller's explicit freshness decision; this helper never
// refreshes evidence or proves private-key presence. Unknown/absent/error
// states and public-key provenance are retained. A certificate or stored
// template is never promoted to metadata. PIN/touch observations remain inputs
// to application policy, not authorization granted by the signing matcher.
func SigningKeyEvidenceFromSlot(slot piv.Slot, description SlotDescription, current bool) (SigningKeyEvidence, error) {
	evidence := SigningKeyEvidence{
		Slot: slot, State: description.KeyState, Current: current, Source: description.PublicKeySource,
		PINPolicy: PINPolicyUnknown, TouchPolicy: TouchPolicyUnknown,
	}
	if description.KeyError != nil {
		evidence.State = SlotStateError
	}
	if metadata := description.Metadata; metadata != nil {
		evidence.PINPolicy, evidence.TouchPolicy = metadata.PINPolicy, metadata.TouchPolicy
		if evidence.PINPolicy == "" {
			evidence.PINPolicy = PINPolicyUnknown
		}
		if evidence.TouchPolicy == "" {
			evidence.TouchPolicy = TouchPolicyUnknown
		}
		if metadata.Slot != 0 && metadata.Slot != slot {
			evidence.State = SlotStateError
			return evidence, fmt.Errorf("%w: metadata for slot %s cannot describe slot %s", ErrInvalidSigningKey, metadata.Slot, slot)
		}
	}
	if description.PublicKey == nil {
		return evidence, nil
	}
	key, err := SigningKeyFromPublicKey(description.PublicKey)
	if err != nil {
		evidence.State = SlotStateError
		return evidence, err
	}
	evidence.Key = key
	if metadata := description.Metadata; metadata != nil && metadata.Algorithm != "" && metadata.Algorithm != KeyAlgorithmUnknown {
		expected, ok := signingKeyFromMetadataAlgorithm(metadata.Algorithm)
		if !ok || expected != key {
			evidence.State = SlotStateError
			return evidence, fmt.Errorf("%w: metadata algorithm %q does not match the public key", ErrInvalidSigningKey, metadata.Algorithm)
		}
	}
	return evidence, nil
}

func signingKeyFromMetadataAlgorithm(algorithm KeyAlgorithm) (SigningKey, bool) {
	switch algorithm {
	case KeyAlgorithmRSA1024:
		return SigningKey{Family: SigningKeyRSA, RSABits: 1024}, true
	case KeyAlgorithmRSA2048:
		return SigningKey{Family: SigningKeyRSA, RSABits: 2048}, true
	case KeyAlgorithmRSA3072:
		return SigningKey{Family: SigningKeyRSA, RSABits: 3072}, true
	case KeyAlgorithmRSA4096:
		return SigningKey{Family: SigningKeyRSA, RSABits: 4096}, true
	case KeyAlgorithmECCP256:
		return SigningKey{Family: SigningKeyEC, CurveOID: SigningCurveP256}, true
	case KeyAlgorithmECCP384:
		return SigningKey{Family: SigningKeyEC, CurveOID: SigningCurveP384}, true
	case KeyAlgorithmEd25519:
		return SigningKey{Family: SigningKeyEdDSA, CurveOID: SigningCurveEd25519}, true
	case KeyAlgorithmMLDSA44:
		return SigningKey{Family: SigningKeyMLDSA, MLDSAParameterSet: 44}, true
	case KeyAlgorithmMLDSA65:
		return SigningKey{Family: SigningKeyMLDSA, MLDSAParameterSet: 65}, true
	case KeyAlgorithmMLDSA87:
		return SigningKey{Family: SigningKeyMLDSA, MLDSAParameterSet: 87}, true
	default:
		return SigningKey{}, false
	}
}

// SigningRequestFromRSAOptions validates and describes one concrete SignRSA
// request entirely off-card. It fills the RSA context/input defaults and keeps
// exact hash, MGF1 and salt semantics. Randomness remains empty because options
// select the operation, not an additional randomness requirement. A consumer
// must still match device/key capabilities and apply its authorization policy.
func SigningRequestFromRSAOptions(algorithm byte, publicKey *rsa.PublicKey, input []byte, options piv.RSASignOptions) (SigningRequest, error) {
	if err := piv.ValidateRSASignRequest(algorithm, publicKey, input, options); err != nil {
		return SigningRequest{}, err
	}
	request := SigningRequest{InputLength: len(input), Parameters: SigningParameters{Context: SigningContextAbsent}}
	switch value := options.(type) {
	case piv.RSAPKCS1v15DigestOptions:
		request.Parameters.Scheme, request.Parameters.Input, request.Parameters.Hash = SigningRSAPKCS1v15Digest, SigningInputDigest, value.Hash
	case *piv.RSAPKCS1v15DigestOptions:
		request.Parameters.Scheme, request.Parameters.Input, request.Parameters.Hash = SigningRSAPKCS1v15Digest, SigningInputDigest, value.Hash
	case piv.RSAPKCS1v15PayloadOptions, *piv.RSAPKCS1v15PayloadOptions:
		request.Parameters.Scheme, request.Parameters.Input = SigningRSAPKCS1v15Payload, SigningInputPayload
	case piv.RSAPSSOptions:
		request.Parameters.Scheme, request.Parameters.Input = SigningRSAPSS, SigningInputDigest
		request.Parameters.Hash, request.Parameters.MGF1Hash, request.SaltLength = value.Hash, value.MGF1Hash, value.SaltLength
	case *piv.RSAPSSOptions:
		request.Parameters.Scheme, request.Parameters.Input = SigningRSAPSS, SigningInputDigest
		request.Parameters.Hash, request.Parameters.MGF1Hash, request.SaltLength = value.Hash, value.MGF1Hash, value.SaltLength
	default:
		return SigningRequest{}, fmt.Errorf("%w: unrecognized RSA options", piv.ErrUnsupportedRSAOptions)
	}
	return request, nil
}
