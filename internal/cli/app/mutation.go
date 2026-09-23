package app

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/PeculiarVentures/piv-go/adapters"
	adaptersadmin "github.com/PeculiarVentures/piv-go/adapters/admin"
	"github.com/PeculiarVentures/piv-go/piv"
)

// CertImportRequest configures piv cert import.
type CertImportRequest struct {
	Global GlobalOptions
	Slot   piv.Slot
	Path   string
	// Raw opts into raw certificate bytes without X.509 validation for
	// post-quantum (ML-DSA) slot certificates. X25519 slots reject even in
	// raw mode: they have no X.509 profile.
	Raw bool
	// ManagementKey authenticates the certificate write on tokens whose
	// adapter requires it (YubiKey, SafeNet). Standard tokens skip it.
	ManagementKey SecretRequest
}

// DeleteRequest configures destructive delete flows.
type DeleteRequest struct {
	Global GlobalOptions
	Slot   piv.Slot
	Yes    bool
	DryRun bool
	// ManagementKey authenticates certificate deletion on tokens whose
	// adapter requires it (YubiKey, SafeNet). Key deletion keeps its own
	// separate credential parameter and ignores this field.
	ManagementKey SecretRequest
}

// KeyGenerateRequest configures piv key generate.
type KeyGenerateRequest struct {
	Global        GlobalOptions
	Slot          piv.Slot
	Algorithm     byte
	AlgorithmName string
	PinPolicy     byte
	TouchPolicy   byte
	ManagementKey SecretRequest
	DryRun        bool
}

// KeyImportRequest configures piv key import.
type KeyImportRequest struct {
	Global        GlobalOptions
	Slot          piv.Slot
	Algorithm     byte
	AlgorithmName string
	Path          string
	PinPolicy     byte
	TouchPolicy   byte
	ManagementKey SecretRequest
	DryRun        bool
}

// SignRequest configures piv key sign.
type SignRequest struct {
	Global    GlobalOptions
	Slot      piv.Slot
	InputPath string
	Hash      string
	Encoding  string
	Out       string
	PIN       SecretRequest
	UsePIN    bool
}

// ChallengeRequest configures piv key challenge.
type ChallengeRequest struct {
	Global       GlobalOptions
	Slot         piv.Slot
	ChallengeHex string
	Encoding     string
	Out          string
	PIN          SecretRequest
	UsePIN       bool
}

// PINVerifyRequest configures piv pin verify.
type PINVerifyRequest struct {
	Global GlobalOptions
	PIN    SecretRequest
}

// PINChangeRequest configures piv pin change.
type PINChangeRequest struct {
	Global GlobalOptions
	OldPIN SecretRequest
	NewPIN SecretRequest
}

// PINUnblockRequest configures piv pin unblock.
type PINUnblockRequest struct {
	Global GlobalOptions
	PUK    SecretRequest
	NewPIN SecretRequest
}

// PUKChangeRequest configures piv puk change.
type PUKChangeRequest struct {
	Global GlobalOptions
	OldPUK SecretRequest
	NewPUK SecretRequest
}

// MGMVerifyRequest configures piv mgm verify.
type MGMVerifyRequest struct {
	Global        GlobalOptions
	Key           SecretRequest
	Algorithm     byte
	AlgorithmName string
}

// MGMRotateRequest configures piv mgm rotate.
type MGMRotateRequest struct {
	Global           GlobalOptions
	CurrentKey       SecretRequest
	NewKey           SecretRequest
	Algorithm        byte
	AlgorithmName    string
	NewAlgorithm     byte
	NewAlgorithmName string
	RequireTouch     bool
	Yes              bool
	DryRun           bool
}

// SetupInitRequest configures piv setup init.
type SetupInitRequest struct {
	Global        GlobalOptions
	ManagementKey SecretRequest
	Yes           bool
	DryRun        bool
}

// SetupResetRequest configures piv setup reset.
type SetupResetRequest struct {
	Global        GlobalOptions
	ManagementKey SecretRequest
	PUK           SecretRequest
	Yes           bool
	DryRun        bool
}

// SetupResetSlotRequest configures piv setup reset-slot.
type SetupResetSlotRequest struct {
	Global        GlobalOptions
	ManagementKey SecretRequest
	Slot          piv.Slot
	Yes           bool
	DryRun        bool
}

// MutationService orchestrates mutating token workflows.
type MutationService struct {
	targets *TargetResolver
	planner *OperationPlanner
	input   io.Reader
	stderr  io.Writer
}

// NewMutationService creates a mutation service.
func NewMutationService(targets *TargetResolver, planner *OperationPlanner, input io.Reader, stderr io.Writer) *MutationService {
	return &MutationService{targets: targets, planner: planner, input: input, stderr: stderr}
}

// CertImport installs a certificate into a slot. Strict X.509 parsing is the
// default; pass Raw for post-quantum (ML-DSA) certificates without a strict
// profile. X25519 slots reject with "no X.509 profile" and ML-DSA slots
// without Raw reject with "post-quantum certificate requires --raw".
func (s *MutationService) CertImport(ctx context.Context, request CertImportRequest) (Response, error) {
	if err := rejectAttestationSlot(request.Slot); err != nil {
		return Response{}, err
	}
	inputData, err := ReadInputFile(request.Path, s.input)
	if err != nil {
		return Response{}, err
	}
	target, err := s.targets.Resolve(ctx, request.Global)
	if err != nil {
		return Response{}, err
	}
	defer func() { _ = target.Close() }()

	if algorithm, ok := bestEffortSlotAlgorithm(target.Runtime, request.Slot); ok {
		if algorithm == piv.AlgX25519 {
			return Response{}, UnsupportedError("x25519 certificate import is not supported: no X.509 profile", "use a slot backed by rsa, ecdsa, ed25519, or ml-dsa")
		}
		if piv.IsMLKEMAlgorithm(algorithm) {
			return Response{}, UnsupportedError(fmt.Sprintf("certificate import for algorithm %s is not supported by this release", AlgorithmName(algorithm)), "inspect capabilities with piv info")
		}
		if piv.IsMLDSAAlgorithm(algorithm) && !request.Raw {
			return Response{}, UnsupportedError("post-quantum certificate requires --raw: ml-dsa certificates have no strict X.509 profile", "rerun with --raw-cert to store raw certificate bytes")
		}
	}
	var certData []byte
	if request.Raw {
		if algorithm, ok := bestEffortSlotAlgorithm(target.Runtime, request.Slot); ok && algorithm == piv.AlgX25519 {
			return Response{}, UnsupportedError("x25519 certificate import is not supported: no X.509 profile", "use a slot backed by rsa, ecdsa, ed25519, or ml-dsa")
		}
		certData, err = ParseCertificateDataRaw(inputData)
	} else {
		certData, err = ParseCertificateData(inputData)
	}
	if err != nil {
		return Response{}, err
	}

	if installed, readErr := readCertificate(target.Runtime, request.Slot); readErr == nil && bytes.Equal(installed, certData) {
		response := Response{
			Command: "cert-import",
			Target:  target.Summary,
			Result:  MutationResult{Action: "cert-import", Changed: false, Notes: []string{"certificate already matches slot contents"}},
		}
		response.traceLines = target.TraceLines()
		return response, nil
	}
	if err := s.authenticateForCertificateWrite(target.Runtime, request.Global, request.ManagementKey); err != nil {
		return Response{}, err
	}
	if err := writeCertificate(target.Runtime, request.Slot, certData); err != nil {
		return Response{}, err
	}
	response := Response{
		Command: "cert-import",
		Target:  target.Summary,
		Result:  MutationResult{Action: "cert-import", Changed: true, Notes: []string{fmt.Sprintf("installed certificate into slot %s", SlotName(request.Slot))}},
	}
	response.traceLines = target.TraceLines()
	return response, nil
}

// CertDelete deletes a certificate from a slot.
func (s *MutationService) CertDelete(ctx context.Context, request DeleteRequest) (Response, error) {
	if err := rejectAttestationSlot(request.Slot); err != nil {
		return Response{}, err
	}
	target, err := s.targets.Resolve(ctx, request.Global)
	if err != nil {
		return Response{}, err
	}
	defer func() { _ = target.Close() }()

	slotView, err := describeSlot(target.Runtime, request.Slot)
	if err != nil {
		return Response{}, err
	}
	plan := s.planner.Build(
		fmt.Sprintf("delete certificate from slot %s", SlotName(request.Slot)),
		nil,
		[]string{fmt.Sprintf("remove the certificate stored in slot %s", SlotName(request.Slot))},
		nil,
	)
	if !slotView.CertPresent {
		response := Response{Command: "cert-delete", Target: target.Summary, Result: MutationResult{Action: "cert-delete", Changed: false, Notes: []string{"certificate is already absent"}}}
		response.traceLines = target.TraceLines()
		return response, nil
	}
	if request.DryRun {
		response := Response{Command: "cert-delete", Target: target.Summary, Result: MutationResult{Action: "cert-delete", DryRun: true, Plan: plan}}
		response.traceLines = target.TraceLines()
		return response, nil
	}
	if err := s.planner.Confirm(plan, request.Global.NonInteractive, request.Yes); err != nil {
		return Response{}, err
	}
	if err := s.authenticateForCertificateWrite(target.Runtime, request.Global, request.ManagementKey); err != nil {
		return Response{}, err
	}
	if err := clearCertificate(target.Runtime, request.Slot); err != nil {
		return Response{}, err
	}
	response := Response{Command: "cert-delete", Target: target.Summary, Result: MutationResult{Action: "cert-delete", Changed: true}}
	response.traceLines = target.TraceLines()
	return response, nil
}

// KeyGenerate generates a new slot key, including ML-KEM decapsulation keys
// on YubiKey 6 tokens (firmware 6.0+).
func (s *MutationService) KeyGenerate(ctx context.Context, request KeyGenerateRequest) (Response, error) {
	if err := rejectAttestationSlot(request.Slot); err != nil {
		return Response{}, err
	}
	resolver := s.resolver(request.Global)
	target, err := s.targets.Resolve(ctx, request.Global)
	if err != nil {
		return Response{}, err
	}
	defer func() { _ = target.Close() }()

	algorithmName, err := s.setManagementCredentials(target.Runtime, resolver, request.ManagementKey, 0)
	if err != nil {
		return Response{}, err
	}
	plan := s.planner.Build(
		fmt.Sprintf("generate a %s key in slot %s", request.AlgorithmName, SlotName(request.Slot)),
		[]string{fmt.Sprintf("management key (%s)", algorithmName)},
		[]string{fmt.Sprintf("replace the key material in slot %s", SlotName(request.Slot))},
		nil,
	)
	if request.DryRun {
		response := Response{Command: "key-generate", Target: target.Summary, Result: MutationResult{Action: "key-generate", DryRun: true, Plan: plan, Algorithm: request.AlgorithmName}}
		response.traceLines = target.TraceLines()
		return response, nil
	}
	if err := target.Runtime.AuthenticateManagementKey(); err != nil {
		return Response{}, err
	}
	if _, err := generateKeyPairWithPolicies(target.Runtime, request.Slot, request.Algorithm, request.PinPolicy, request.TouchPolicy); err != nil {
		return Response{}, err
	}
	response := Response{Command: "key-generate", Target: target.Summary, Result: MutationResult{Action: "key-generate", Changed: true, Algorithm: request.AlgorithmName}}
	response.traceLines = target.TraceLines()
	return response, nil
}

// KeyImport imports a private key into a slot. RSA-1024/2048/3072/4096,
// ECCP-256/384, Ed25519, X25519, and ML-KEM-768/1024 are implemented;
// Ed25519/X25519 accept PKCS #8 or a raw 32-byte seed (binary, hex, or
// base64) via --in, while ML-KEM accepts the raw 64-byte seed (binary, hex,
// or base64) via --in. ML-KEM-512 import stays unsupported (no standard
// library implementation to derive the stored encapsulation key) and
// ML-DSA has no import APDU; both gap-reject without sending a command.
func (s *MutationService) KeyImport(ctx context.Context, request KeyImportRequest) (Response, error) {
	if err := rejectAttestationSlot(request.Slot); err != nil {
		return Response{}, err
	}
	if piv.IsMLDSAAlgorithm(request.Algorithm) {
		return Response{}, UnsupportedError(fmt.Sprintf("key import for algorithm %s is not supported by this release", request.AlgorithmName), "use rsa, ecdsa, ed25519, x25519, or ml-kem; ml-dsa has no import flow")
	}
	switch request.Algorithm {
	case piv.AlgRSA1024, piv.AlgRSA2048, piv.AlgRSA3072, piv.AlgRSA4096,
		piv.AlgECCP256, piv.AlgECCP384,
		piv.AlgEd25519, piv.AlgX25519,
		piv.AlgMLKEM512, piv.AlgMLKEM768, piv.AlgMLKEM1024:
	default:
		return Response{}, UsageError(fmt.Sprintf("unsupported import algorithm %q", request.AlgorithmName), "use p256, p384, rsa1024, rsa2048, rsa3072, rsa4096, ed25519, x25519, mlkem512, mlkem768, or mlkem1024")
	}
	inputData, err := ReadInputFile(request.Path, s.input)
	if err != nil {
		return Response{}, err
	}
	privateKey, err := ParsePrivateKeyForAlgorithm(inputData, request.Algorithm)
	if err != nil {
		return Response{}, err
	}
	if err := checkImportKeyMatch(request.Algorithm, privateKey); err != nil {
		return Response{}, err
	}
	resolver := s.resolver(request.Global)
	target, err := s.targets.Resolve(ctx, request.Global)
	if err != nil {
		return Response{}, err
	}
	defer func() { _ = target.Close() }()

	algorithmName, err := s.setManagementCredentials(target.Runtime, resolver, request.ManagementKey, 0)
	if err != nil {
		return Response{}, err
	}
	plan := s.planner.Build(
		fmt.Sprintf("import a %s key into slot %s", request.AlgorithmName, SlotName(request.Slot)),
		[]string{fmt.Sprintf("management key (%s)", algorithmName)},
		[]string{fmt.Sprintf("replace the key material in slot %s", SlotName(request.Slot))},
		nil,
	)
	if request.DryRun {
		response := Response{Command: "key-import", Target: target.Summary, Result: MutationResult{Action: "key-import", DryRun: true, Plan: plan, Algorithm: request.AlgorithmName}}
		response.traceLines = target.TraceLines()
		return response, nil
	}
	if err := target.Runtime.AuthenticateManagementKey(); err != nil {
		return Response{}, err
	}
	if err := importKeyPair(target.Runtime, request.Slot, request.Algorithm, privateKey, request.PinPolicy, request.TouchPolicy); err != nil {
		return Response{}, err
	}
	response := Response{Command: "key-import", Target: target.Summary, Result: MutationResult{Action: "key-import", Changed: true, Algorithm: request.AlgorithmName}}
	response.traceLines = target.TraceLines()
	return response, nil
}

func checkImportKeyMatch(algorithm byte, privateKey crypto.PrivateKey) error {
	switch algorithm {
	case piv.AlgECCP256:
		key, ok := privateKey.(*ecdsa.PrivateKey)
		if !ok {
			return UsageError(fmt.Sprintf("import key type mismatch: p256 requires an EC private key, got %T", privateKey), "provide a P-256 private key for --alg p256")
		}
		if key.Curve.Params().BitSize != 256 {
			return UsageError("import key type mismatch: p256 requires a P-256 private key", "provide a P-256 private key for --alg p256")
		}
		return nil
	case piv.AlgECCP384:
		key, ok := privateKey.(*ecdsa.PrivateKey)
		if !ok {
			return UsageError(fmt.Sprintf("import key type mismatch: p384 requires an EC private key, got %T", privateKey), "provide a P-384 private key for --alg p384")
		}
		if key.Curve.Params().BitSize != 384 {
			return UsageError("import key type mismatch: p384 requires a P-384 private key", "provide a P-384 private key for --alg p384")
		}
		return nil
	case piv.AlgRSA1024, piv.AlgRSA2048, piv.AlgRSA3072, piv.AlgRSA4096:
		key, ok := privateKey.(*rsa.PrivateKey)
		if !ok {
			return UsageError(fmt.Sprintf("import key type mismatch: %s requires an RSA private key, got %T", AlgorithmName(algorithm), privateKey), fmt.Sprintf("provide an RSA private key for --alg %s", AlgorithmName(algorithm)))
		}
		wantBits := map[byte]int{piv.AlgRSA1024: 1024, piv.AlgRSA2048: 2048, piv.AlgRSA3072: 3072, piv.AlgRSA4096: 4096}[algorithm]
		if key.N.BitLen() != wantBits {
			return UsageError(fmt.Sprintf("import key type mismatch: %s requires a %d-bit key, got %d bits", AlgorithmName(algorithm), wantBits, key.N.BitLen()), fmt.Sprintf("provide an RSA-%d private key for --alg %s", wantBits, AlgorithmName(algorithm)))
		}
		return nil
	case piv.AlgEd25519:
		switch key := privateKey.(type) {
		case ed25519.PrivateKey:
			if len(key) != ed25519.PrivateKeySize {
				return UsageError(fmt.Sprintf("import key type mismatch: ed25519 requires a %d-byte private key, got %d bytes", ed25519.PrivateKeySize, len(key)), "provide an Ed25519 private key for --alg ed25519")
			}
			return nil
		case *piv.OpaquePrivateKey:
			if key == nil || len(key.Raw) != 32 {
				return UsageError("import key type mismatch: ed25519 requires a 32-byte raw seed", "provide a raw 32-byte seed (binary, hex, or base64) for --alg ed25519")
			}
			return nil
		case piv.OpaquePrivateKey:
			if len(key.Raw) != 32 {
				return UsageError("import key type mismatch: ed25519 requires a 32-byte raw seed", "provide a raw 32-byte seed (binary, hex, or base64) for --alg ed25519")
			}
			return nil
		case []byte:
			if len(key) != 32 {
				return UsageError("import key type mismatch: ed25519 requires a 32-byte raw seed", "provide a raw 32-byte seed (binary, hex, or base64) for --alg ed25519")
			}
			return nil
		default:
			return UsageError(fmt.Sprintf("import key type mismatch: ed25519 requires an Ed25519 private key, got %T", privateKey), "provide an Ed25519 private key for --alg ed25519")
		}
	case piv.AlgX25519:
		switch key := privateKey.(type) {
		case *ecdh.PrivateKey:
			if key.Curve() != ecdh.X25519() {
				return UsageError("import key type mismatch: x25519 requires an X25519 private key", "provide an X25519 private key for --alg x25519")
			}
			return nil
		case *piv.OpaquePrivateKey:
			if key == nil || len(key.Raw) != 32 {
				return UsageError("import key type mismatch: x25519 requires a 32-byte raw seed", "provide a raw 32-byte seed (binary, hex, or base64) for --alg x25519")
			}
			return nil
		case piv.OpaquePrivateKey:
			if len(key.Raw) != 32 {
				return UsageError("import key type mismatch: x25519 requires a 32-byte raw seed", "provide a raw 32-byte seed (binary, hex, or base64) for --alg x25519")
			}
			return nil
		case []byte:
			if len(key) != 32 {
				return UsageError("import key type mismatch: x25519 requires a 32-byte raw seed", "provide a raw 32-byte seed (binary, hex, or base64) for --alg x25519")
			}
			return nil
		default:
			return UsageError(fmt.Sprintf("import key type mismatch: x25519 requires an X25519 private key, got %T", privateKey), "provide an X25519 private key for --alg x25519")
		}
	case piv.AlgMLKEM512, piv.AlgMLKEM768, piv.AlgMLKEM1024:
		if algorithm == piv.AlgMLKEM512 {
			// The card accepts ML-KEM-512 seeds, but this release
			// cannot derive the encapsulation key for the stored
			// public key object without a standard library
			// implementation.
			return UnsupportedError(fmt.Sprintf("key import for algorithm %s is not supported by this release", AlgorithmName(algorithm)), "use mlkem768 or mlkem1024 for key import")
		}
		switch key := privateKey.(type) {
		case *piv.OpaquePrivateKey:
			if key == nil || len(key.Raw) != piv.MLKEMSeedLength {
				return UsageError(fmt.Sprintf("import key type mismatch: %s requires a %d-byte seed, got %d bytes", AlgorithmName(algorithm), piv.MLKEMSeedLength, opaqueRawLength(key)), fmt.Sprintf("provide a raw %d-byte seed (binary, hex, or base64) for --alg %s", piv.MLKEMSeedLength, AlgorithmName(algorithm)))
			}
			return nil
		case piv.OpaquePrivateKey:
			if len(key.Raw) != piv.MLKEMSeedLength {
				return UsageError(fmt.Sprintf("import key type mismatch: %s requires a %d-byte seed, got %d bytes", AlgorithmName(algorithm), piv.MLKEMSeedLength, len(key.Raw)), fmt.Sprintf("provide a raw %d-byte seed (binary, hex, or base64) for --alg %s", piv.MLKEMSeedLength, AlgorithmName(algorithm)))
			}
			return nil
		case []byte:
			if len(key) != piv.MLKEMSeedLength {
				return UsageError(fmt.Sprintf("import key type mismatch: %s requires a %d-byte seed, got %d bytes", AlgorithmName(algorithm), piv.MLKEMSeedLength, len(key)), fmt.Sprintf("provide a raw %d-byte seed (binary, hex, or base64) for --alg %s", piv.MLKEMSeedLength, AlgorithmName(algorithm)))
			}
			return nil
		default:
			return UsageError(fmt.Sprintf("import key type mismatch: %s requires an ML-KEM seed, got %T", AlgorithmName(algorithm), privateKey), fmt.Sprintf("provide a raw %d-byte seed (binary, hex, or base64) for --alg %s", piv.MLKEMSeedLength, AlgorithmName(algorithm)))
		}
	default:
		return UsageError("unsupported import algorithm", "use p256, p384, rsa1024, rsa2048, rsa3072, rsa4096, ed25519, x25519, mlkem512, mlkem768, or mlkem1024")
	}
}

func opaqueRawLength(key *piv.OpaquePrivateKey) int {
	if key == nil {
		return 0
	}
	return len(key.Raw)
}

// bestEffortSlotAlgorithm resolves the slot key algorithm without failing
// the caller when the slot is empty or metadata is unavailable.
func bestEffortSlotAlgorithm(runtime *adapters.Runtime, slot piv.Slot) (byte, bool) {
	if runtime == nil {
		return 0, false
	}
	publicKey, err := readPublicKey(runtime, slot)
	if err != nil {
		return 0, false
	}
	algorithm, _, err := InferPublicKeyAlgorithm(publicKey)
	if err != nil {
		return 0, false
	}
	return algorithm, true
}

// KeyDelete deletes a slot key.
func (s *MutationService) KeyDelete(ctx context.Context, request DeleteRequest, managementKey SecretRequest) (Response, error) {
	if err := rejectAttestationSlot(request.Slot); err != nil {
		return Response{}, err
	}
	resolver := s.resolver(request.Global)
	target, err := s.targets.Resolve(ctx, request.Global)
	if err != nil {
		return Response{}, err
	}
	defer func() { _ = target.Close() }()

	slotView, err := describeSlot(target.Runtime, request.Slot)
	if err != nil {
		return Response{}, err
	}
	if !slotView.KeyPresent {
		response := Response{Command: "key-delete", Target: target.Summary, Result: MutationResult{Action: "key-delete", Changed: false, Notes: []string{"key is already absent"}}}
		response.traceLines = target.TraceLines()
		return response, nil
	}
	algorithmName, err := s.setManagementCredentials(target.Runtime, resolver, managementKey, 0)
	if err != nil {
		return Response{}, err
	}
	plan := s.planner.Build(
		fmt.Sprintf("delete key from slot %s", SlotName(request.Slot)),
		[]string{fmt.Sprintf("management key (%s)", algorithmName)},
		[]string{fmt.Sprintf("remove key material from slot %s", SlotName(request.Slot))},
		nil,
	)
	if request.DryRun {
		response := Response{Command: "key-delete", Target: target.Summary, Result: MutationResult{Action: "key-delete", DryRun: true, Plan: plan}}
		response.traceLines = target.TraceLines()
		return response, nil
	}
	if err := s.planner.Confirm(plan, request.Global.NonInteractive, request.Yes); err != nil {
		return Response{}, err
	}
	if err := target.Runtime.AuthenticateManagementKey(); err != nil {
		return Response{}, err
	}
	if err := deleteKeyPair(target.Runtime, request.Slot); err != nil {
		return Response{}, err
	}
	response := Response{Command: "key-delete", Target: target.Summary, Result: MutationResult{Action: "key-delete", Changed: true}}
	response.traceLines = target.TraceLines()
	return response, nil
}

// KeySign signs input data with a slot key. The --hash mode selects both
// the host hashing (hashInput) and the extended-RSA wire format: sha256
// hashes the payload and wraps the digest with DigestInfo, while none
// signs raw with PKCS#1 v1.5 type-1 padding but no DigestInfo (ykman
// _pad_message semantics).
func (s *MutationService) KeySign(ctx context.Context, request SignRequest) (Response, error) {
	if err := rejectAttestationSlot(request.Slot); err != nil {
		return Response{}, err
	}
	resolver := s.resolver(request.Global)
	payload, err := ReadInputFile(request.InputPath, s.input)
	if err != nil {
		return Response{}, err
	}
	payload, err = hashInput(payload, request.Hash)
	if err != nil {
		return Response{}, err
	}
	hashMode, err := signHashMode(request.Hash)
	if err != nil {
		return Response{}, err
	}
	target, err := s.targets.Resolve(ctx, request.Global)
	if err != nil {
		return Response{}, err
	}
	defer func() { _ = target.Close() }()

	metadata, err := adapters.ResolveKeyMetadata(target.Runtime, request.Slot)
	if err != nil {
		return Response{}, err
	}
	policy := adapters.DeriveSignAuthorization(metadata)
	publicKey, err := readPublicKey(target.Runtime, request.Slot)
	if err != nil {
		return Response{}, err
	}
	algorithm, _, err := InferPublicKeyAlgorithm(publicKey)
	if err != nil {
		return Response{}, err
	}
	if shouldPromptPINForSign(policy, request.UsePIN) {
		pin, resolveErr := resolver.ResolveString(request.PIN)
		if resolveErr != nil {
			return Response{}, resolveErr
		}
		if err := target.Session.Client.VerifyPIN(pin); err != nil {
			return Response{}, err
		}
	}
	signature, err := target.Session.Client.Sign(algorithm, request.Slot, payload, hashMode)
	if err != nil {
		return Response{}, err
	}
	return s.binaryArtifactResponse(target, "key-sign", "signature", request.Encoding, request.Out, signature, request.Global.JSON)
}

// KeyChallenge runs GENERAL AUTHENTICATE with a supplied challenge. X25519
// slots perform ECDH key agreement instead: the challenge hex carries the
// 32-byte peer public key and the response is the 32-byte shared secret
// (kind "ecdh-secret"). ML-KEM slots decapsulate instead: the challenge hex
// carries the variant-sized ciphertext (768/1088/1568 bytes for
// ML-KEM-512/768/1024) and the response is the 32-byte shared secret (kind
// "kem-secret"); encapsulation stays host-side.
func (s *MutationService) KeyChallenge(ctx context.Context, request ChallengeRequest) (Response, error) {
	if err := rejectAttestationSlot(request.Slot); err != nil {
		return Response{}, err
	}
	resolver := s.resolver(request.Global)
	challenge, err := hex.DecodeString(strings.TrimSpace(strings.ReplaceAll(request.ChallengeHex, " ", "")))
	if err != nil || len(challenge) == 0 {
		return Response{}, UsageError("invalid challenge hex", "provide challenge bytes through --challenge-hex")
	}
	target, err := s.targets.Resolve(ctx, request.Global)
	if err != nil {
		return Response{}, err
	}
	defer func() { _ = target.Close() }()

	publicKey, err := readPublicKey(target.Runtime, request.Slot)
	if err != nil {
		return Response{}, err
	}
	algorithm, _, err := InferPublicKeyAlgorithm(publicKey)
	if err != nil {
		return Response{}, err
	}
	if algorithm == piv.AlgX25519 {
		if len(challenge) != 32 {
			return Response{}, UsageError(fmt.Sprintf("invalid ECDH peer key length %d, must be 32 bytes", len(challenge)), "provide the 32-byte peer public key through --challenge-hex")
		}
		if request.UsePIN {
			pin, resolveErr := resolver.ResolveString(request.PIN)
			if resolveErr != nil {
				return Response{}, resolveErr
			}
			if err := target.Session.Client.VerifyPIN(pin); err != nil {
				return Response{}, err
			}
		}
		secret, err := target.Session.Client.CalculateSecret(request.Slot, challenge)
		if err != nil {
			return Response{}, err
		}
		return s.binaryArtifactResponse(target, "key-challenge", "ecdh-secret", request.Encoding, request.Out, secret, request.Global.JSON)
	}
	if piv.IsMLKEMAlgorithm(algorithm) {
		ciphertextLen, ok := piv.MLKEMCiphertextLength(algorithm)
		if !ok || len(challenge) != ciphertextLen {
			return Response{}, UsageError(fmt.Sprintf("invalid KEM ciphertext length %d for %s, must be %d bytes", len(challenge), AlgorithmName(algorithm), ciphertextLen), "provide the encapsulation ciphertext through --challenge-hex")
		}
		if request.UsePIN {
			pin, resolveErr := resolver.ResolveString(request.PIN)
			if resolveErr != nil {
				return Response{}, resolveErr
			}
			if err := target.Session.Client.VerifyPIN(pin); err != nil {
				return Response{}, err
			}
		}
		secret, err := decapsulateSecret(target.Runtime, algorithm, request.Slot, challenge)
		if err != nil {
			return Response{}, err
		}
		return s.binaryArtifactResponse(target, "key-challenge", "kem-secret", request.Encoding, request.Out, secret, request.Global.JSON)
	}
	if request.UsePIN {
		pin, resolveErr := resolver.ResolveString(request.PIN)
		if resolveErr != nil {
			return Response{}, resolveErr
		}
		if err := target.Session.Client.VerifyPIN(pin); err != nil {
			return Response{}, err
		}
		responseData, err := target.Session.Client.Authenticate(algorithm, request.Slot, challenge)
		if err != nil {
			return Response{}, err
		}
		return s.binaryArtifactResponse(target, "key-challenge", "challenge-response", request.Encoding, request.Out, responseData, request.Global.JSON)
	}
	responseData, err := target.Session.Client.Authenticate(algorithm, request.Slot, challenge)
	if err != nil {
		return Response{}, err
	}
	return s.binaryArtifactResponse(target, "key-challenge", "challenge-response", request.Encoding, request.Out, responseData, request.Global.JSON)
}

// PINVerify verifies the card PIN.
func (s *MutationService) PINVerify(ctx context.Context, request PINVerifyRequest) (Response, error) {
	resolver := s.resolver(request.Global)
	target, err := s.targets.Resolve(ctx, request.Global)
	if err != nil {
		return Response{}, err
	}
	defer func() { _ = target.Close() }()

	pin, err := resolver.ResolveString(request.PIN)
	if err != nil {
		return Response{}, err
	}
	if err := target.Session.Client.VerifyPIN(pin); err != nil {
		return Response{}, err
	}
	response := Response{Command: "pin-verify", Target: target.Summary, Result: VerificationResult{Subject: "pin", Verified: true}}
	response.traceLines = target.TraceLines()
	return response, nil
}

// PINChange changes the current PIN.
func (s *MutationService) PINChange(ctx context.Context, request PINChangeRequest) (Response, error) {
	resolver := s.resolver(request.Global)
	target, err := s.targets.Resolve(ctx, request.Global)
	if err != nil {
		return Response{}, err
	}
	defer func() { _ = target.Close() }()

	oldPIN, err := resolver.ResolveString(request.OldPIN)
	if err != nil {
		return Response{}, err
	}
	newPIN, err := resolver.ResolveString(request.NewPIN)
	if err != nil {
		return Response{}, err
	}
	if err := adaptersadmin.ChangePIN(target.Runtime, oldPIN, newPIN); err != nil {
		return Response{}, err
	}
	response := Response{Command: "pin-change", Target: target.Summary, Result: MutationResult{Action: "pin-change", Changed: true}}
	response.traceLines = target.TraceLines()
	return response, nil
}

// PINUnblock resets the PIN using the PUK.
func (s *MutationService) PINUnblock(ctx context.Context, request PINUnblockRequest) (Response, error) {
	resolver := s.resolver(request.Global)
	target, err := s.targets.Resolve(ctx, request.Global)
	if err != nil {
		return Response{}, err
	}
	defer func() { _ = target.Close() }()

	puk, err := resolver.ResolveString(request.PUK)
	if err != nil {
		return Response{}, err
	}
	newPIN, err := resolver.ResolveString(request.NewPIN)
	if err != nil {
		return Response{}, err
	}
	if err := adaptersadmin.UnblockPIN(target.Runtime, puk, newPIN); err != nil {
		return Response{}, err
	}
	response := Response{Command: "pin-unblock", Target: target.Summary, Result: MutationResult{Action: "pin-unblock", Changed: true}}
	response.traceLines = target.TraceLines()
	return response, nil
}

// PUKChange changes the current PUK.
func (s *MutationService) PUKChange(ctx context.Context, request PUKChangeRequest) (Response, error) {
	resolver := s.resolver(request.Global)
	target, err := s.targets.Resolve(ctx, request.Global)
	if err != nil {
		return Response{}, err
	}
	defer func() { _ = target.Close() }()

	oldPUK, err := resolver.ResolveString(request.OldPUK)
	if err != nil {
		return Response{}, err
	}
	newPUK, err := resolver.ResolveString(request.NewPUK)
	if err != nil {
		return Response{}, err
	}
	if err := adaptersadmin.ChangePUK(target.Runtime, oldPUK, newPUK); err != nil {
		return Response{}, err
	}
	response := Response{Command: "puk-change", Target: target.Summary, Result: MutationResult{Action: "puk-change", Changed: true}}
	response.traceLines = target.TraceLines()
	return response, nil
}

// MGMVerify verifies the supplied management key.
func (s *MutationService) MGMVerify(ctx context.Context, request MGMVerifyRequest) (Response, error) {
	resolver := s.resolver(request.Global)
	target, err := s.targets.Resolve(ctx, request.Global)
	if err != nil {
		return Response{}, err
	}
	defer func() { _ = target.Close() }()

	algorithmName, err := s.setManagementCredentials(target.Runtime, resolver, request.Key, request.Algorithm)
	if err != nil {
		return Response{}, err
	}
	if err := target.Runtime.AuthenticateManagementKey(); err != nil {
		return Response{}, err
	}
	response := Response{Command: "mgm-verify", Target: target.Summary, Result: VerificationResult{Subject: "management-key", Verified: true, Algorithm: algorithmName}}
	response.traceLines = target.TraceLines()
	return response, nil
}

// MGMRotate rotates the management key.
func (s *MutationService) MGMRotate(ctx context.Context, request MGMRotateRequest) (Response, error) {
	resolver := s.resolver(request.Global)
	if request.NewAlgorithm == 0 {
		return Response{}, UsageError("a new management key algorithm is required", "rerun with --new-alg aes128, aes192, aes256, or 3des")
	}
	target, err := s.targets.Resolve(ctx, request.Global)
	if err != nil {
		return Response{}, err
	}
	defer func() { _ = target.Close() }()

	currentAlgorithmName, err := s.setManagementCredentials(target.Runtime, resolver, request.CurrentKey, request.Algorithm)
	if err != nil {
		return Response{}, err
	}
	newKey, err := resolver.ResolveManagementKey(request.NewKey)
	if err != nil {
		return Response{}, err
	}
	plan := s.planner.Build(
		"rotate the management key",
		[]string{fmt.Sprintf("current management key (%s)", currentAlgorithmName), fmt.Sprintf("new management key (%s)", request.NewAlgorithmName)},
		[]string{fmt.Sprintf("replace the management key with a %s credential", request.NewAlgorithmName)},
		nil,
	)
	if request.DryRun {
		response := Response{Command: "mgm-rotate", Target: target.Summary, Result: MutationResult{Action: "mgm-rotate", DryRun: true, Plan: plan, Algorithm: request.NewAlgorithmName}}
		response.traceLines = target.TraceLines()
		return response, nil
	}
	if err := s.planner.Confirm(plan, request.Global.NonInteractive, request.Yes); err != nil {
		return Response{}, err
	}
	if err := adaptersadmin.ChangeManagementKeyWithTouch(target.Runtime, request.NewAlgorithm, newKey, request.RequireTouch); err != nil {
		return Response{}, err
	}
	response := Response{Command: "mgm-rotate", Target: target.Summary, Result: MutationResult{Action: "mgm-rotate", Changed: true, Algorithm: request.NewAlgorithmName}}
	response.traceLines = target.TraceLines()
	return response, nil
}

// SetupInit initializes the selected token using application defaults.
func (s *MutationService) SetupInit(ctx context.Context, request SetupInitRequest) (Response, error) {
	resolver := s.resolver(request.Global)
	target, err := s.targets.Resolve(ctx, request.Global)
	if err != nil {
		return Response{}, err
	}
	defer func() { _ = target.Close() }()

	requirements, err := describeInitialization(target.Runtime)
	if err != nil {
		return Response{}, err
	}
	algorithmName, err := s.setManagementCredentials(target.Runtime, resolver, request.ManagementKey, 0)
	if err != nil {
		return Response{}, err
	}
	plan := s.planner.Build(
		"initialize the token",
		[]string{fmt.Sprintf("management key (%s)", algorithmName)},
		[]string{"clear token containers", "provision identity objects"},
		descriptionsFromFields(requirements.Fields),
	)
	if request.DryRun {
		response := Response{Command: "setup-init", Target: target.Summary, Result: MutationResult{Action: "setup-init", DryRun: true, Plan: plan}}
		response.traceLines = target.TraceLines()
		return response, nil
	}
	if err := s.planner.Confirm(plan, request.Global.NonInteractive, request.Yes); err != nil {
		return Response{}, err
	}
	result, err := initializeToken(target.Runtime, adapters.InitializeTokenParams{ClearContainers: true, ProvisionIdentity: true})
	if err != nil {
		return Response{}, err
	}
	response := Response{Command: "setup-init", Target: target.Summary, Result: MutationResult{Action: "setup-init", Changed: true, Steps: result.Steps, Notes: result.Notes}}
	if len(result.APDULog) > 0 {
		response.traceLines = result.APDULog
	} else {
		response.traceLines = target.TraceLines()
	}
	return response, nil
}

// SetupReset resets the selected token.
func (s *MutationService) SetupReset(ctx context.Context, request SetupResetRequest) (Response, error) {
	resolver := s.resolver(request.Global)
	target, err := s.targets.Resolve(ctx, request.Global)
	if err != nil {
		return Response{}, err
	}
	defer func() { _ = target.Close() }()

	requirements, err := adaptersadmin.DescribeReset(target.Runtime)
	if err != nil {
		return Response{}, err
	}
	credentials := make([]string, 0, 2)
	notes := descriptionsFromFields(requirements.Fields)
	params := adapters.ResetTokenParams{}
	if requiresManagementKey(target.Runtime) {
		algorithmName, resolveErr := s.setManagementCredentials(target.Runtime, resolver, request.ManagementKey, 0)
		if resolveErr != nil {
			return Response{}, resolveErr
		}
		credentials = append(credentials, fmt.Sprintf("management key (%s)", algorithmName))
	}
	if requirements.RequiresPUK {
		puk, resolveErr := resolver.ResolveString(request.PUK)
		if resolveErr != nil {
			return Response{}, resolveErr
		}
		params.PUK = puk
		credentials = append(credentials, "PUK")
	}
	plan := s.planner.Build("reset the token", credentials, []string{"clear PIV application state and vendor metadata"}, notes)
	if request.DryRun {
		response := Response{Command: "setup-reset", Target: target.Summary, Result: MutationResult{Action: "setup-reset", DryRun: true, Plan: plan}}
		response.traceLines = target.TraceLines()
		return response, nil
	}
	if err := s.planner.Confirm(plan, request.Global.NonInteractive, request.Yes); err != nil {
		return Response{}, err
	}
	if err := adaptersadmin.ResetToken(target.Runtime, params); err != nil {
		return Response{}, err
	}
	response := Response{Command: "setup-reset", Target: target.Summary, Result: MutationResult{Action: "setup-reset", Changed: true}}
	response.traceLines = target.TraceLines()
	return response, nil
}

// SetupResetSlot resets one slot.
func (s *MutationService) SetupResetSlot(ctx context.Context, request SetupResetSlotRequest) (Response, error) {
	if err := rejectAttestationSlot(request.Slot); err != nil {
		return Response{}, err
	}
	resolver := s.resolver(request.Global)
	target, err := s.targets.Resolve(ctx, request.Global)
	if err != nil {
		return Response{}, err
	}
	defer func() { _ = target.Close() }()

	algorithmName, err := s.setManagementCredentials(target.Runtime, resolver, request.ManagementKey, 0)
	if err != nil {
		return Response{}, err
	}
	plan := s.planner.Build(
		fmt.Sprintf("reset slot %s", SlotName(request.Slot)),
		[]string{fmt.Sprintf("management key (%s)", algorithmName)},
		[]string{fmt.Sprintf("clear vendor slot state for %s", SlotName(request.Slot))},
		nil,
	)
	if request.DryRun {
		response := Response{Command: "setup-reset-slot", Target: target.Summary, Result: MutationResult{Action: "setup-reset-slot", DryRun: true, Plan: plan}}
		response.traceLines = target.TraceLines()
		return response, nil
	}
	if err := s.planner.Confirm(plan, request.Global.NonInteractive, request.Yes); err != nil {
		return Response{}, err
	}
	if err := target.Runtime.AuthenticateManagementKey(); err != nil {
		return Response{}, err
	}
	if err := adaptersadmin.ResetSlot(target.Runtime, request.Slot); err != nil {
		return Response{}, err
	}
	response := Response{Command: "setup-reset-slot", Target: target.Summary, Result: MutationResult{Action: "setup-reset-slot", Changed: true}}
	response.traceLines = target.TraceLines()
	return response, nil
}

func (s *MutationService) setManagementCredentials(runtime *adapters.Runtime, resolver *CredentialResolver, request SecretRequest, explicitAlgorithm byte) (string, error) {
	key, err := resolver.ResolveManagementKey(request)
	if err != nil {
		return "", err
	}
	algorithm := explicitAlgorithm
	if algorithm == 0 {
		resolved, resolveErr := adapters.ResolveManagementKeyAlgorithm(runtime.Session, runtime.Adapter, key)
		if resolveErr != nil {
			return "", resolveErr
		}
		algorithm = resolved
	}
	runtime.Session.ManagementAlgorithm = algorithm
	runtime.Session.ManagementKey = append([]byte(nil), key...)
	return AlgorithmName(algorithm), nil
}

func (s *MutationService) binaryArtifactResponse(target *ResolvedTarget, command string, kind string, encoding string, out string, data []byte, jsonMode bool) (Response, error) {
	encoded, effectiveEncoding, err := EncodeBinary(data, encoding)
	if err != nil {
		return Response{}, err
	}
	result := ArtifactResult{Kind: kind, Encoding: effectiveEncoding, Size: len(encoded)}
	warnings := make([]Warning, 0)
	if out != "" {
		if err := os.WriteFile(out, encoded, 0o644); err != nil {
			return Response{}, IOError("unable to write output file", "check the output path and permissions", err)
		}
		result.Path = out
	} else if jsonMode {
		if effectiveEncoding == "raw" {
			result.Data = base64.StdEncoding.EncodeToString(data)
			result.Encoding = "base64"
			warnings = append(warnings, Warning{Code: "raw-json-coercion", Message: "raw output is encoded as base64 in JSON mode"})
		} else {
			result.Data = strings.TrimSpace(string(encoded))
		}
	} else {
		result.Data = strings.TrimSpace(string(encoded))
	}
	response := Response{Command: command, Target: target.Summary, Result: result, Warnings: warnings}
	if out == "" {
		response.rawOutput = encoded
	}
	response.traceLines = target.TraceLines()
	return response, nil
}

func hashInput(data []byte, mode string) ([]byte, error) {
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case "", "none":
		return data, nil
	case "sha256":
		hashed := sha256.Sum256(data)
		return hashed[:], nil
	default:
		return nil, UsageError(fmt.Sprintf("unsupported hash mode %q", mode), "use none or sha256")
	}
}

// signHashMode maps the CLI --hash flag to the explicit extended-RSA wire
// format: none pads raw PKCS#1 v1.5 type-1 without DigestInfo, sha256 wraps
// the hashed digest with DigestInfo. The mode is ignored for non-extended
// algorithms but is still threaded explicitly so a 32-byte raw payload is
// never confused with a digest.
func signHashMode(mode string) (piv.RSASignHashMode, error) {
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case "", "none":
		return piv.RSASignHashNone, nil
	case "sha256":
		return piv.RSASignHashSHA256, nil
	default:
		return piv.RSASignHashNone, UsageError(fmt.Sprintf("unsupported hash mode %q", mode), "use none or sha256")
	}
}

func descriptionsFromFields(fields []adapters.InitializationField) []string {
	result := make([]string, 0, len(fields))
	for _, field := range fields {
		if field.Description != "" {
			result = append(result, field.Description)
		}
	}
	return result
}

func requiresManagementKey(runtime *adapters.Runtime) bool {
	if runtime == nil || runtime.Adapter == nil {
		return false
	}
	return runtime.Adapter.Name() == "safenet"
}

// requiresCertificateManagementAuth reports whether certificate writes on
// the selected token require management authentication. YubiKey and SafeNet
// adapters authenticate inside Put/DeleteCertificate; the standard transport
// writes the object directly, preserving its credential-free behavior.
func requiresCertificateManagementAuth(runtime *adapters.Runtime) bool {
	if runtime == nil || runtime.Adapter == nil {
		return false
	}
	switch runtime.Adapter.Name() {
	case "yubikey", "safenet":
		return true
	default:
		return false
	}
}

// authenticateForCertificateWrite resolves management credentials and
// authenticates before a certificate import or delete on tokens whose
// adapter requires it. Standard tokens skip authentication entirely so
// credential-free writes keep working. Idempotent no-change and dry-run
// paths return before this point and never touch credentials.
func (s *MutationService) authenticateForCertificateWrite(runtime *adapters.Runtime, global GlobalOptions, request SecretRequest) error {
	if !requiresCertificateManagementAuth(runtime) {
		return nil
	}
	resolver := s.resolver(global)
	if _, err := s.setManagementCredentials(runtime, resolver, request, 0); err != nil {
		return err
	}
	if err := runtime.AuthenticateManagementKey(); err != nil {
		return err
	}
	return nil
}

func (s *MutationService) resolver(global GlobalOptions) *CredentialResolver {
	interactive := !global.NonInteractive && IsInteractiveInput(s.input)
	return NewCredentialResolver(s.input, s.stderr, interactive)
}
