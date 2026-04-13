package app

import (
	"bytes"
	"context"
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
}

// DeleteRequest configures destructive delete flows.
type DeleteRequest struct {
	Global GlobalOptions
	Slot   piv.Slot
	Yes    bool
	DryRun bool
}

// KeyGenerateRequest configures piv key generate.
type KeyGenerateRequest struct {
	Global        GlobalOptions
	Slot          piv.Slot
	Algorithm     byte
	AlgorithmName string
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

// CertImport installs a certificate into a slot.
func (s *MutationService) CertImport(ctx context.Context, request CertImportRequest) (Response, error) {
	inputData, err := ReadInputFile(request.Path, s.input)
	if err != nil {
		return Response{}, err
	}
	certData, err := ParseCertificateData(inputData)
	if err != nil {
		return Response{}, err
	}
	target, err := s.targets.Resolve(ctx, request.Global)
	if err != nil {
		return Response{}, err
	}
	defer func() { _ = target.Close() }()

	if installed, readErr := readCertificate(target.Runtime, request.Slot); readErr == nil && bytes.Equal(installed, certData) {
		response := Response{
			Command: "cert-import",
			Target:  target.Summary,
			Result:  MutationResult{Action: "cert-import", Changed: false, Notes: []string{"certificate already matches slot contents"}},
		}
		response.traceLines = target.TraceLines()
		return response, nil
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
	if err := clearCertificate(target.Runtime, request.Slot); err != nil {
		return Response{}, err
	}
	response := Response{Command: "cert-delete", Target: target.Summary, Result: MutationResult{Action: "cert-delete", Changed: true}}
	response.traceLines = target.TraceLines()
	return response, nil
}

// KeyGenerate generates a new slot key.
func (s *MutationService) KeyGenerate(ctx context.Context, request KeyGenerateRequest) (Response, error) {
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
	if _, err := generateKeyPair(target.Runtime, request.Slot, request.Algorithm); err != nil {
		return Response{}, err
	}
	response := Response{Command: "key-generate", Target: target.Summary, Result: MutationResult{Action: "key-generate", Changed: true, Algorithm: request.AlgorithmName}}
	response.traceLines = target.TraceLines()
	return response, nil
}

// KeyDelete deletes a slot key.
func (s *MutationService) KeyDelete(ctx context.Context, request DeleteRequest, managementKey SecretRequest) (Response, error) {
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

// KeySign signs input data with a slot key.
func (s *MutationService) KeySign(ctx context.Context, request SignRequest) (Response, error) {
	resolver := s.resolver(request.Global)
	payload, err := ReadInputFile(request.InputPath, s.input)
	if err != nil {
		return Response{}, err
	}
	payload, err = hashInput(payload, request.Hash)
	if err != nil {
		return Response{}, err
	}
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
	publicKey, err := readPublicKey(target.Runtime, request.Slot)
	if err != nil {
		return Response{}, err
	}
	algorithm, _, err := InferPublicKeyAlgorithm(publicKey)
	if err != nil {
		return Response{}, err
	}
	signature, err := target.Session.Client.Sign(algorithm, request.Slot, payload)
	if err != nil {
		return Response{}, err
	}
	return s.binaryArtifactResponse(target, "key-sign", "signature", request.Encoding, request.Out, signature, request.Global.JSON)
}

// KeyChallenge runs GENERAL AUTHENTICATE with a supplied challenge.
func (s *MutationService) KeyChallenge(ctx context.Context, request ChallengeRequest) (Response, error) {
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

	if request.UsePIN {
		pin, resolveErr := resolver.ResolveString(request.PIN)
		if resolveErr != nil {
			return Response{}, resolveErr
		}
		if err := target.Session.Client.VerifyPIN(pin); err != nil {
			return Response{}, err
		}
	}
	publicKey, err := readPublicKey(target.Runtime, request.Slot)
	if err != nil {
		return Response{}, err
	}
	algorithm, _, err := InferPublicKeyAlgorithm(publicKey)
	if err != nil {
		return Response{}, err
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
	if err := adaptersadmin.ChangeManagementKey(target.Runtime, request.NewAlgorithm, newKey); err != nil {
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

func (s *MutationService) resolver(global GlobalOptions) *CredentialResolver {
	interactive := !global.NonInteractive && IsInteractiveInput(s.input)
	return NewCredentialResolver(s.input, s.stderr, interactive)
}
