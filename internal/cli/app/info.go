package app

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"math/big"
	"os"
	"strings"
	"unicode/utf8"

	"github.com/PeculiarVentures/piv-go/adapters"
	adaptersadmin "github.com/PeculiarVentures/piv-go/adapters/admin"
	"github.com/PeculiarVentures/piv-go/iso7816"
	"github.com/PeculiarVentures/piv-go/piv"
)

// InfoRequest configures the piv info command.
type InfoRequest struct {
	Global   GlobalOptions
	Sections []string
}

// SlotRequest configures slot inspection commands.
type SlotRequest struct {
	Global GlobalOptions
	Slot   piv.Slot
}

// ExportRequest configures artifact export commands.
type ExportRequest struct {
	Global GlobalOptions
	Slot   piv.Slot
	Format string
	Out    string
}

// StatusRequest configures PIN and PUK status reads.
type StatusRequest struct {
	Global GlobalOptions
}

// InfoService exposes the read-only command surface.
type InfoService struct {
	targets *TargetResolver
}

// NewInfoService creates a new read-only service layer.
func NewInfoService(targets *TargetResolver) *InfoService {
	return &InfoService{targets: targets}
}

// Devices lists visible readers and PIV readiness.
func (s *InfoService) Devices(ctx context.Context, global GlobalOptions) (Response, error) {
	devices, err := s.targets.Discover(ctx)
	if err != nil {
		return Response{}, err
	}
	return Response{
		Command: "devices",
		Target:  TargetSummary{},
		Result:  DevicesResult{Devices: devices},
	}, nil
}

// Info gathers a multi-section token summary.
func (s *InfoService) Info(ctx context.Context, request InfoRequest) (Response, error) {
	sections, err := normalizeInfoSections(request.Sections)
	if err != nil {
		return Response{}, err
	}
	target, err := s.targets.Resolve(ctx, request.Global)
	if err != nil {
		return Response{}, err
	}
	defer func() {
		_ = target.Close()
	}()

	result := InfoResult{}
	warnings := make([]Warning, 0)
	capabilityReport := adapters.ReportCapabilities(target.Runtime.Adapter)

	if sections["summary"] {
		if label, readErr := adapters.ReadTokenLabel(target.Runtime); readErr == nil {
			result.Label = sanitizeDisplayBytes([]byte(label))
		} else if !errors.Is(readErr, adapters.ErrTokenLabelUnsupported) {
			warnings = append(warnings, Warning{Code: "label-read-failed", Message: readErr.Error()})
		}
		if serial, readErr := adapters.ReadSerialNumber(target.Runtime); readErr == nil {
			result.Serial = formatSerial(target.Runtime.Adapter, serial)
		} else if !errors.Is(readErr, adapters.ErrSerialNumberUnsupported) {
			warnings = append(warnings, Warning{Code: "serial-read-failed", Message: readErr.Error()})
		}
		if chuid, readErr := adapters.ReadCHUID(target.Runtime); readErr == nil {
			result.CHUID = chuid
		} else if !(iso7816.IsStatus(readErr, iso7816.SwFileNotFound) || iso7816.IsStatus(readErr, iso7816.SwReferencedDataNotFound)) {
			warnings = append(warnings, Warning{Code: "chuid-read-failed", Message: readErr.Error()})
		}
	}

	var slots []SlotView
	if sections["slots"] || sections["summary"] {
		slots, err = describePrimarySlots(target.Runtime)
		if err != nil {
			return Response{}, err
		}
		if sections["slots"] {
			result.Slots = slots
		}
	}

	if sections["capabilities"] {
		result.Capabilities = buildCapabilityViews(capabilityReport)
	}

	if sections["credentials"] {
		result.Credentials = s.readCredentialStatuses(target.Runtime, capabilityReport, &warnings)
	}

	result.State = deriveTokenState(target.Runtime, slots, capabilityReport)
	response := Response{
		Command:  "info",
		Target:   target.Summary,
		Result:   result,
		Warnings: warnings,
	}
	response.traceLines = target.TraceLines()
	return response, nil
}

func formatSerial(adapter adapters.Adapter, serial []byte) string {
	serial = bytes.Trim(serial, "\x00")
	if adapter != nil && strings.EqualFold(adapter.Name(), "yubikey") {
		return new(big.Int).SetBytes(serial).String()
	}
	return strings.ToUpper(strings.TrimSpace(sanitizeDisplayBytes(serial)))
}

func sanitizeDisplayBytes(data []byte) string {
	data = bytes.Trim(data, "\x00")
	if utf8.Valid(data) {
		return strings.TrimSpace(string(data))
	}
	filtered := make([]byte, 0, len(data))
	for _, b := range data {
		if b >= 0x20 && b <= 0x7e {
			filtered = append(filtered, b)
		}
	}
	return strings.TrimSpace(string(filtered))
}

// SlotList lists the primary user slots.
func (s *InfoService) SlotList(ctx context.Context, global GlobalOptions) (Response, error) {
	target, err := s.targets.Resolve(ctx, global)
	if err != nil {
		return Response{}, err
	}
	defer func() {
		_ = target.Close()
	}()

	slots, err := describePrimarySlots(target.Runtime)
	if err != nil {
		return Response{}, err
	}
	response := Response{
		Command: "slot-list",
		Target:  target.Summary,
		Result:  SlotListResult{Slots: slots},
	}
	response.traceLines = target.TraceLines()
	return response, nil
}

// SlotShow displays one slot in detail.
func (s *InfoService) SlotShow(ctx context.Context, request SlotRequest) (Response, error) {
	target, err := s.targets.Resolve(ctx, request.Global)
	if err != nil {
		return Response{}, err
	}
	defer func() {
		_ = target.Close()
	}()

	slot, err := describeSlot(target.Runtime, request.Slot)
	if err != nil {
		return Response{}, err
	}
	response := Response{
		Command: "slot-show",
		Target:  target.Summary,
		Result:  SlotShowResult{Slot: slot},
	}
	response.traceLines = target.TraceLines()
	return response, nil
}

// CertExport exports a slot certificate in PEM or DER format.
func (s *InfoService) CertExport(ctx context.Context, request ExportRequest) (Response, error) {
	target, err := s.targets.Resolve(ctx, request.Global)
	if err != nil {
		return Response{}, err
	}
	defer func() {
		_ = target.Close()
	}()

	certData, err := readCertificate(target.Runtime, request.Slot)
	if err != nil {
		return Response{}, NotFoundError("the requested certificate is not present", "inspect slot state with piv slot show <slot>", err)
	}
	format := request.Format
	if format == "" {
		format = request.Global.DefaultCertFmt
	}
	if format == "" {
		format = "pem"
	}
	encoded, err := EncodeCertificate(certData, format)
	if err != nil {
		return Response{}, err
	}
	result := ArtifactResult{Kind: "certificate", Format: strings.ToLower(format), Size: len(encoded)}
	if request.Out != "" {
		if err := os.WriteFile(request.Out, encoded, 0o644); err != nil {
			return Response{}, IOError("unable to write certificate output", "check the output path and permissions", err)
		}
		result.Path = request.Out
	} else if request.Global.JSON {
		if strings.EqualFold(format, "der") {
			result.Data = base64.StdEncoding.EncodeToString(encoded)
			result.Encoding = "base64"
		} else {
			result.Data = string(encoded)
		}
	} else {
		result.Data = string(encoded)
	}
	response := Response{Command: "cert-export", Target: target.Summary, Result: result}
	if request.Out == "" {
		response.rawOutput = encoded
	}
	response.traceLines = target.TraceLines()
	return response, nil
}

// KeyPublic exports a public key in PEM or DER format. Ed25519 opaque keys
// encode as standard PEM/DER through the standard library. All other opaque
// keys (X25519, ML-DSA/ML-KEM, ambiguous) keep the PEM/DER gap and must be
// exported with --format raw, base64, or hex, which renders the raw key
// bytes via EncodeBinary.
func (s *InfoService) KeyPublic(ctx context.Context, request ExportRequest) (Response, error) {
	target, err := s.targets.Resolve(ctx, request.Global)
	if err != nil {
		return Response{}, err
	}
	defer func() {
		_ = target.Close()
	}()

	publicKey, err := readPublicKey(target.Runtime, request.Slot)
	if err != nil {
		return Response{}, NotFoundError("the requested public key is not present", "inspect slot state with piv slot show <slot>", err)
	}
	format := request.Format
	if format == "" {
		format = request.Global.DefaultPublicFmt
	}
	if format == "" {
		format = "pem"
	}
	if _, ok := opaquePublicKeyAlgorithm(publicKey); ok && isOpaqueRawFormat(format) {
		return s.opaqueKeyResponse(target, request, publicKey, format)
	}
	encoded, err := EncodePublicKey(publicKey, format)
	if err != nil {
		return Response{}, err
	}
	result := ArtifactResult{Kind: "public-key", Format: strings.ToLower(format), Size: len(encoded)}
	if request.Out != "" {
		if err := os.WriteFile(request.Out, encoded, 0o644); err != nil {
			return Response{}, IOError("unable to write public key output", "check the output path and permissions", err)
		}
		result.Path = request.Out
	} else if request.Global.JSON {
		if strings.EqualFold(format, "der") {
			result.Data = base64.StdEncoding.EncodeToString(encoded)
			result.Encoding = "base64"
		} else {
			result.Data = string(encoded)
		}
	} else {
		result.Data = string(encoded)
	}
	response := Response{Command: "key-public", Target: target.Summary, Result: result}
	if request.Out == "" {
		response.rawOutput = encoded
	}
	response.traceLines = target.TraceLines()
	return response, nil
}

// isOpaqueRawFormat reports whether the requested public key format selects
// raw opaque bytes instead of PEM/DER.
func isOpaqueRawFormat(format string) bool {
	switch strings.ToLower(strings.TrimSpace(format)) {
	case "raw", "base64", "hex":
		return true
	default:
		return false
	}
}

func (s *InfoService) opaqueKeyResponse(target *ResolvedTarget, request ExportRequest, publicKey interface{}, format string) (Response, error) {
	var raw []byte
	switch key := publicKey.(type) {
	case *piv.OpaquePublicKey:
		if key == nil {
			return Response{}, NotFoundError("the requested public key is not present", "inspect slot state with piv slot show <slot>", nil)
		}
		raw = key.Raw
	case piv.OpaquePublicKey:
		raw = key.Raw
	default:
		return Response{}, UnsupportedError("the selected slot uses an opaque key without PEM or DER encoding support", "rerun with --format raw, base64, or hex for the opaque key bytes")
	}
	normalized := strings.ToLower(strings.TrimSpace(format))
	switch normalized {
	case "pem", "der":
		return Response{}, UnsupportedError("the selected slot uses an opaque key without PEM or DER encoding support", "rerun with --format raw, base64, or hex for the opaque key bytes")
	case "", "base64", "hex", "raw":
		if normalized == "" {
			normalized = "base64"
		}
	default:
		return Response{}, UsageError("unsupported public key format", "use pem, der, raw, base64, or hex (raw encodings for post-quantum keys)")
	}
	encoded, effectiveEncoding, err := EncodeBinary(raw, normalized)
	if err != nil {
		return Response{}, err
	}
	result := ArtifactResult{Kind: "public-key", Format: effectiveEncoding, Encoding: effectiveEncoding, Size: len(encoded)}
	if request.Out != "" {
		if err := os.WriteFile(request.Out, encoded, 0o644); err != nil {
			return Response{}, IOError("unable to write public key output", "check the output path and permissions", err)
		}
		result.Path = request.Out
	} else if request.Global.JSON {
		if effectiveEncoding == "raw" {
			result.Data = base64.StdEncoding.EncodeToString(raw)
			result.Encoding = "base64"
		} else {
			result.Data = strings.TrimSpace(string(encoded))
		}
	} else {
		result.Data = strings.TrimSpace(string(encoded))
	}
	response := Response{Command: "key-public", Target: target.Summary, Result: result}
	if request.Out == "" {
		response.rawOutput = encoded
	}
	response.traceLines = target.TraceLines()
	return response, nil
}

// Attest exports the attestation certificate for a slot key in PEM or DER
// format. Attestation is a read-only vendor operation: tokens without a
// KeyAttestationAdapter report it as unsupported.
func (s *InfoService) Attest(ctx context.Context, request ExportRequest) (Response, error) {
	if isAttestationSlot(request.Slot) {
		return Response{}, UnsupportedError("attestation is not supported for slot F9", "attest one of auth, sign, key-mgmt, or card-auth")
	}
	target, err := s.targets.Resolve(ctx, request.Global)
	if err != nil {
		return Response{}, err
	}
	defer func() {
		_ = target.Close()
	}()

	attestationDER, err := attestKey(target.Runtime, request.Slot)
	if err != nil {
		return Response{}, err
	}
	format := request.Format
	if format == "" {
		format = request.Global.DefaultCertFmt
	}
	if format == "" {
		format = "pem"
	}
	encoded, err := EncodeCertificate(attestationDER, format)
	if err != nil {
		return Response{}, err
	}
	result := ArtifactResult{Kind: "attestation", Format: strings.ToLower(format), Size: len(encoded)}
	if request.Out != "" {
		if err := os.WriteFile(request.Out, encoded, 0o644); err != nil {
			return Response{}, IOError("unable to write attestation output", "check the output path and permissions", err)
		}
		result.Path = request.Out
	} else if request.Global.JSON {
		if strings.EqualFold(format, "der") {
			result.Data = base64.StdEncoding.EncodeToString(encoded)
			result.Encoding = "base64"
		} else {
			result.Data = string(encoded)
		}
	} else {
		result.Data = string(encoded)
	}
	response := Response{Command: "key-attest", Target: target.Summary, Result: result}
	if request.Out == "" {
		response.rawOutput = encoded
	}
	response.traceLines = target.TraceLines()
	return response, nil
}

// PINStatus reports the card PIN retry state.
func (s *InfoService) PINStatus(ctx context.Context, request StatusRequest) (Response, error) {
	target, err := s.targets.Resolve(ctx, request.Global)
	if err != nil {
		return Response{}, err
	}
	defer func() {
		_ = target.Close()
	}()

	status, err := adaptersadmin.ReadPINStatus(target.Runtime, piv.PINTypeCard)
	if err != nil {
		return Response{}, err
	}
	response := Response{
		Command: "pin-status",
		Target:  target.Summary,
		Result: CredentialStatus{
			Supported:        true,
			RetriesRemaining: status.RetriesLeft,
			Blocked:          status.Blocked,
			Verified:         status.Verified,
		},
	}
	response.traceLines = target.TraceLines()
	return response, nil
}

// PUKStatus reports the PUK retry state when the token supports it.
func (s *InfoService) PUKStatus(ctx context.Context, request StatusRequest) (Response, error) {
	target, err := s.targets.Resolve(ctx, request.Global)
	if err != nil {
		return Response{}, err
	}
	defer func() {
		_ = target.Close()
	}()

	capabilityReport := adapters.ReportCapabilities(target.Runtime.Adapter)
	for _, item := range capabilityReport.Items {
		if item.ID == adapters.CapabilityPUKStatus && item.Support == adapters.CapabilityUnsupported {
			response := Response{
				Command: "puk-status",
				Target:  target.Summary,
				Result:  CredentialStatus{Supported: false, Note: unsupportedCapabilityNote(item.Notes)},
			}
			response.traceLines = target.TraceLines()
			return response, nil
		}
	}
	status, err := adaptersadmin.ReadPINStatus(target.Runtime, piv.PINTypePUK)
	if err != nil {
		return Response{}, err
	}
	response := Response{
		Command: "puk-status",
		Target:  target.Summary,
		Result: CredentialStatus{
			Supported:        true,
			RetriesRemaining: status.RetriesLeft,
			Blocked:          status.Blocked,
			Verified:         status.Verified,
		},
	}
	response.traceLines = target.TraceLines()
	return response, nil
}

func (s *InfoService) MGMStatus(ctx context.Context, request StatusRequest) (Response, error) {
	target, err := s.targets.Resolve(ctx, request.Global)
	if err != nil {
		return Response{}, err
	}
	defer func() {
		_ = target.Close()
	}()

	capabilityReport := adapters.ReportCapabilities(target.Runtime.Adapter)
	for _, item := range capabilityReport.Items {
		if item.ID == adapters.CapabilityManagementKeyStatus && item.Support == adapters.CapabilityUnsupported {
			response := Response{
				Command: "mgm-status",
				Target:  target.Summary,
				Result:  CredentialStatus{Supported: false, Note: unsupportedCapabilityNote(item.Notes)},
			}
			response.traceLines = target.TraceLines()
			return response, nil
		}
	}
	status, err := adaptersadmin.ReadManagementKeyStatus(target.Runtime)
	if err != nil {
		return Response{}, err
	}
	response := Response{
		Command: "mgm-status",
		Target:  target.Summary,
		Result: CredentialStatus{
			Supported:        true,
			RetriesRemaining: status.RetriesLeft,
			Blocked:          status.Blocked,
		},
	}
	response.traceLines = target.TraceLines()
	return response, nil
}

func (s *InfoService) readCredentialStatuses(runtime *adapters.Runtime, capabilityReport adapters.CapabilityReport, warnings *[]Warning) CredentialsView {
	credentials := CredentialsView{}
	if status, err := adaptersadmin.ReadPINStatus(runtime, piv.PINTypeCard); err == nil {
		credentials.PIN = CredentialStatus{Supported: true, RetriesRemaining: status.RetriesLeft, Blocked: status.Blocked, Verified: status.Verified}
	} else {
		*warnings = append(*warnings, Warning{Code: "pin-status-failed", Message: err.Error()})
	}

	pukSupported := true
	mgmSupported := true
	for _, item := range capabilityReport.Items {
		switch item.ID {
		case adapters.CapabilityPUKStatus:
			if item.Support == adapters.CapabilityUnsupported {
				pukSupported = false
				credentials.PUK = CredentialStatus{Supported: false, Note: unsupportedCapabilityNote(item.Notes)}
			}
		case adapters.CapabilityManagementKeyStatus:
			if item.Support == adapters.CapabilityUnsupported {
				mgmSupported = false
				credentials.MGM = CredentialStatus{Supported: false, Note: unsupportedCapabilityNote(item.Notes)}
			}
		}
	}

	if pukSupported {
		if status, err := adaptersadmin.ReadPINStatus(runtime, piv.PINTypePUK); err == nil {
			credentials.PUK = CredentialStatus{Supported: true, RetriesRemaining: status.RetriesLeft, Blocked: status.Blocked, Verified: status.Verified}
		} else {
			*warnings = append(*warnings, Warning{Code: "puk-status-failed", Message: err.Error()})
		}
	}

	if mgmSupported {
		if status, err := adaptersadmin.ReadManagementKeyStatus(runtime); err == nil {
			credentials.MGM = CredentialStatus{Supported: true, RetriesRemaining: status.RetriesLeft, Blocked: status.Blocked}
		} else {
			*warnings = append(*warnings, Warning{Code: "mgm-status-failed", Message: err.Error()})
		}
	}

	return credentials
}

func normalizeInfoSections(sections []string) (map[string]bool, error) {
	allowed := map[string]bool{"summary": true, "capabilities": true, "slots": true, "credentials": true}
	if len(sections) == 0 {
		return map[string]bool{"summary": true, "capabilities": true, "slots": true, "credentials": true}, nil
	}
	resolved := make(map[string]bool)
	for _, section := range sections {
		normalized := strings.ToLower(strings.TrimSpace(section))
		if normalized == "" {
			continue
		}
		if !allowed[normalized] {
			return nil, UsageError("unsupported info section", "use summary, capabilities, slots, or credentials")
		}
		resolved[normalized] = true
	}
	return resolved, nil
}

func buildCapabilityViews(report adapters.CapabilityReport) []CapabilityView {
	result := make([]CapabilityView, 0, len(report.Items))
	for _, item := range report.Items {
		result = append(result, CapabilityView{ID: string(item.ID), Label: item.Label, Support: string(item.Support), Notes: item.Notes})
	}
	return result
}

func deriveTokenState(runtime *adapters.Runtime, slots []SlotView, report adapters.CapabilityReport) string {
	for _, slot := range slots {
		if slot.KeyPresent || slot.CertPresent {
			return "initialized"
		}
	}
	if runtime != nil {
		if _, err := adapters.ReadCHUID(runtime); err == nil {
			return "initialized"
		}
	}
	for _, item := range report.Items {
		if item.ID == adapters.CapabilityInitializeToken && item.Support != adapters.CapabilityUnsupported {
			return "uninitialized"
		}
	}
	return "unknown"
}

func unsupportedCapabilityNote(notes string) string {
	if notes != "" {
		return notes
	}
	return "unsupported on the selected token"
}
