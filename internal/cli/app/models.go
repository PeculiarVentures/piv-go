package app

import (
	"time"

	"github.com/PeculiarVentures/piv-go/adapters"
)

// TraceLevel controls which diagnostic signals are collected during execution.
type TraceLevel string

const (
	TraceOff  TraceLevel = "off"
	TraceAPDU TraceLevel = "apdu"
	TraceOps  TraceLevel = "ops"
	TraceAll  TraceLevel = "all"
)

// GlobalOptions contains the resolved process-wide execution settings.
type GlobalOptions struct {
	Reader              string
	ReaderOrigin        string
	Adapter             string
	AdapterOrigin       string
	JSON                bool
	NonInteractive      bool
	Timeout             time.Duration
	TimeoutOrigin       string
	Trace               TraceLevel
	TraceOrigin         string
	TraceFile           string
	Verbose             bool
	Color               string
	ColorOrigin         string
	DefaultCertFmt      string
	DefaultCertOrigin   string
	DefaultPublicFmt    string
	DefaultPublicOrigin string
}

// TargetSummary identifies the token targeted by a command.
type TargetSummary struct {
	Reader    string `json:"reader,omitempty"`
	Adapter   string `json:"adapter,omitempty"`
	Selection string `json:"selection,omitempty"`
}

// Warning is a stable machine-readable warning record.
type Warning struct {
	Code    string `json:"code,omitempty"`
	Message string `json:"message"`
}

// Response is the unified success envelope for JSON output.
type Response struct {
	Command  string        `json:"command"`
	Target   TargetSummary `json:"target"`
	Result   any           `json:"result"`
	Warnings []Warning     `json:"warnings,omitempty"`

	traceLines []string
	rawOutput  []byte
}

// DevicesResult describes the currently visible PC/SC readers.
type DevicesResult struct {
	Devices []DeviceInfo `json:"devices"`
}

// DeviceInfo describes one PC/SC reader and token probe result.
type DeviceInfo struct {
	Reader      string `json:"reader"`
	CardPresent bool   `json:"card_present"`
	PIVReady    bool   `json:"piv_ready"`
	Adapter     string `json:"adapter,omitempty"`
	Status      string `json:"status"`
	Message     string `json:"message,omitempty"`
}

// InfoResult is the high-level summary returned by piv info.
type InfoResult struct {
	State        string           `json:"state,omitempty"`
	Label        string           `json:"label,omitempty"`
	Serial       string           `json:"serial,omitempty"`
	CHUID        adapters.CHUID   `json:"chuid,omitempty"`
	Capabilities []CapabilityView `json:"capabilities,omitempty"`
	Slots        []SlotView       `json:"slots,omitempty"`
	Credentials  CredentialsView  `json:"credentials,omitempty"`
	Notes        []string         `json:"notes,omitempty"`
}

// CapabilityView is a JSON-friendly capability summary.
type CapabilityView struct {
	ID      string `json:"id"`
	Label   string `json:"label"`
	Support string `json:"support"`
	Notes   string `json:"notes,omitempty"`
}

// SlotView is the stable representation of one slot state.
type SlotView struct {
	Name         string `json:"name"`
	Hex          string `json:"hex"`
	KeyPresent   bool   `json:"key_present"`
	KeyAlgorithm string `json:"key_algorithm,omitempty"`
	CertPresent  bool   `json:"cert_present"`
	CertLabel    string `json:"cert_label,omitempty"`
}

// CredentialsView summarizes the observable credential state.
type CredentialsView struct {
	PIN CredentialStatus `json:"pin,omitempty"`
	PUK CredentialStatus `json:"puk,omitempty"`
	MGM CredentialStatus `json:"mgm,omitempty"`
}

// CredentialStatus describes one credential probe result.
type CredentialStatus struct {
	Supported        bool   `json:"supported"`
	RetriesRemaining int    `json:"retries_remaining,omitempty"`
	Blocked          bool   `json:"blocked,omitempty"`
	Verified         bool   `json:"verified,omitempty"`
	Note             string `json:"note,omitempty"`
}

// SlotListResult is returned by piv slot list.
type SlotListResult struct {
	Slots []SlotView `json:"slots"`
}

// SlotShowResult is returned by piv slot show.
type SlotShowResult struct {
	Slot SlotView `json:"slot"`
}

// ArtifactResult contains a serialized artifact emitted by a command.
type ArtifactResult struct {
	Kind     string `json:"kind"`
	Format   string `json:"format,omitempty"`
	Encoding string `json:"encoding,omitempty"`
	Data     string `json:"data,omitempty"`
	Path     string `json:"path,omitempty"`
	Size     int    `json:"size,omitempty"`
}

// VerificationResult contains the outcome of a non-mutating credential check.
type VerificationResult struct {
	Subject   string   `json:"subject"`
	Verified  bool     `json:"verified"`
	Algorithm string   `json:"algorithm,omitempty"`
	Notes     []string `json:"notes,omitempty"`
}

// MutationResult is the generic result for mutating flows.
type MutationResult struct {
	Action    string         `json:"action"`
	Changed   bool           `json:"changed"`
	DryRun    bool           `json:"dry_run,omitempty"`
	Algorithm string         `json:"algorithm,omitempty"`
	Plan      *OperationPlan `json:"plan,omitempty"`
	Steps     []string       `json:"steps,omitempty"`
	Notes     []string       `json:"notes,omitempty"`
}

// DoctorResult summarizes safe diagnostic checks.
type DoctorResult struct {
	Checks []DoctorCheck `json:"checks"`
}

// DoctorCheck is one doctor probe outcome.
type DoctorCheck struct {
	Name    string `json:"name"`
	Status  string `json:"status"`
	Message string `json:"message"`
	Hint    string `json:"hint,omitempty"`
}

// ObjectListResult is returned by piv diag object list.
type ObjectListResult struct {
	Objects []ObjectRecord `json:"objects"`
}

// ObjectRecord describes one known PIV object probe.
type ObjectRecord struct {
	Name    string `json:"name"`
	Tag     string `json:"tag"`
	Present bool   `json:"present"`
	Size    int    `json:"size,omitempty"`
}

// ObjectReadResult is returned by piv diag object read.
type ObjectReadResult struct {
	Name   string    `json:"name,omitempty"`
	Tag    string    `json:"tag"`
	Format string    `json:"format"`
	Data   string    `json:"data"`
	TLV    []TLVNode `json:"tlv,omitempty"`
}

// TLVDecodeResult contains a decoded BER-TLV tree.
type TLVDecodeResult struct {
	InputFormat string    `json:"input_format"`
	Nodes       []TLVNode `json:"nodes"`
}

// TLVNode is a recursive JSON-friendly TLV view.
type TLVNode struct {
	Tag         string    `json:"tag"`
	Length      int       `json:"length"`
	Constructed bool      `json:"constructed,omitempty"`
	ValueHex    string    `json:"value_hex,omitempty"`
	Children    []TLVNode `json:"children,omitempty"`
}

// APDUSendResult contains the outcome of raw APDU execution.
type APDUSendResult struct {
	Exchanges []APDUExchange `json:"exchanges"`
}

// APDUExchange describes one raw APDU command and response pair.
type APDUExchange struct {
	Command  string `json:"command"`
	Response string `json:"response"`
	Status   string `json:"status"`
}

// ConfigShowResult is returned by piv config show.
type ConfigShowResult struct {
	Path     string            `json:"path"`
	Resolved bool              `json:"resolved,omitempty"`
	Values   []ConfigValueView `json:"values"`
}

// ConfigValueView describes one config value and its origin.
type ConfigValueView struct {
	Key    string `json:"key"`
	Value  string `json:"value,omitempty"`
	Origin string `json:"origin,omitempty"`
}

// ConfigPathResult is returned by piv config path.
type ConfigPathResult struct {
	Path string `json:"path"`
}

// VersionResult is returned by piv version.
type VersionResult struct {
	Binary    string `json:"binary"`
	Version   string `json:"version"`
	Commit    string `json:"commit,omitempty"`
	BuildDate string `json:"build_date,omitempty"`
}
