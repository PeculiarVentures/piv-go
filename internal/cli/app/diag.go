package app

import (
	"context"
	"encoding/hex"
	"fmt"
	"io"
	"strings"

	"github.com/PeculiarVentures/piv-go/iso7816"
	"github.com/PeculiarVentures/piv-go/piv"
)

// DoctorRequest configures piv doctor.
type DoctorRequest struct {
	Global     GlobalOptions
	WithSelect bool
}

// ObjectReadRequest configures piv diag object read.
type ObjectReadRequest struct {
	Global   GlobalOptions
	Selector string
	Format   string
}

// TLVDecodeRequest configures piv diag tlv decode.
type TLVDecodeRequest struct {
	InputPath string
}

// APDUSendRequest configures piv diag apdu send.
type APDUSendRequest struct {
	Global      GlobalOptions
	HexCommands []string
	Yes         bool
}

// DiagService exposes safe diagnostics and expert tooling.
type DiagService struct {
	targets *TargetResolver
	planner *OperationPlanner
	input   io.Reader
}

// NewDiagService creates a new diagnostics service.
func NewDiagService(targets *TargetResolver, planner *OperationPlanner, input io.Reader) *DiagService {
	return &DiagService{targets: targets, planner: planner, input: input}
}

// Doctor runs safe PC/SC and PIV readiness probes.
func (s *DiagService) Doctor(ctx context.Context, request DoctorRequest) (Response, error) {
	devices, err := s.targets.Discover(ctx)
	if err != nil {
		return Response{}, err
	}
	checks := make([]DoctorCheck, 0, 6)
	readyReaders := make([]string, 0)
	if len(devices) == 0 {
		checks = append(checks, DoctorCheck{Name: "pcsc", Status: "fail", Message: "no PC/SC readers are available", Hint: "connect a reader and rerun piv devices"})
	} else {
		checks = append(checks, DoctorCheck{Name: "pcsc", Status: "pass", Message: fmt.Sprintf("detected %d PC/SC reader(s)", len(devices))})
	}
	for _, device := range devices {
		if device.PIVReady {
			readyReaders = append(readyReaders, device.Reader)
		}
	}
	if len(readyReaders) == 0 {
		checks = append(checks, DoctorCheck{Name: "piv", Status: "fail", Message: "no ready PIV token was detected", Hint: "insert a token and rerun piv devices"})
	} else if len(readyReaders) == 1 {
		checks = append(checks, DoctorCheck{Name: "piv", Status: "pass", Message: fmt.Sprintf("ready PIV token detected in %s", readyReaders[0])})
	} else {
		checks = append(checks, DoctorCheck{Name: "piv", Status: "warn", Message: fmt.Sprintf("multiple ready PIV tokens detected (%d)", len(readyReaders)), Hint: "use --reader <name> to select one token explicitly"})
	}

	response := Response{Command: "doctor", Target: TargetSummary{}, Result: DoctorResult{Checks: checks}}
	if request.WithSelect || request.Global.Reader != "" || len(readyReaders) == 1 {
		target, resolveErr := s.targets.Resolve(ctx, request.Global)
		if resolveErr != nil {
			mapped := (&ErrorMapper{}).Map(resolveErr)
			doctorResult := response.Result.(DoctorResult)
			doctorResult.Checks = append(doctorResult.Checks, DoctorCheck{Name: "select", Status: "fail", Message: mapped.Message, Hint: mapped.Hint})
			response.Result = doctorResult
			return response, nil
		}
		defer func() { _ = target.Close() }()
		doctorResult := response.Result.(DoctorResult)
		doctorResult.Checks = append(doctorResult.Checks,
			DoctorCheck{Name: "select", Status: "pass", Message: fmt.Sprintf("selected the PIV application on %s", target.Summary.Reader)},
			DoctorCheck{Name: "adapter", Status: "pass", Message: fmt.Sprintf("resolved adapter %s", target.Summary.Adapter)},
		)
		response.Result = doctorResult
		response.Target = target.Summary
		response.traceLines = target.TraceLines()
	}
	return response, nil
}

// ObjectList probes known standard PIV objects.
func (s *DiagService) ObjectList(ctx context.Context, global GlobalOptions) (Response, error) {
	target, err := s.targets.Resolve(ctx, global)
	if err != nil {
		return Response{}, err
	}
	defer func() { _ = target.Close() }()

	objects := make([]ObjectRecord, 0, len(piv.KnownObjects()))
	for _, object := range piv.KnownObjects() {
		data, readErr := target.Session.Client.GetData(object.Tag)
		if readErr != nil {
			objects = append(objects, ObjectRecord{Name: object.Name, Tag: strings.ToUpper(hex.EncodeToString(iso7816.EncodeTag(object.Tag))), Present: false})
			continue
		}
		objects = append(objects, ObjectRecord{Name: object.Name, Tag: strings.ToUpper(hex.EncodeToString(iso7816.EncodeTag(object.Tag))), Present: true, Size: len(data)})
	}
	response := Response{Command: "diag-object-list", Target: target.Summary, Result: ObjectListResult{Objects: objects}}
	response.traceLines = target.TraceLines()
	return response, nil
}

// ObjectRead reads one object by name or tag.
func (s *DiagService) ObjectRead(ctx context.Context, request ObjectReadRequest) (Response, error) {
	tag, name, err := ParseObjectSelector(request.Selector)
	if err != nil {
		return Response{}, err
	}
	format := strings.ToLower(strings.TrimSpace(request.Format))
	if format == "" {
		format = "hex"
	}
	if format != "hex" && format != "json" {
		return Response{}, UsageError(fmt.Sprintf("unsupported object format %q", request.Format), "use hex or json")
	}
	target, err := s.targets.Resolve(ctx, request.Global)
	if err != nil {
		return Response{}, err
	}
	defer func() { _ = target.Close() }()

	data, err := target.Session.Client.GetData(tag)
	if err != nil {
		return Response{}, NotFoundError("the requested object is not present", "inspect available objects with piv diag object list", err)
	}
	result := ObjectReadResult{Name: name, Tag: strings.ToUpper(hex.EncodeToString(iso7816.EncodeTag(tag))), Format: format, Data: strings.ToUpper(hex.EncodeToString(data))}
	if format == "json" {
		nodes, decodeErr := BuildTLVNodes(data)
		if decodeErr == nil {
			result.TLV = nodes
		}
	}
	response := Response{Command: "diag-object-read", Target: target.Summary, Result: result}
	response.traceLines = target.TraceLines()
	return response, nil
}

// TLVDecode decodes BER-TLV input from a file or stdin.
func (s *DiagService) TLVDecode(_ context.Context, request TLVDecodeRequest) (Response, error) {
	path := request.InputPath
	if path == "" {
		path = "-"
	}
	data, err := ReadInputFile(path, s.input)
	if err != nil {
		return Response{}, err
	}
	nodes, err := BuildTLVNodes(data)
	if err != nil {
		return Response{}, err
	}
	return Response{Command: "diag-tlv-decode", Target: TargetSummary{}, Result: TLVDecodeResult{InputFormat: "ber-tlv", Nodes: nodes}}, nil
}

// APDUSend sends expert-mode raw APDU commands.
func (s *DiagService) APDUSend(ctx context.Context, request APDUSendRequest) (Response, error) {
	if len(request.HexCommands) == 0 {
		return Response{}, UsageError("at least one APDU is required", "provide one or more commands with --hex")
	}
	plan := s.planner.Build("send raw APDU commands", nil, []string{"send raw APDU bytes directly to the token"}, []string{"expert mode only; responses may expose low-level token details"})
	if err := s.planner.Confirm(plan, request.Global.NonInteractive, request.Yes); err != nil {
		return Response{}, err
	}
	target, err := s.targets.Resolve(ctx, request.Global)
	if err != nil {
		return Response{}, err
	}
	defer func() { _ = target.Close() }()

	exchanges := make([]APDUExchange, 0, len(request.HexCommands))
	for _, commandHex := range request.HexCommands {
		raw, decodeErr := hex.DecodeString(strings.TrimSpace(strings.ReplaceAll(commandHex, " ", "")))
		if decodeErr != nil {
			return Response{}, UsageError(fmt.Sprintf("invalid APDU %q", commandHex), "provide hexadecimal APDU bytes")
		}
		command, parseErr := iso7816.ParseCommand(raw)
		if parseErr != nil {
			return Response{}, UsageError(fmt.Sprintf("invalid APDU %q", commandHex), "provide a valid ISO 7816 command APDU")
		}
		resp, execErr := target.Session.Client.Execute(command)
		if execErr != nil {
			return Response{}, execErr
		}
		responseBytes := append([]byte(nil), resp.Data...)
		responseBytes = append(responseBytes, resp.SW1, resp.SW2)
		exchanges = append(exchanges, APDUExchange{
			Command:  strings.ToUpper(hex.EncodeToString(raw)),
			Response: strings.ToUpper(hex.EncodeToString(responseBytes)),
			Status:   fmt.Sprintf("%04X", resp.StatusWord()),
		})
	}
	response := Response{Command: "diag-apdu-send", Target: target.Summary, Result: APDUSendResult{Exchanges: exchanges}}
	response.traceLines = target.TraceLines()
	return response, nil
}
