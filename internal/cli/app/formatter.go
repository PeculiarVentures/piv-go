package app

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"text/tabwriter"
)

// Formatter renders human and JSON output for all commands.
type Formatter struct{}

// WriteResponse renders a success response to stdout and stderr.
func (f *Formatter) WriteResponse(stdout io.Writer, stderr io.Writer, response Response, options GlobalOptions) error {
	if options.JSON {
		encoder := json.NewEncoder(stdout)
		encoder.SetEscapeHTML(false)
		if err := encoder.Encode(response); err != nil {
			return err
		}
		return f.writeTrace(stderr, response.traceLines, options)
	}

	switch result := response.Result.(type) {
	case DevicesResult:
		f.renderDevices(stdout, result)
	case InfoResult:
		f.renderInfo(stdout, response.Target, result)
	case SlotListResult:
		f.renderSlotTable(stdout, result.Slots)
	case SlotShowResult:
		f.renderSlotTable(stdout, []SlotView{result.Slot})
	case ArtifactResult:
		if result.Path != "" {
			_, _ = fmt.Fprintf(stderr, "%s written to %s\n", artifactLabel(result.Kind), result.Path)
		} else if len(response.rawOutput) > 0 {
			_, _ = stdout.Write(response.rawOutput)
		} else if result.Data != "" {
			_, _ = fmt.Fprintln(stdout, result.Data)
		}
	case VerificationResult:
		f.renderVerification(stdout, result)
	case MutationResult:
		if result.DryRun && result.Plan != nil {
			f.renderPlan(stdout, *result.Plan)
		} else {
			_, _ = fmt.Fprintln(stderr, f.mutationSummary(result, response.Target))
		}
	case CredentialStatus:
		f.renderCredentialStatus(stdout, response.Command, result)
	case DoctorResult:
		f.renderDoctor(stdout, result)
	case ObjectListResult:
		f.renderObjectList(stdout, result)
	case ObjectReadResult:
		f.renderObjectRead(stdout, result)
	case TLVDecodeResult:
		f.renderTLVDecode(stdout, result)
	case APDUSendResult:
		f.renderAPDUSend(stdout, result)
	case ConfigShowResult:
		f.renderConfig(stdout, result)
	case ConfigPathResult:
		_, _ = fmt.Fprintln(stdout, result.Path)
	case VersionResult:
		f.renderVersion(stdout, result)
	default:
		_, _ = fmt.Fprintf(stdout, "%v\n", result)
	}

	for _, warning := range response.Warnings {
		_, _ = fmt.Fprintf(stderr, "Warning: %s\n", warning.Message)
	}
	return f.writeTrace(stderr, response.traceLines, options)
}

// WriteError renders a normalized CLI error.
func (f *Formatter) WriteError(stdout io.Writer, stderr io.Writer, cliErr *CLIError, jsonOutput bool) error {
	if cliErr == nil {
		return nil
	}
	if jsonOutput {
		payload := struct {
			Error *CLIError `json:"error"`
		}{Error: cliErr}
		encoder := json.NewEncoder(stdout)
		encoder.SetEscapeHTML(false)
		return encoder.Encode(payload)
	}
	if _, err := fmt.Fprintf(stderr, "Error: %s\n", cliErr.Message); err != nil {
		return err
	}
	if cliErr.Hint != "" {
		if _, err := fmt.Fprintf(stderr, "Hint: %s\n", cliErr.Hint); err != nil {
			return err
		}
	}
	return nil
}

func (f *Formatter) renderDevices(writer io.Writer, result DevicesResult) {
	table := tabwriter.NewWriter(writer, 0, 0, 2, ' ', 0)
	_, _ = fmt.Fprintln(table, "READER\tTOKEN\tADAPTER\tSTATUS")
	for _, device := range result.Devices {
		token := "-"
		if device.PIVReady {
			token = "PIV"
		}
		adapter := device.Adapter
		if adapter == "" {
			adapter = "-"
		}
		_, _ = fmt.Fprintf(table, "%s\t%s\t%s\t%s\n", device.Reader, token, adapter, device.Status)
	}
	_ = table.Flush()
}

func (f *Formatter) renderInfo(writer io.Writer, target TargetSummary, result InfoResult) {
	if result.Label != "" {
		_, _ = fmt.Fprintf(writer, "Token: %s\n", result.Label)
	}
	if target.Reader != "" {
		_, _ = fmt.Fprintf(writer, "Reader: %s\n", target.Reader)
	}
	if target.Adapter != "" {
		_, _ = fmt.Fprintf(writer, "Adapter: %s\n", target.Adapter)
	}
	if result.Serial != "" {
		_, _ = fmt.Fprintf(writer, "Serial: %s\n", result.Serial)
	}
	if result.CHUID.FASCN != "" || result.CHUID.GUID != "" || result.CHUID.Expiration != "" {
		_, _ = fmt.Fprintln(writer, "CHUID:")
		if result.CHUID.FASCN != "" {
			_, _ = fmt.Fprintf(writer, "  FASC-N: %s\n", result.CHUID.FASCN)
		}
		if result.CHUID.GUID != "" {
			_, _ = fmt.Fprintf(writer, "  GUID: %s\n", result.CHUID.GUID)
		}
		if result.CHUID.Expiration != "" {
			_, _ = fmt.Fprintf(writer, "  Expiration: %s\n", result.CHUID.Expiration)
		}
	}
	if result.State != "" {
		_, _ = fmt.Fprintf(writer, "State: %s\n", result.State)
	}
	if len(result.Capabilities) > 0 {
		_, _ = fmt.Fprintln(writer, "Capabilities:")
		for _, item := range result.Capabilities {
			line := fmt.Sprintf("  %s: %s", item.ID, item.Support)
			if item.Notes != "" {
				line += fmt.Sprintf(" (%s)", item.Notes)
			}
			_, _ = fmt.Fprintln(writer, line)
		}
	}
	if len(result.Slots) > 0 {
		_, _ = fmt.Fprintln(writer, "Slots:")
		f.renderSlotTable(writer, result.Slots)
	}
	if result.Credentials.PIN.Supported || result.Credentials.PUK.Supported || result.Credentials.PUK.Note != "" {
		_, _ = fmt.Fprintln(writer, "Credentials:")
		if result.Credentials.PIN.Supported {
			_, _ = fmt.Fprintf(writer, "  PIN retries remaining: %d\n", result.Credentials.PIN.RetriesRemaining)
		}
		if result.Credentials.PUK.Supported {
			_, _ = fmt.Fprintf(writer, "  PUK retries remaining: %d\n", result.Credentials.PUK.RetriesRemaining)
		} else if result.Credentials.PUK.Note != "" {
			_, _ = fmt.Fprintf(writer, "  PUK: %s\n", result.Credentials.PUK.Note)
		}
	}
	for _, note := range result.Notes {
		_, _ = fmt.Fprintf(writer, "Note: %s\n", note)
	}
}

func (f *Formatter) renderSlotTable(writer io.Writer, slots []SlotView) {
	table := tabwriter.NewWriter(writer, 0, 0, 2, ' ', 0)
	_, _ = fmt.Fprintln(table, "SLOT\tHEX\tKEY\tCERT")
	for _, slot := range slots {
		key := "empty"
		if slot.KeyPresent {
			key = slot.KeyAlgorithm
		}
		cert := "empty"
		if slot.CertPresent {
			cert = slot.CertLabel
		}
		_, _ = fmt.Fprintf(table, "%s\t%s\t%s\t%s\n", slot.Name, slot.Hex, key, cert)
	}
	_ = table.Flush()
}

func (f *Formatter) renderVerification(writer io.Writer, result VerificationResult) {
	if result.Algorithm != "" {
		_, _ = fmt.Fprintf(writer, "%s verified (%s)\n", humanSubject(result.Subject), result.Algorithm)
		return
	}
	_, _ = fmt.Fprintf(writer, "%s verified\n", humanSubject(result.Subject))
}

func (f *Formatter) renderCredentialStatus(writer io.Writer, command string, status CredentialStatus) {
	name := "Credential"
	if strings.Contains(command, "pin") {
		name = "PIN"
	}
	if strings.Contains(command, "puk") {
		name = "PUK"
	}
	if !status.Supported {
		_, _ = fmt.Fprintf(writer, "%s status: %s\n", name, status.Note)
		return
	}
	if status.Blocked {
		_, _ = fmt.Fprintf(writer, "%s is blocked\n", name)
		return
	}
	_, _ = fmt.Fprintf(writer, "%s retries remaining: %d\n", name, status.RetriesRemaining)
}

func (f *Formatter) renderDoctor(writer io.Writer, result DoctorResult) {
	for _, check := range result.Checks {
		_, _ = fmt.Fprintf(writer, "[%s] %s: %s\n", strings.ToUpper(check.Status), check.Name, check.Message)
		if check.Hint != "" {
			_, _ = fmt.Fprintf(writer, "  Hint: %s\n", check.Hint)
		}
	}
}

func (f *Formatter) renderObjectList(writer io.Writer, result ObjectListResult) {
	table := tabwriter.NewWriter(writer, 0, 0, 2, ' ', 0)
	_, _ = fmt.Fprintln(table, "NAME\tTAG\tSTATE\tSIZE")
	for _, object := range result.Objects {
		state := "absent"
		if object.Present {
			state = "present"
		}
		size := "-"
		if object.Size > 0 {
			size = fmt.Sprintf("%d", object.Size)
		}
		_, _ = fmt.Fprintf(table, "%s\t%s\t%s\t%s\n", object.Name, object.Tag, state, size)
	}
	_ = table.Flush()
}

func (f *Formatter) renderObjectRead(writer io.Writer, result ObjectReadResult) {
	if result.Format == "json" && len(result.TLV) > 0 {
		_, _ = fmt.Fprintf(writer, "Object: %s (%s)\n", fallback(result.Name, "unknown"), result.Tag)
		for _, node := range result.TLV {
			renderTLVNode(writer, node, 0)
		}
		return
	}
	_, _ = fmt.Fprintln(writer, result.Data)
}

func (f *Formatter) renderTLVDecode(writer io.Writer, result TLVDecodeResult) {
	for _, node := range result.Nodes {
		renderTLVNode(writer, node, 0)
	}
}

func (f *Formatter) renderAPDUSend(writer io.Writer, result APDUSendResult) {
	for _, exchange := range result.Exchanges {
		_, _ = fmt.Fprintf(writer, "APDU -> %s\n", exchange.Command)
		_, _ = fmt.Fprintf(writer, "APDU <- %s [%s]\n", exchange.Response, exchange.Status)
	}
}

func (f *Formatter) renderConfig(writer io.Writer, result ConfigShowResult) {
	table := tabwriter.NewWriter(writer, 0, 0, 2, ' ', 0)
	if result.Resolved {
		_, _ = fmt.Fprintln(table, "KEY\tVALUE\tORIGIN")
		for _, item := range result.Values {
			_, _ = fmt.Fprintf(table, "%s\t%s\t%s\n", item.Key, item.Value, item.Origin)
		}
	} else {
		_, _ = fmt.Fprintln(table, "KEY\tVALUE")
		for _, item := range result.Values {
			_, _ = fmt.Fprintf(table, "%s\t%s\n", item.Key, item.Value)
		}
	}
	_ = table.Flush()
	_, _ = fmt.Fprintf(writer, "Path: %s\n", result.Path)
}

func (f *Formatter) renderVersion(writer io.Writer, result VersionResult) {
	_, _ = fmt.Fprintf(writer, "%s %s\n", result.Binary, result.Version)
	if result.Commit != "" {
		_, _ = fmt.Fprintf(writer, "Commit: %s\n", result.Commit)
	}
	if result.BuildDate != "" {
		_, _ = fmt.Fprintf(writer, "BuildDate: %s\n", result.BuildDate)
	}
}

func (f *Formatter) renderPlan(writer io.Writer, plan OperationPlan) {
	_, _ = fmt.Fprintf(writer, "Plan: %s\n", plan.Operation)
	if len(plan.Credentials) > 0 {
		_, _ = fmt.Fprintln(writer, "Credentials:")
		for _, credential := range plan.Credentials {
			_, _ = fmt.Fprintf(writer, "  - %s\n", credential)
		}
	}
	if len(plan.Effects) > 0 {
		_, _ = fmt.Fprintln(writer, "Effects:")
		for _, effect := range plan.Effects {
			_, _ = fmt.Fprintf(writer, "  - %s\n", effect)
		}
	}
	if len(plan.Notes) > 0 {
		_, _ = fmt.Fprintln(writer, "Notes:")
		for _, note := range plan.Notes {
			_, _ = fmt.Fprintf(writer, "  - %s\n", note)
		}
	}
}

func (f *Formatter) mutationSummary(result MutationResult, target TargetSummary) string {
	switch result.Action {
	case "cert-import":
		return "certificate imported"
	case "cert-delete":
		return "certificate deleted"
	case "key-generate":
		if result.Algorithm != "" {
			return fmt.Sprintf("key generated (%s)", result.Algorithm)
		}
		return "key generated"
	case "key-delete":
		return "key deleted"
	case "pin-change":
		return "PIN changed"
	case "pin-unblock":
		return "PIN unblocked"
	case "puk-change":
		return "PUK changed"
	case "mgm-rotate":
		if result.Algorithm != "" {
			return fmt.Sprintf("management key rotated (%s)", result.Algorithm)
		}
		return "management key rotated"
	case "setup-init":
		return "token initialized"
	case "setup-reset":
		return "token reset"
	case "setup-reset-slot":
		return "slot reset"
	default:
		return fallback(result.Action, "operation completed")
	}
}

func (f *Formatter) writeTrace(stderr io.Writer, lines []string, options GlobalOptions) error {
	if options.Trace == TraceOff || len(lines) == 0 {
		return nil
	}
	if options.TraceFile == "" || options.TraceFile == "stderr" {
		for _, line := range lines {
			if _, err := fmt.Fprintln(stderr, line); err != nil {
				return err
			}
		}
		return nil
	}
	file, err := os.Create(options.TraceFile)
	if err != nil {
		return err
	}
	defer func() { _ = file.Close() }()
	for _, line := range lines {
		if _, err := fmt.Fprintln(file, line); err != nil {
			return err
		}
	}
	return nil
}

func renderTLVNode(writer io.Writer, node TLVNode, depth int) {
	indent := strings.Repeat("  ", depth)
	line := fmt.Sprintf("%s%s len=%d", indent, node.Tag, node.Length)
	if !node.Constructed && node.ValueHex != "" {
		line += fmt.Sprintf(" value=%s", node.ValueHex)
	}
	_, _ = fmt.Fprintln(writer, line)
	for _, child := range node.Children {
		renderTLVNode(writer, child, depth+1)
	}
}

func artifactLabel(kind string) string {
	switch kind {
	case "certificate":
		return "certificate"
	case "public-key":
		return "public key"
	case "signature":
		return "signature"
	case "challenge-response":
		return "challenge response"
	default:
		return kind
	}
}

func humanSubject(subject string) string {
	switch subject {
	case "pin":
		return "PIN"
	case "management-key":
		return "management key"
	default:
		return subject
	}
}

func fallback(value string, defaultValue string) string {
	if value != "" {
		return value
	}
	return defaultValue
}
