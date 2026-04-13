package app

import (
	"bufio"
	"fmt"
	"io"
	"strings"
)

// OperationPlan is the stable dry-run representation for destructive actions.
type OperationPlan struct {
	Operation   string   `json:"operation"`
	Credentials []string `json:"credentials,omitempty"`
	Effects     []string `json:"effects,omitempty"`
	Notes       []string `json:"notes,omitempty"`
}

// OperationPlanner creates preflight plans and handles confirmations.
type OperationPlanner struct {
	input  *bufio.Reader
	stderr io.Writer
}

// NewOperationPlanner creates a planner backed by the provided IO streams.
func NewOperationPlanner(input io.Reader, stderr io.Writer) *OperationPlanner {
	return &OperationPlanner{input: bufio.NewReader(input), stderr: stderr}
}

// Build constructs a new operation plan.
func (p *OperationPlanner) Build(operation string, credentials []string, effects []string, notes []string) *OperationPlan {
	return &OperationPlan{
		Operation:   operation,
		Credentials: append([]string(nil), credentials...),
		Effects:     append([]string(nil), effects...),
		Notes:       append([]string(nil), notes...),
	}
}

// Confirm enforces the --yes policy and prompts in interactive sessions.
func (p *OperationPlanner) Confirm(plan *OperationPlan, nonInteractive bool, yes bool) error {
	if plan == nil {
		return nil
	}
	if yes {
		return nil
	}
	if nonInteractive {
		return RefusedError("confirmation is required", "rerun the command with --yes after reviewing --dry-run output")
	}
	if p.stderr != nil {
		_, _ = fmt.Fprintf(p.stderr, "Proceed with %s? [y/N]: ", plan.Operation)
	}
	answer, err := p.input.ReadString('\n')
	if err != nil && err != io.EOF {
		return IOError("unable to read interactive confirmation", "rerun the command with --yes to skip the prompt", err)
	}
	answer = strings.ToLower(strings.TrimSpace(answer))
	if answer != "y" && answer != "yes" {
		return RefusedError("operation cancelled", "rerun the command with --yes after reviewing the preflight summary")
	}
	return nil
}
