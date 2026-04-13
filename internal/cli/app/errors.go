package app

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"regexp"
	"strings"

	"github.com/PeculiarVentures/piv-go/adapters"
	"github.com/PeculiarVentures/piv-go/iso7816"
	"github.com/PeculiarVentures/piv-go/pcsc"
)

var wrongPINPattern = regexp.MustCompile(`wrong pin,?\s*(\d+) retries remaining`)

// ExitError is returned by the command layer after output has been rendered.
type ExitError struct {
	Code int
}

func (e *ExitError) Error() string {
	return fmt.Sprintf("exit code %d", e.Code)
}

// CLIError is the normalized user-facing error model.
type CLIError struct {
	Code     string `json:"code"`
	Message  string `json:"message"`
	Hint     string `json:"hint,omitempty"`
	ExitCode int    `json:"-"`
	Cause    error  `json:"-"`
}

func (e *CLIError) Error() string {
	if e == nil {
		return ""
	}
	return e.Message
}

// Unwrap exposes the underlying cause for errors.As and errors.Is.
func (e *CLIError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Cause
}

// ErrorMapper translates low-level errors into the stable CLI error contract.
type ErrorMapper struct{}

// Map normalizes an arbitrary execution error.
func (m *ErrorMapper) Map(err error) *CLIError {
	if err == nil {
		return nil
	}
	var cliErr *CLIError
	if errors.As(err, &cliErr) {
		return cliErr
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return TransportError("the operation timed out", "increase --timeout or rerun with --trace ops", err)
	}
	var pathErr *fs.PathError
	if errors.As(err, &pathErr) {
		return IOError("local file operation failed", "check the file path and permissions", err)
	}
	var pcscErr *pcsc.Error
	if errors.As(err, &pcscErr) {
		return TransportError("smart card transport failed", "rerun with piv doctor or specify --reader explicitly", err)
	}
	if errors.Is(err, adapters.ErrInitializationNotSupported) {
		return UnsupportedError("initialization is not supported on the selected token", "use piv info to inspect token capabilities")
	}
	if errors.Is(err, adapters.ErrUnsupportedToken) {
		return UnsupportedError("the selected token is not supported by the available adapters", "rerun with --adapter standard only if you need standard PIV access")
	}
	if errors.Is(err, adapters.ErrSerialNumberUnsupported) {
		return UnsupportedError("serial number is not available on the selected token", "rerun with piv info --sections summary")
	}
	if errors.Is(err, adapters.ErrTokenLabelUnsupported) {
		return UnsupportedError("token label is not available on the selected token", "rerun with piv info --sections summary")
	}
	if status, ok := iso7816.StatusWordFromError(err); ok {
		switch status {
		case iso7816.SwFileNotFound, iso7816.SwReferencedDataNotFound:
			return NotFoundError("the requested slot or object is not present", "inspect the token with piv slot list or piv diag object list", err)
		case iso7816.SwSecurityNotSatisfied:
			return AuthError("the token rejected the supplied credential", "verify the secret and retry", err)
		case iso7816.SwAuthBlocked:
			return AuthError("the credential is blocked", "use piv pin status or piv puk status to inspect retry counters", err)
		case iso7816.SwConditionsNotMet:
			return RefusedError("the token refused the requested operation", "check whether the token policy requires additional authentication")
		case iso7816.SwWrongData, iso7816.SwWrongLength, iso7816.SwIncorrectP1P2:
			return UsageError("the request is not valid for the selected token", "double-check the command arguments and input data")
		case iso7816.SwInsNotSupported, iso7816.SwClaNotSupported:
			return UnsupportedError("the selected token does not support this operation", "inspect capabilities with piv info")
		default:
			return TransportError("card communication failed", "rerun with --trace apdu to inspect the exchange", err)
		}
	}
	lower := strings.ToLower(err.Error())
	if match := wrongPINPattern.FindStringSubmatch(lower); len(match) == 2 {
		return AuthError("PIN verification failed", fmt.Sprintf("verify the PIN and retry; %s retries remain", match[1]), err)
	}
	switch {
	case strings.Contains(lower, "wrong pin"):
		return AuthError("PIN verification failed", "verify the PIN and retry", err)
	case strings.Contains(lower, "management authenticate") || strings.Contains(lower, "management key") && strings.Contains(lower, "authenticate"):
		return AuthError("management key authentication failed", "verify the management key and algorithm", err)
	case strings.Contains(lower, "unsupported") || strings.Contains(lower, "not supported"):
		return UnsupportedError("the selected token does not support this operation", "inspect capabilities with piv info", err)
	case strings.Contains(lower, "confirmation"):
		return RefusedError("confirmation is required", "rerun with --yes or confirm the operation interactively")
	case strings.Contains(lower, "slot") && strings.Contains(lower, "not present"):
		return NotFoundError("the requested slot is empty", "inspect slot state with piv slot show <slot>", err)
	default:
		return InternalError("unexpected internal error", "rerun with --trace ops and inspect the failure", err)
	}
}

// UsageError creates a validation error mapped to exit code 1.
func UsageError(message string, hint string) *CLIError {
	return &CLIError{Code: "usage-error", Message: message, Hint: hint, ExitCode: 1}
}

// TargetError creates a target selection error mapped to exit code 2.
func TargetError(code string, message string, hint string) *CLIError {
	return &CLIError{Code: code, Message: message, Hint: hint, ExitCode: 2}
}

// AuthError creates an authentication error mapped to exit code 3.
func AuthError(message string, hint string, cause ...error) *CLIError {
	return newCLIError("authentication-failed", message, hint, 3, cause...)
}

// UnsupportedError creates a capability error mapped to exit code 4.
func UnsupportedError(message string, hint string, cause ...error) *CLIError {
	return newCLIError("unsupported-capability", message, hint, 4, cause...)
}

// NotFoundError creates a not-found error mapped to exit code 5.
func NotFoundError(message string, hint string, cause ...error) *CLIError {
	return newCLIError("not-found", message, hint, 5, cause...)
}

// RefusedError creates a policy or confirmation refusal mapped to exit code 6.
func RefusedError(message string, hint string, cause ...error) *CLIError {
	return newCLIError("operation-refused", message, hint, 6, cause...)
}

// TransportError creates a transport error mapped to exit code 7.
func TransportError(message string, hint string, cause ...error) *CLIError {
	return newCLIError("transport-failure", message, hint, 7, cause...)
}

// IOError creates a local input or output error mapped to exit code 8.
func IOError(message string, hint string, cause ...error) *CLIError {
	return newCLIError("io-error", message, hint, 8, cause...)
}

// InternalError creates an unexpected error mapped to exit code 9.
func InternalError(message string, hint string, cause ...error) *CLIError {
	return newCLIError("internal-error", message, hint, 9, cause...)
}

func newCLIError(code string, message string, hint string, exitCode int, cause ...error) *CLIError {
	var wrapped error
	if len(cause) > 0 {
		wrapped = cause[0]
	}
	return &CLIError{Code: code, Message: message, Hint: hint, ExitCode: exitCode, Cause: wrapped}
}
