package app

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"strings"

	"golang.org/x/term"
)

// SecretRequest describes one credential input source.
type SecretRequest struct {
	Label         string
	Prompt        string
	EnvVar        string
	ReadFromStdin bool
}

// CredentialResolver resolves secrets from env, stdin, or interactive prompts.
type CredentialResolver struct {
	reader      *bufio.Reader
	inputFile   *os.File
	stderr      io.Writer
	interactive bool
}

// NewCredentialResolver prepares a resolver for one command execution.
func NewCredentialResolver(input io.Reader, stderr io.Writer, interactive bool) *CredentialResolver {
	resolver := &CredentialResolver{reader: bufio.NewReader(input), stderr: stderr, interactive: interactive}
	if file, ok := input.(*os.File); ok {
		resolver.inputFile = file
	}
	return resolver
}

// IsInteractiveInput reports whether the provided reader is a terminal-backed file.
func IsInteractiveInput(input io.Reader) bool {
	file, ok := input.(*os.File)
	if !ok {
		return false
	}
	return term.IsTerminal(int(file.Fd()))
}

// ResolveString resolves one text secret.
func (r *CredentialResolver) ResolveString(request SecretRequest) (string, error) {
	if request.EnvVar != "" {
		if value := strings.TrimSpace(os.Getenv(request.EnvVar)); value != "" {
			return value, nil
		}
	}
	if request.ReadFromStdin {
		return r.readSecretLine(request.Label)
	}
	if r.interactive {
		prompt := request.Prompt
		if prompt == "" {
			prompt = fmt.Sprintf("Enter %s: ", request.Label)
		}
		return r.promptSecret(prompt)
	}
	hint := ""
	if request.EnvVar != "" {
		hint = fmt.Sprintf("provide %s through %s or use the matching --*-stdin flag", request.Label, request.EnvVar)
	} else {
		hint = fmt.Sprintf("provide %s through stdin or rerun interactively", request.Label)
	}
	return "", UsageError(fmt.Sprintf("%s is required", request.Label), hint)
}

// ResolveManagementKey resolves management key material from text input.
func (r *CredentialResolver) ResolveManagementKey(request SecretRequest) ([]byte, error) {
	value, err := r.ResolveString(request)
	if err != nil {
		return nil, err
	}
	value = strings.TrimSpace(value)
	normalizedHex := strings.ReplaceAll(strings.ReplaceAll(value, ":", ""), " ", "")
	if decoded, decodeErr := hex.DecodeString(normalizedHex); decodeErr == nil {
		switch len(decoded) {
		case 16, 24, 32:
			return decoded, nil
		}
	}
	raw := []byte(value)
	switch len(raw) {
	case 16, 24, 32:
		return raw, nil
	default:
		return nil, UsageError("invalid management key material", "provide a 16, 24, or 32 byte value, preferably as hexadecimal")
	}
}

func (r *CredentialResolver) readSecretLine(label string) (string, error) {
	if r.reader == nil {
		return "", UsageError(fmt.Sprintf("%s is required", label), "provide the secret through stdin")
	}
	line, err := r.reader.ReadString('\n')
	if err != nil && err != io.EOF {
		return "", IOError("unable to read stdin", "provide the required secret through stdin", err)
	}
	value := strings.TrimSpace(line)
	if value == "" {
		return "", UsageError(fmt.Sprintf("%s is required", label), "provide a non-empty value through stdin")
	}
	return value, nil
}

func (r *CredentialResolver) promptSecret(prompt string) (string, error) {
	if r.stderr != nil {
		_, _ = fmt.Fprint(r.stderr, prompt)
	}
	if r.inputFile != nil && term.IsTerminal(int(r.inputFile.Fd())) {
		secret, err := term.ReadPassword(int(r.inputFile.Fd()))
		if r.stderr != nil {
			_, _ = fmt.Fprintln(r.stderr)
		}
		if err != nil {
			return "", IOError("unable to read interactive input", "retry the command or use --non-interactive with env or stdin", err)
		}
		value := strings.TrimSpace(string(secret))
		if value == "" {
			return "", UsageError("secret input is required", "provide a non-empty value")
		}
		return value, nil
	}
	line, err := r.reader.ReadString('\n')
	if err != nil && err != io.EOF {
		return "", IOError("unable to read interactive input", "retry the command or use --non-interactive with env or stdin", err)
	}
	value := strings.TrimSpace(line)
	if value == "" {
		return "", UsageError("secret input is required", "provide a non-empty value")
	}
	return value, nil
}
