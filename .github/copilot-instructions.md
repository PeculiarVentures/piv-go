# Project Guidelines

## Overview

`piv-go` is a layered Go module and CLI for working with PIV smart cards over
PC/SC transport.

- Module: `github.com/PeculiarVentures/piv-go`
- PC/SC binding: `github.com/ebfe/scard`
- CLI framework: `github.com/spf13/cobra`

## Architecture

```text
Application Layer -> PIV Client API -> PIV Core -> ISO 7816 -> PC/SC Transport -> Smart Card
```

Primary package responsibilities:

- `pcsc/` owns all direct interaction with `scard`
- `iso7816/` owns APDU encoding, responses, status words, and TLV parsing
- `piv/` owns protocol commands and card-facing PIV operations
- `adapters/` owns vendor-aware behavior and higher-level token workflows
- `emulator/` owns emulator-backed behavior used by tests and diagnostics
- `cmd/piv/` owns the CLI command surface
- `internal/cli/app/` owns CLI orchestration, output formatting, config, and mutation planning

## Always-On Rules

- Keep the layer boundaries intact. Do not import `scard` outside `pcsc/`.
- Keep vendor-specific logic in `adapters/` packages, not in `piv/`, `iso7816/`,
  or the CLI command handlers.
- Keep the CLI thin. Reusable business logic belongs in library packages or
  `internal/cli/app/`.
- Prefer existing helper types, result models, and error mapping patterns over
  introducing a new command-local style.
- Use Go standard formatting and keep exported API changes documented.

## Safety and Operational Guardrails

- Assume real token operations can be destructive.
- For destructive flows such as `setup`, `mgm rotate`, `key generate`,
  `key delete`, `cert import`, `cert delete`, and reset operations, preserve the
  current preflight and confirmation model.
- Do not remove or weaken `--dry-run`, `--yes`, `--non-interactive`, or similar
  safety behavior without an explicit request.
- Treat trace output and credential material as sensitive. Keep secrets out of
  normal command output, examples, and tests unless a test is explicitly about
  secret handling.

## Testing and Validation

- Minimum validation for code changes is `go test ./...`.
- When changing package APIs or shared behavior, also run `go build ./...` and
  `go vet ./...`.
- Prefer emulator-backed tests and existing fake context helpers before
  introducing hardware-dependent tests.
- When changing CLI JSON output, keep stdout reserved for JSON and send
  warnings, prompts, and trace output to stderr.

## Git Workflow

- Keep commits focused on one logical change when possible.
- Before committing, review the diff and avoid staging unrelated files.
- Use English commit messages.
- Prefer Conventional Commit prefixes such as `feat:`, `fix:`, `docs:`,
  `test:`, `refactor:`, `chore:`, and `ci:` when they match the change.
- Do not create a commit automatically unless the user asked for a commit or the
  task explicitly includes producing one.

## Repository-Specific Notes for Agents

- SafeNet and YubiKey support lives under `adapters/safenet/` and
  `adapters/yubikey/`.
- Built-in adapter registration lives under `adapters/all/`.
- Emulator-specific implementations should remain easy to identify, typically
  with names such as `*_emulator.go`.
- The emulator is useful for tests and smoke validation, but it does not imply
  exact parity with every real token or firmware.
