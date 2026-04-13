# Project Guidelines

## Overview

Go module implementing the PIV (Personal Identity Verification) protocol over PC/SC smart card transport.

- Repository: `github.com/PeculiarVentures/piv-go`
- PC/SC binding: `github.com/ebfe/scard`
- CLI framework: `github.com/spf13/cobra`

## Architecture

```
Application Layer → PIV Client API → PIV Core → ISO 7816 (APDU + TLV) → PC/SC Transport → Smart Card
```

Packages:

- `pcsc/` — PC/SC transport wrapping `scard`, all direct scard calls isolated here
- `iso7816/` — APDU encoding/decoding, status words, BER-TLV parsing
- `piv/` — PIV protocol commands (SELECT, GET DATA, VERIFY PIN, GENERAL AUTHENTICATE, etc.)
- `adapters/` — Vendor-specific adapters and higher-level token operations (YubiKey, SafeNet)
- `internal/` — Shared internal utilities
- `cmd/piv/` — CLI utility using cobra

## Code Style

- Go standard formatting (`gofmt`)
- Exported types and functions must have doc comments
- Errors should be wrapped with context using `fmt.Errorf` or custom error types
- Keep packages focused: upper layers must not import `scard` directly
- Each package must have a `doc.go` file with a package-level doc comment describing its purpose

## Build and Test

```sh
go build ./...
go test ./...
go vet ./...
```

## Conventions

- Git commits follow Conventional Commits: `feat:`, `fix:`, `docs:`, `test:`, `chore:`, `refactor:`, `ci:`
- Commit messages in English
- Map SW1/SW2 status words to Go errors in `iso7816` package
- All vendor-specific behavior goes in `vendor/` adapters
- CLI must be thin — business logic lives in library packages

## Emulator and agent guidance

- Vendor-specific emulator implementations should be clearly identifiable by filename.
- Prefer naming emulator-only files with a suffix like `*_emulator.go`.
- Keep emulator helpers separate from production adapter code when possible.
- When working with emulator-related tasks, locate dedicated emulator files first and avoid mixing emulator logic into main adapter code.
