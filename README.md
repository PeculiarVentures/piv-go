# piv-go

`piv-go` is a Go module and CLI for working with PIV (Personal Identity Verification) smart cards over PC/SC. It provides a layered library for ISO 7816 and PIV operations, vendor-aware adapters for common tokens, and a task-oriented `piv` command-line interface.

The repository is intended for developers and operators who need to inspect tokens, read and manage certificates, verify or rotate credentials, generate keys, and run targeted diagnostics without dropping to raw APDU tooling unless they choose to.

## What is included

- Go packages for ISO 7816 APDU/TLV handling, PIV commands, PC/SC transport, emulator flows, and vendor adapters.
- A `piv` CLI for reader discovery, token inspection, certificate and key operations, credential workflows, and diagnostics.
- Built-in vendor adapters for SafeNet/eToken and YubiKey PIV tokens.
- Emulator-backed tests for core library and CLI flows.

## Repository layout

- `pcsc/` implements the PC/SC transport layer and isolates direct `scard` calls.
- `iso7816/` implements APDU encoding, response parsing, status handling, and BER-TLV utilities.
- `piv/` implements the PIV protocol client and high-level token operations.
- `adapters/` contains vendor-neutral helpers and vendor-specific adapters.
- `emulator/` contains emulator-backed support used in tests and diagnostics.
- `cmd/piv/` contains the public CLI.

Additional public documentation:

- [docs/architecture.md](docs/architecture.md)
- [docs/CLI.md](docs/CLI.md)

## Requirements

- Go 1.25 or newer.
- A PC/SC runtime and a compatible reader driver.
- A PIV-capable token for real device operations.

Platform notes:

- macOS: the PC/SC framework is available as part of the operating system.
- Linux: install `pcsc-lite`, the development headers (`libpcsclite-dev` on Debian/Ubuntu), and `pkg-config` before building.
- Windows: install the vendor reader driver and ensure the Smart Card service is enabled.

The transport layer depends on `github.com/ebfe/scard`, so missing PC/SC headers or runtime services will break builds or runtime discovery even if the Go toolchain is installed correctly.

## Build and test

```sh
go build ./...
go test ./...
go vet ./...
```

Run the CLI directly from the module root:

```sh
go run ./cmd/piv --help
```

## CLI quick start

Discover readers and detect whether a token is PIV-ready:

```sh
go run ./cmd/piv devices
```

Inspect the selected token:

```sh
go run ./cmd/piv info --reader "YubiKey 5C NFC"
go run ./cmd/piv slot list --reader "YubiKey 5C NFC"
```

Export public artifacts:

```sh
go run ./cmd/piv cert export auth --reader "YubiKey 5C NFC" --out auth-cert.pem
go run ./cmd/piv key public auth --reader "YubiKey 5C NFC" --out auth-pub.pem
```

Run safe diagnostics before attempting a mutation:

```sh
go run ./cmd/piv doctor --reader "YubiKey 5C NFC" --with-select
```

Use machine-readable output when automating:

```sh
go run ./cmd/piv info --reader "YubiKey 5C NFC" --json
```

See [docs/CLI.md](docs/CLI.md) for the full command map, output conventions, and destructive-operation guidance.

## Library example

```go
package main

import (
    "fmt"
    "log"

    "github.com/PeculiarVentures/piv-go/pcsc"
    "github.com/PeculiarVentures/piv-go/piv"
)

func main() {
    ctx, err := pcsc.NewContext()
    if err != nil {
        log.Fatal(err)
    }
    defer ctx.Release()

    card, err := ctx.Connect("YubiKey 5C NFC")
    if err != nil {
        log.Fatal(err)
    }
    defer card.Close()

    client := piv.NewClient(card)
    if err := client.Select(); err != nil {
        log.Fatal(err)
    }

    certDER, err := client.GetCertificate(piv.SlotAuthentication)
    if err != nil {
        log.Fatal(err)
    }

    fmt.Printf("authentication certificate is %d bytes\n", len(certDER))
}
```

## Security and operational caveats

- Real hardware operations can be destructive. Review `setup`, `mgm`, `key delete`, `key generate`, and `cert delete` commands before using them on a live token.
- SafeNet and YubiKey support includes vendor-specific handling for factory-default credentials and reset flows. Treat those defaults as onboarding aids for uninitialized devices, not as acceptable production settings.
- APDU tracing can capture credential material and token metadata. If you use `--trace` or store debug output, keep it out of shell history, issue trackers, and public archives.
- The emulator is useful for tests and smoke validation, but it is not a full replacement for vendor firmware behavior.

## License

This project is licensed under the Apache License 2.0. See [LICENSE](LICENSE).
