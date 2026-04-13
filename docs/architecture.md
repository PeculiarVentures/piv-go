# Architecture Overview

`piv-go` is organized as a layered Go module so that transport, protocol, vendor behavior, and user-facing tooling stay separated.

```text
Application Layer -> PIV Client API -> PIV Core -> ISO 7816 -> PC/SC Transport -> Smart Card
```

## Packages

- `pcsc/` wraps `github.com/ebfe/scard` and contains the only direct PC/SC calls.
- `iso7816/` handles command encoding, response parsing, status words, and BER-TLV structures.
- `piv/` exposes the public PIV client and command helpers built on top of a card transport.
- `adapters/` adds vendor-aware behavior and higher-level token workflows.
- `emulator/` provides emulator-backed helpers used by tests and some diagnostics.
- `cmd/piv/` exposes the public CLI surface.
- `internal/cli/app/` contains CLI-only orchestration such as output formatting, target resolution, and mutation planning.

## Design constraints

- Upper layers should not import `scard` directly; all transport-specific behavior belongs in `pcsc/`.
- Vendor-specific flows belong in adapter packages, not in the core `piv/` client.
- The CLI stays thin. Business logic should be reusable from library packages or CLI app services.
- Emulator behavior is kept distinct from production adapter code when practical.

## Runtime model

For a real token workflow, the typical sequence is:

1. Establish a PC/SC context.
2. Discover and connect to a reader.
3. Select the PIV application.
4. Run standard or vendor-specific operations through the `piv` client and adapters.

The repository also contains emulator-backed tests so that core flows can be validated without physical hardware, but the emulator does not promise exact parity with every token family or firmware revision.
