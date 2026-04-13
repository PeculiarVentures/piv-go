# CLI Guide

The public binary is `piv`.

It is designed around token tasks rather than raw APDU sequences. The default flow is: discover a reader, inspect the token, perform a targeted operation, and only then drop into expert diagnostics if required.

## Top-level commands

- `devices` lists readers and whether a card appears PIV-ready.
- `info` shows a summary of the selected token.
- `slot` inspects slot state.
- `cert` exports, imports, or deletes slot certificates.
- `key` generates, exports, deletes, signs, or challenges with slot keys.
- `pin`, `puk`, and `mgm` manage credentials.
- `setup` contains destructive initialization and reset flows.
- `doctor` runs safe environment and token readiness checks.
- `diag` contains expert diagnostics such as object reads, TLV decoding, and raw APDU sends.
- `config` stores CLI-layer defaults.
- `version` prints build information.

## Global flags

- `--reader` selects a PC/SC reader by name.
- `--adapter` overrides adapter auto-detection.
- `--json` emits machine-readable JSON to stdout.
- `--non-interactive` disables prompts and interactive selection.
- `--timeout` sets the command timeout.
- `--trace` and `--trace-file` control diagnostic trace output.
- `--verbose` enables additional human-readable detail.
- `--color` controls color policy.

When `--json` is enabled, stdout is reserved for JSON only. Human-facing notes, warnings, prompts, and trace output go to stderr.

## Common workflows

List readers and PIV readiness:

```sh
piv devices
```

Inspect one token:

```sh
piv info --reader "YubiKey 5C NFC"
piv slot show auth --reader "YubiKey 5C NFC"
```

Export public artifacts:

```sh
piv cert export auth --reader "YubiKey 5C NFC" --out auth-cert.pem
piv key public auth --reader "YubiKey 5C NFC" --out auth-pub.pem
```

Use credentialed operations safely:

```sh
piv pin verify --reader "YubiKey 5C NFC"
piv mgm rotate --reader "YubiKey 5C NFC" --dry-run
piv setup reset --reader "YubiKey 5C NFC" --dry-run
```

Run expert diagnostics:

```sh
piv doctor --reader "YubiKey 5C NFC" --with-select
piv diag tlv decode --in response.bin
piv diag object read chuid --reader "YubiKey 5C NFC"
```

## Destructive commands

Treat these commands as state-changing operations:

- `cert import`
- `cert delete`
- `key generate`
- `key delete`
- `mgm rotate`
- `setup init`
- `setup reset`
- `setup reset-slot`

Prefer `--dry-run` when available. Use `--yes` only when your automation already validated the target device and credentials.

## Secret handling

Credential-bearing commands accept explicit stdin or environment-variable options. Prefer those mechanisms over shell arguments so that secrets do not leak into shell history or process listings.

APDU traces can contain credential material and token metadata. Route traces to a controlled destination with `--trace-file`, and redact them before sharing.
