# CLI Guide

The public binary is `piv`.

It is designed around token tasks rather than raw APDU sequences. The default flow is: discover a reader, inspect the token, perform a targeted operation, and only then drop into expert diagnostics if required.

## Top-level commands

- `devices` lists readers and whether a card appears PIV-ready.
- `info` shows a summary of the selected token.
- `slot` inspects slot state.
- `cert` exports, imports, or deletes slot certificates.
- `key` generates, exports, deletes, signs, attests, or challenges with slot keys.
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
piv key attest 9c --reader "YubiKey 5C NFC" --out attest-9c.pem
piv cert export attestation --reader "YubiKey 5C NFC" --out attest-ca.pem
```

`key attest <slot>` exports the attestation certificate proving the slot key
was generated on a YubiKey (firmware 4.3.0+, slots 9A/9C/9D/9E).
`cert export attestation` (alias `f9`) reads the long-lived attestation
certificate from the YubiKey attestation object instead of a slot object.
The attestation slot (F9) is read-only: key and certificate mutation commands
reject it before touching the token to protect the factory attestation key.

Use credentialed operations safely:

```sh
piv pin verify --reader "YubiKey 5C NFC"
piv mgm rotate --reader "YubiKey 5C NFC" --dry-run
piv setup reset --reader "YubiKey 5C NFC" --dry-run
```

For `piv key sign`, the CLI resolves best-effort key metadata before deciding
whether to call `VERIFY PIN`.

- If the slot policy is known to require PIN verification, the CLI performs `VERIFY` before signing.
- If the slot policy is known to allow signing without PIN, the CLI skips the extra `VERIFY` unless you explicitly supply a PIN source.
- If the policy is unknown, the CLI keeps the conservative behavior and still requires `VERIFY`.

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
- `key import`
- `key delete`
- `mgm rotate`
- `setup init`
- `setup reset`
- `setup reset-slot`

YubiKey slot policies: `key generate` and `key import` accept
`--pin-policy never|once|always` and `--touch-policy never|always|cached`
(default omits the policy tags, so the device applies its own defaults instead
of preserving the slot's previous policies). `mgm rotate` accepts `--touch`
to require touch confirmation for management operations.

## YubiKey 6 preview algorithms (pqc-v1)

`key generate` and `key import` accept `--alg` (case-insensitive):
`p256`, `p384` (`eccp256`, `eccp384` aliases), `rsa1024`, `rsa2048`,
`rsa3072`, `rsa4096`, `ed25519`, `x25519`, `mldsa44`, `mldsa65`, `mldsa87`
(preview), `mlkem512`, `mlkem768`, `mlkem1024` (preview).

- Generate implements RSA-3072/4096, Ed25519, X25519, ML-DSA, and ML-KEM
  via `00 47 00 <slot> AC{80 <alg> [+AA pin][+AB touch]}` with the generated
  public key stored as `0x53{7F49{...} + 71 00 + FE}` (RSA `81/82`,
  Ed/X `86`, ML-DSA `87`, ML-KEM `88` with 800/1184/1568 bytes).
- Import implements RSA-3072/4096 (halves 192/256 bytes, tags `01-05`,
  `e=65537`, two primes), Ed25519/X25519 (tag `07`/`08`, 32-byte raw
  seed), and ML-KEM-768/1024 (tag `0x0A`, 64-byte raw seed `d||z`,
  identical for every variant; the card expands it into the full
  decapsulation key). Supply `--in` as PEM/DER (PKCS #8 round-trips for
  RSA/EC/Ed25519/X25519) or raw bytes as binary, hex, or base64 (required
  for ML-KEM, which has no PEM/DER encoding here). ML-KEM-512 import
  stays unsupported (no standard library implementation to derive the
  stored encapsulation key) and ML-DSA has no import APDU: both
  gap-reject with `not supported` before any APDU.
- Sign implements Ed25519 and ML-DSA over the raw message
  (`00 87 <alg> <slot> 7C{82 empty, 81 msg}`). RSA-3072/4096 apply host-side
  PKCS#1 v1.5 type-1 formatting so the challenge is exactly modulus-length
  (384/512 bytes): a 32-byte message is DigestInfo-wrapped as SHA-256
  (matching `--hash sha256`); any other length is type-1 padded raw
  (matching `--hash none`). X25519 cannot sign and ML-KEM has no sign
  flow: `key sign` and `key challenge` reject with
  `x25519 cannot sign: use ECDH` (exit 4) and `not supported` (exit 4)
  respectively.
- ECDH: `key challenge <slot> --challenge-hex <64 hex>` on an X25519 slot
  runs `00 87 E1 <slot> 7C{82 empty, 85 peer}` and returns the 32-byte
  shared secret (result kind `ecdh-secret`).
- Decapsulation: `key challenge <slot> --challenge-hex <ciphertext hex>`
  on an ML-KEM slot runs `00 87 <alg> <slot> 7C{82 empty, 86 ciphertext}`
  and returns the 32-byte shared secret (result kind `kem-secret`).
  The ciphertext is 768/1088/1568 bytes for ML-KEM-512/768/1024.
  Encapsulation stays host-side (for example with `crypto/mlkem`):
  the card only decapsulates. Supply `--pin-env`/`--pin-stdin` when the
  slot PIN policy requires verification (the token answers `6982`
  otherwise).
- Certificates: RSA and Ed25519 use strict X.509 import. ML-DSA slots
  require `cert import --raw-cert` to store raw bytes; without it the
  import rejects with `post-quantum certificate requires --raw`. X25519
  and ML-KEM slots always reject with `no X.509 profile` /
  `not supported`, even with `--raw-cert`.
- Public keys: Ed25519 exports standard PEM/DER. X25519 and ML-DSA/ML-KEM
  are opaque and keep the PEM/DER gap; export their bytes with
  `key public <slot> --format raw|base64|hex`.

Attestation (`key attest`, INS `00 F9 <slot> 00`) and key/certificate
delete work for all implemented algorithms. `key delete` also clears the
slot object holding the stored public key template, so post-delete
inspection reports the slot empty. The attestation slot (F9)
stays read-only and rejects before any APDU.

Certificate writes need management authentication on YubiKey/SafeNet
tokens: `cert import` and `cert delete` accept `--mgm-stdin`/`--mgm-env`
(or `PIV_MANAGEMENT_KEY`) like the key commands. Standard-transport tokens
write without management credentials, preserving prior behavior.

Prefer `--dry-run` when available. Use `--yes` only when your automation already validated the target device and credentials.

## Secret handling

Credential-bearing commands accept explicit stdin or environment-variable options. Prefer those mechanisms over shell arguments so that secrets do not leak into shell history or process listings.

APDU traces can contain credential material and token metadata. Route traces to a controlled destination with `--trace-file`, and redact them before sharing.
