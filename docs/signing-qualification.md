# Signing qualification

Qualification date: 2026-11-12. These results describe the designated preview,
production and legacy test devices and the listed parameter combinations,
not universal PIV or YubiKey support.

## Preview test environment

- Device: YubiKey 5C NFC - Enhanced PIN, used as the Yubico 6 test token.
- Device firmware: `6.0.0.alpha.8`, reported by YubiKey Manager 5.9.2.
- PIV GET VERSION: `0.0.1`. This preview applet version is not firmware `0.0.1`.
- Interface: USB PC/SC, macOS arm64; Go 1.26.7.
- Independent verifier: OpenSSL 3.6.3, default provider.
- Keys: generated on the test device after PIV reset; PIN policy always,
  touch policy never. The test does not qualify touch-enforced workflows.

## Qualified subset

| Operation | Key | Slot | Verified input/parameters | Hardware result |
|---|---|---|---|---|
| PKCS#1 v1.5 digest | RSA-2048 | `9a` | SHA-256/384/512 | OpenSSL verified |
| PKCS#1 v1.5 digest | RSA-3072 | `9c` | SHA-256/384/512 | OpenSSL verified |
| PKCS#1 v1.5 digest | RSA-4096 | `82` | SHA-256/384/512 | OpenSSL verified |
| PSS | RSA-2048/3072/4096 | Same slots as above | Each SHA-2 hash, equal MGF1 hash; salt 0, 1, hash size, maximum | OpenSSL verified |
| PKCS#1 v1.5 exact payload | RSA-2048/3072/4096 | Same slots as above | Empty, ordinary and `k-11` byte payloads | OpenSSL recovered bytes matched |
| ECDSA | P-256 | `9d`, `95` | SHA-256/384/512 via `SignECDSA` | OpenSSL verified |
| ECDSA | P-384 | `9e` | SHA-256/384/512 via `SignECDSA` | OpenSSL verified |
| Pure Ed25519 | Ed25519 | `9c` | Empty, 32-byte, ordinary message and 4096-byte message | OpenSSL verified |
| Pure ML-DSA | ML-DSA-44 | `9c` | Same message lengths; empty context | OpenSSL verified |
| Pure ML-DSA | ML-DSA-65 | `9c` | Same message lengths; empty context | OpenSSL verified |
| Pure ML-DSA | ML-DSA-87 | `9c` | Same message lengths; empty context | OpenSSL verified |

PSS maximum salt is `ceil((modBits-1)/8) - hashSize - 2`. Exact zero salt is
verified with `rsa_pss_saltlen:0`; no automatic salt selection is used.
Capability profiles describe zero salt as deterministic and positive salt
lengths separately as host-CSPRNG operations.

The ECDSA device primitive requires a fixed-width representative. Passing some
unformatted hash lengths through legacy `Sign` returned `6A80`; `SignECDSA`
performs the standard conversion and OpenSSL verifies against the original
digest. Legacy behavior is preserved.

OpenSSL's `pkeyutl` one-shot CLI rejects an empty file because its zero-byte
buffer allocation fails. The suite uses the same installation's OpenSSL EVP
verifier directly for empty-message Ed25519/ML-DSA signatures. Nonempty
signatures are verified using `pkeyutl`. Nonempty exact PKCS#1 payloads are
recovered with `pkeyutl -verifyrecover` and compared byte-for-byte. OpenSSL's
PKCS#1 provider rejects a zero-byte recovered payload; that boundary uses raw
OpenSSL recovery and checks the complete `00 01 FF...FF 00` representative.

## Production and legacy regression

Terra 6.1 also ran the explicit reset-enabled production suite on two designated
test cards with OpenSSL 3.6.3. Device identity was read through ykman 5.9.2
before opening the active PIV session and checked against the expected serial,
model and device firmware. PIV applet versions were recorded separately.

| Device | Device firmware | PIV applet | Verified keys and slots | Capability evidence |
|---|---|---|---|---|
| YubiKey 5C NFC | `5.4.3` | `5.4.3` | RSA-2048 `9a`, P-256 `9c`, P-384 `9d` | Each operation matched current authoritative slot metadata and an advertised profile |
| YubiKey NEO | `3.4.9` | `1.0.4` | RSA-2048 `9a`, P-256 `9c` | GET METADATA unavailable; live matcher remains `unknown/key-evidence-unavailable` |

Both RSA keys passed SHA-256/384/512 PKCS#1 v1.5 digest signing, exact payloads
of length zero/ordinary/maximum, and PSS with equal MGF1 hash and salt lengths
zero/one/hash-size/maximum. Both P-256 keys and the production P-384 key passed
SHA-256/384/512 digest signing. Signatures were independently verified through
the same OpenSSL paths described above. NEO P-384 and RSA sizes above 2048 bits
were not qualified or advertised.

Successful controlled key generation and signature verification on NEO do not
turn a later passive certificate/template read into metadata evidence. The
read-only legacy regression verifies that its static P-256 profile can exist
while current-key capability matching correctly remains unknown.

## Reproduce

The hardware suite is separate from normal tests. It resets the selected PIV
application, replaces keys and uses the reset defaults. Use a dedicated test
token. The reader and expected serial are both required; a mismatch aborts
before reset. No APDU trace or private key is written to the repository.

```sh
PIV_TEST_ALLOW_RESET=1 \
PIV_TEST_READER='your exact PC/SC reader' \
PIV_TEST_SERIAL='your test token serial' \
PIV_TEST_MODEL='YubiKey 5C NFC - Enhanced PIN' \
PIV_TEST_DEVICE_FIRMWARE='6.0.0.alpha.8' \
PIV_TEST_YKMAN='/path/to/ykman' \
PIV_TEST_OPENSSL='/path/to/openssl-3/bin/openssl' \
go test -tags hardware ./integration -run '^TestYubiKeySigningOpenSSL$' -v -count=1 -timeout 20m
```

For the production suite, use the same explicit variables with model/firmware
`YubiKey 5C NFC`/`5.4.3` or `YubiKey NEO`/`3.4.9` and select
`-run '^TestYubiKeyProductionSigningOpenSSL$'`. For passive NEO evidence checks,
set `PIV_TEST_LEGACY_READ_ONLY=1` and select
`-run '^TestYubiKeyLegacySigningEvidence$'`; omit the reset opt-in.
The preview identity/serial guard can also be checked without mutation using
`PIV_TEST_IDENTITY_READ_ONLY=1` and
`-run '^TestYubiKeyPreviewIdentityReadOnly$'`, with the preview identity variables
above and no reset opt-in.

Expected model and firmware environment values are selectors, not independent
evidence. The suites compare them with actual vendor inventory before any reset.
The preview and production cards also bind the selected PIV reader through
direct PIV GET SERIAL; NEO's missing command requires its explicit reader-bound
vendor inventory. Generated public keys are compared with live slot metadata
where available, and operations must match the corresponding profiles before
PIN verification. The deliberately metadata-blind NEO suite records unknown
capabilities instead of fabricating evidence.

After the full preview signature matrix passed, the serial guard was made an
explicit shared direct-PIV read. That final guard passed the read-only identity
check; the cryptographic matrix and its input/result handling were unchanged.

Use ykman 5.9.2 for the documented inventory naming contract and OpenSSL 3 with
ML-DSA support and matching development headers/library for the preview suite.
A C compiler builds the small EVP empty-message verifier under the test's
temporary directory. Public keys and signatures used for verification are
temporary files; no host private key is created by the hardware suite.

## Interpretation

The YubiKey provider advertises the qualified preview subset only for the exact
model, firmware and applet tuple above, and only for the listed slots. It does
not infer support from a `6.x` prefix or the applet's `0.0.1` value.

Known production YubiKey models use separately cited vendor documentation;
the production/legacy regressions above qualify only their listed cases.
Unqualified production Ed25519 message limits remain unknown; preview limits
are not copied onto other devices. SafeNet signing profiles remain unknown
until a model/firmware parameter matrix is qualified. Existing coarse
capabilities and low-level APIs remain available.

P-521, secp256k1 and Ed448 have no qualified native path in this release.
HashML-DSA, EdDSA prehash/context variants and caller-controlled device
randomness are not claimed. Each requires a separately documented and qualified
device interface.

See the [device roadmap](signing-device-roadmap.md) for the remaining protocol,
hardware and release dependencies.
