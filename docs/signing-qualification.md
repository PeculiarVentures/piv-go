# Signing qualification

Qualification date: 2026-11-12. These results describe the designated preview,
production and legacy test devices and the listed parameter combinations,
not universal PIV or YubiKey support.

Additional slot-specific checks were performed on 2026-11-13 and are recorded
separately below. They do not imply that all algorithms or operations work in
every slot.

## Preview test environment

- Device: YubiKey 5C NFC - Enhanced PIN, used as the Yubico 6 test token.
- Device firmware: `6.0.0.alpha.8`, reported by YubiKey Manager 5.9.2.
- PIV GET VERSION: `0.0.1`. This preview applet version is not firmware `0.0.1`.
- Interface: USB PC/SC, macOS arm64; Go 1.26.7.
- Independent verifier: OpenSSL 3.6.3, default provider.
- Keys: generated on the test device after PIV reset; PIN policy always,
  touch policy never. The test does not qualify touch-enforced workflows.

## Originally qualified preview subset

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

## Additional slot checks, 2026-11-13

The preview tests used the user-identified YubiKey 6 preview card (PIV serial
`38997686`) associated with the model/firmware/applet tuple above. The tests
checked the PIV serial, but did **not** independently re-read the model,
device firmware, or PIV applet version during this follow-up. Those identity
fields are based on the supplied session context and should be rechecked on
the device before treating this as independently established inventory. All
checks below used USB PC/SC on macOS arm64. The P-256 signatures were verified
using Go's `crypto/ecdsa`; one `9c` SHA-256 signature was also verified using
OpenSSL. Ed25519 signatures were verified with Go's `crypto/ed25519`, and
ML-DSA signatures with CIRCL. ECDH results were compared to a host-generated
peer's independently computed secret. PIN/touch policies varied between tests;
these results do not qualify touch-enforced workflows.

| Operation | Key | Tested slots | Inputs or parameters |
|---|---|---|---|
| ECDSA | P-256 | `9a`, `9c`, `9e`, `82`–`95` | SHA-256/384/512 via `SignECDSA` |
| ECDSA | P-256 | `9d` | SHA-256 via the CLI's signing path |
| Pure EdDSA | Ed25519 | `9d`, `82`, `95` | Empty, ordinary and 4096-byte messages |
| Pure ML-DSA | ML-DSA-44 | `9c`, `82` | Empty, ordinary and 4096-byte messages; empty context |
| Pure ML-DSA | ML-DSA-65 | `9a`, `9d` | Empty, ordinary and 4096-byte messages; empty context |
| Pure ML-DSA | ML-DSA-87 | `9e`, `95` | Empty, ordinary and 4096-byte messages; empty context |
| ECDH | P-256 | `9a`, `9c`, `9d`, `9e`, `82`, `95` | Host peer and card shared secrets matched |
| ECDH | X25519 | `9d`, `82`, `95` | Host peer and card shared secrets matched |

These message-input checks exercised the endpoints and ordinary lengths, not
every length in the range. The preview message profile retains its existing
4096-byte limit. The original preview tests above independently qualified all
three ML-DSA variants and Ed25519 in `9c`. ECDH is recorded here as hardware
evidence only: `SigningCapabilityReport` describes signing, not key agreement.

For the subsequent slot-policy release, the same preview token was identified
again with YubiKey Manager 5.9.2 and a reader-bound PIV serial and GET VERSION:
model `YubiKey 5C NFC - Enhanced PIN`, device firmware `6.0.0.alpha.8`, PIV
`0.0.1`. Its existing Ed25519 key in `9a` matched the updated capability report
using current slot metadata, and empty, ordinary and 4096-byte messages were
signed and verified with Go's `crypto/ed25519`. This follow-up did not reset
PIV or replace keys. Other generalized slot combinations were not rechecked.

The NEO follow-up used the YubiKey NEO with device firmware `3.4.9` and PIV
version `1.0.4`, identified using YubiKey Manager 5.9.2. Its PIV application
was reset before and after the tests. ECDSA P-256 with SHA-256/384/512 and
RSA-2048 PKCS#1 v1.5 and PSS with SHA-256/384/512 and hash-sized salt were
verified on `9a`, `9c`, `9d`, and `9e` using Go's `crypto/ecdsa` and
`crypto/rsa`. The P-256 ECDH result in all four slots matched a host peer.
RSA-2048 PKCS#1 v1.5 and OAEP-SHA-256 encrypted messages were recovered in
all four slots: the card performed the raw private RSA operation, with padding
encoded and removed on the host. RSA-1024 signing and decryption were sampled
in `9a`; RSA-3072 and RSA-4096 key generation there returned `6A80`.
RSA-2048 generation returned `6B00` in each slot `82`–`95`; P-256 generation
also returned `6B00` in `82` and `95`. Ed25519, X25519 and ML-DSA-44/65/87
generation in `9a` returned `6A80`.

The NEO profile already advertised documented P-256 and RSA-2048 signing
for the four main slots. For the exact tested NEO identity, the named-hash
ECDSA and RSA PKCS#1 v1.5 profiles additionally cite this hardware evidence.
The wider documented PSS salt ranges are not represented as hardware-tested
in every slot. RSA decryption and ECDH do not belong to the signing report.
The NEO remains metadata-blind for current-key matching.

The YubiKey 4 follow-up used a card identified by YubiKey Manager 5.9.2 as
`YubiKey 4`, device firmware `4.2.8`, PIV applet `4.2.8` (PIV serial
`4158393`). The test verified the reader-bound serial, reset PIV before and
afterward, generated keys with default policies and used the reset PIN. The
following operations were verified on USB PC/SC using Go's cryptographic
implementations for independent signature and shared-secret checks:

| Operation | Key | Tested slots | Inputs or parameters |
|---|---|---|---|
| ECDSA and ECDH | P-256 | `9a`, `9c`, `9d`, `9e`, `82`–`95` | SHA-256/384/512; host peer shared secret |
| ECDSA and ECDH | P-384 | `9a`, `9c`, `9d`, `9e`, `82`, `95` | SHA-256/384/512; host peer shared secret |
| RSA signature and decryption | RSA-2048 | `9a`, `9c`, `9d`, `9e`, `82`, `95` | PKCS#1 v1.5 and PSS SHA-256/384/512 with hash-sized PSS salt; PKCS#1 v1.5 and OAEP-SHA-256 decryption |
| RSA signature and decryption | RSA-1024 | `9a` | PKCS#1 v1.5 SHA-256/384/512, PSS SHA-256/384 with hash-sized salt; PKCS#1 v1.5 and OAEP-SHA-256 decryption |

RSA encryption padding and unpadding were performed on the host; the card
performed the raw private RSA operation. RSA-3072 and RSA-4096, Ed25519,
X25519, and ML-DSA-44/65/87 generation in `9a` returned `6A80`.
For the exact YubiKey 4 tuple above, named-hash P-256 signing profiles cite the
hardware result for all their slots. Named-hash P-384 ECDSA and RSA-2048
PKCS#1 v1.5 profiles are split so only the six tested slots cite hardware
evidence; other slots retain their existing vendor documentation evidence.
The wider PSS salt ranges, ECDH, and decryption are not claimed by the added
signing-profile evidence. As with NEO, this device lacks authoritative current
key metadata for `MatchSigningCapability`, which remains unknown when only a
stored public object or certificate is available.

The subsequent YubiKey 5 follow-up used a card identified by YubiKey Manager
5.9.2 as `YubiKey 5C NFC`, device firmware `5.4.3`, PIV applet `5.4.3` (PIV
serial `26748006`). The tests checked the serial against the PIV reader, reset
PIV before and after the run, generated keys with default PIN/touch policies,
and verified the reset PIN for each private operation. On USB PC/SC, Go's
cryptographic implementations independently verified the following results:

| Operation | Key | Tested slots | Inputs or parameters |
|---|---|---|---|
| ECDSA and ECDH | P-256, P-384 | `9a`, `9c`, `9d`, `9e`, `82`–`95` | SHA-256/384/512; host peer shared secret |
| RSA signature and decryption | RSA-2048 | `9a`, `9c`, `9d`, `9e`, `82`–`95` | PKCS#1 v1.5 and PSS SHA-256/384/512 with hash-sized PSS salt; PKCS#1 v1.5 and OAEP-SHA-256 decryption |
| RSA signature and decryption | RSA-1024 | `9a` | PKCS#1 v1.5 SHA-256/384/512, PSS SHA-256/384 with hash-sized salt; PKCS#1 v1.5 and OAEP-SHA-256 decryption |

For RSA decryption, the host applied and removed padding while the card
performed the raw private RSA operation. RSA-3072/4096, Ed25519, X25519 and
ML-DSA-44/65/87 key generation in `9a` returned `6A80`. These errors concern
the tested generation requests and do not establish every other operation.
For the exact YubiKey 5 tuple above, named-hash P-256 and P-384 ECDSA and
RSA-2048 PKCS#1 v1.5 profiles cite the hardware evidence for all their slots.
The test used hash-sized PSS salts and does not qualify the wider salt range
as hardware-tested. ECDH and RSA decryption remain outside the signing report.

## Reproduce

The hardware suite is separate from normal tests. It resets the selected PIV
application, replaces keys and uses the reset defaults. Use a dedicated test
token. The reader and expected serial are both required; a mismatch aborts
before reset. No APDU trace or private key is written to the repository.
The additional slot checks above were performed separately using temporary
test programs and are not fully reproduced by the commands below.

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

Before publishing v0.5.0, the complete matrix above was repeated against the
final signing source from PR #22 (`3cbccc8`), whose tree matched the merged
`main` source. All three devices passed with OpenSSL 3.6.3, including the final
shared serial guard, fresh metadata/profile matching where available, and
NEO's deliberately unknown live-key evidence. No PIV reset was performed.
A temporary test copy reused existing keys and replaced only missing preview
test keys in `9c` and the NEO test keys in `9a`/`9c`; only the two hardware test
files were adapted for this setup. Signing source, identity checks, parameter
matrices and OpenSSL verification code were unchanged.

Use ykman 5.9.2 for the documented inventory naming contract and OpenSSL 3 with
ML-DSA support and matching development headers/library for the preview suite.
A C compiler builds the small EVP empty-message verifier under the test's
temporary directory. Public keys and signatures used for verification are
temporary files; no host private key is created by the hardware suite.

## Interpretation

For the exact preview model, firmware and applet tuple above, the YubiKey
provider advertises the qualified RSA-2048/3072/4096, P-256, P-384, Ed25519
and ML-DSA operations across the four ordinary slots and `82`–`95`. The slot
policy generalizes the sampled hardware results recorded above; the tables do
not assert that every algorithm was physically tested in every slot. It does
not infer support from a `6.x` prefix or the applet's `0.0.1` value. RSA-1024
has no qualified preview profile.

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
