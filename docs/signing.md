# Explicit signing APIs

Signing requests identify the operation and input explicitly. No API guesses a
hash or mode from the input length. Existing `Client.Sign` and `Authenticate`
retain their wire behavior for compatibility.

| Operation | Execution API | Input | Result encoding | Verification |
|---|---|---|---|---|
| RSA PKCS#1 v1.5 digest | `Client.SignRSA` with `RSAPKCS1v15DigestOptions` | Named-hash digest | `raw`, modulus width | `piv.VerifyRSA` with the same options |
| RSA PKCS#1 v1.5 payload | `Client.SignRSA` with `RSAPKCS1v15PayloadOptions` | Exact payload, including any caller's DigestInfo | `raw`, modulus width | `piv.VerifyRSA` with the same options |
| RSA-PSS | `Client.SignRSA` with `RSAPSSOptions` | Digest and explicit hash/MGF1/salt parameters | `raw`, modulus width | `piv.VerifyRSA` with the same options |
| ECDSA P-256/P-384 | `Client.SignECDSA` | Already computed digest | `asn1-der` sequence of `r` and `s` | `ecdsa.VerifyASN1` against the original digest |
| Pure Ed25519 | `Client.Sign(piv.AlgEd25519, slot, message, piv.RSASignHashNone)` | Complete message | `raw`, 64 bytes | `ed25519.Verify` |
| Pure ML-DSA-44/65/87 | `MLDSASigner.Sign` with nil or `crypto.Hash(0)` options | Complete message, empty context | `raw`, parameter-set width | `piv.VerifyMLDSASignature` |

The APIs validate parameters and response shape, but do not cryptographically
verify the returned signature against the supplied public key. Call the listed
verifier with the expected key before accepting a result. An opaque Ed25519 key
must carry `AlgEd25519`; its validated raw bytes can be used as an
`ed25519.PublicKey`. None of these signing APIs performs implicit PIN
verification or grants application authorization.

## RSA

Choose one complete operation:

- `RSAPKCS1v15DigestOptions{Hash: crypto.SHA256}` adds the named hash's
  DigestInfo and PKCS#1 v1.5 padding.
- `RSAPKCS1v15PayloadOptions{}` pads the exact input bytes. A caller-supplied
  DigestInfo is neither parsed nor rewritten. Maximum payload size is `k-11`,
  where `k` is the modulus width in bytes.
- `RSAPSSOptions{Hash: crypto.SHA256, MGF1Hash: crypto.SHA256, SaltLength: 32}`
  encodes PSS with the exact requested parameters.

SHA-256, SHA-384 and SHA-512 are implemented. MGF1 hash must be explicit and
equal to the digest hash in this release. Salt length zero means exactly zero;
negative values, including Go's `PSSSaltLengthEqualsHash`, are rejected. Set
`SaltLength: hash.Size()` for hash-sized salt. Nil options are rejected.

PSS capability profiles describe zero salt as deterministic: no salt randomness
is read for that operation. Positive salt lengths use a separate host-CSPRNG
profile and cannot satisfy a deterministic-signature requirement.

```go
options := piv.RSAPSSOptions{
    Hash: crypto.SHA256, MGF1Hash: crypto.SHA256, SaltLength: 0,
}
if err := piv.ValidateRSASignRequest(piv.AlgRSA2048, publicKey, digest, options); err != nil {
    return err // off-card validation, before asking for a PIN
}
// Resolve application authorization and verify the PIN as required here.
signature, err := client.SignRSA(piv.AlgRSA2048, slot, publicKey, digest, options)
if err != nil {
    return err
}
return piv.VerifyRSA(publicKey, digest, signature, options)
```

The protocol identifier must match the public modulus size exactly.
RSA-2048/3072/4096 use the same contract; RSA-1024 is a legacy compatibility
case. PSS salt uses `crypto/rand`. The new API accepts neither an arbitrary
encoded RSA block nor a fixed salt. `VerifyRSA` checks the exact salt length,
including zero, rather than Go's automatic salt detection.

`ValidateRSA` remains a compatibility wrapper for `ValidateRSASignRequest`.
Absent options, including typed-nil supported options, return
`ErrInvalidRSAParameters`. An unimplemented scheme or hash returns
`ErrUnsupportedRSAOptions`.

The host encodes the scheme and the card executes its RSA primitive through
`Authenticate`. This preserves legacy short-command chaining and response
continuation. Signature output has exactly the modulus width. Device/firmware
support and the association with the current private key require separate
adapter evidence. Verification after a signature does not replace authorization
before it.

## ECDSA

`Client.SignECDSA(algorithm, slot, publicKey, digest)` supports the existing
P-256 and P-384 protocol algorithms. It uses `PrepareECDSADigest` to truncate
the digest to the order's bit length and left-pad short inputs to the required
width. This allows SHA-256/384/512 digests without changing the signed message.
Input is never hashed again. Output is a canonical DER sequence of `r` and `s`,
not PKCS#11's fixed-width concatenation.

Call `ValidateECDSASignRequest(algorithm, publicKey, digest)` before requesting a
PIN. It shares SignECDSA's exact key/curve/algorithm/digest preflight and sends
no APDU. This validation does not establish device support or key presence.

`PrepareECDSADigest` also implements off-card P-521 preparation for future
adapters. This does not advertise a P-521 card algorithm. Exact curve identity
is required; a 256-bit curve is not automatically P-256. Empty digests and
malformed public points are rejected before the private operation.

## Pure ML-DSA

`MLDSASigner` supports pure ML-DSA-44/65/87 with an empty context. Only nil
options and `crypto.Hash(0)` are accepted. Nil preserves the existing pure
CSR and certificate workflows. All other option types are rejected before an
APDU, including custom options whose `HashFunc` returns zero.

Signing a hash as ordinary message bytes remains pure ML-DSA; it is not
HashML-DSA. Context, prehash and explicit hedged/deterministic requirements need
a separately documented device interface. The `io.Reader` argument cannot
control a device's internal random generator. Callers that previously passed
ignored options must migrate to an explicit pure request or handle
`ErrUnsupportedMLDSAOptions`. `ErrMLDSAOptionsUnsupported` remains a
compatibility name for the same error, including with `errors.Is`.

## Errors after a private operation

Incorrect RSA/ML-DSA signature lengths and malformed or noncanonical ECDSA DER
signatures wrap `ErrInvalidSignatureResponse`. The card's private operation may
already have completed, including PIN-always or touch interaction. This is a
response-shape error, not a preflight failure or a cryptographic verification
result. Do not automatically retry a private operation on this error. Response
and transport errors can occur after submission even when no signature is
returned.

## Signing capability snapshots

`adapters.ReportSigningCapabilities(adapter, device)` is separate from the
existing coarse `CapabilityReport`. `device` is an explicit cached snapshot:
model, device firmware and PIV applet version are distinct fields. Reporting
and `MatchSigningCapability` perform no I/O, slot scan, PIN verification,
signing probe, applet selection or mutation.

Profiles bind a key to one exact scheme/input/hash/MGF/mode/context tuple,
length limits, slots, signature encoding, transport and evidence. Missing
information stays `unknown`. An omitted combination never becomes supported
through a Cartesian product of unrelated lists.

The YubiKey snapshot contract uses canonical names from
[`yubikit.support.get_name` in ykman 5.9.2](https://github.com/Yubico/yubikey-manager/blob/5.9.2/yubikit/support.py)
for `Model`, including `YubiKey 5A` and the aggregate name `YubiKey 4`.
Documented product aliases `YubiKey NEO-n`, `YubiKey 4 Nano`, `YubiKey 4C`,
`YubiKey 4C Nano` and `YubiKey 5` are also accepted. `Firmware` comes from an
explicit management/device inventory and includes its version qualifier, such
as `6.0.0.alpha.8`. `PIVVersion` is the raw PIV GET VERSION value. Reader labels
and PIV applet versions do not substitute for device firmware. The library does
not invoke ykman or collect either inventory field when reporting capabilities.
FIPS and unknown suffixes remain unqualified unless explicitly supported by a
separate profile.

The following pure helpers connect existing observations and signing APIs:

- `SigningKeyFromPublicKey(publicKey)` describes exact supported key parameters.
  Unknown curves or unlabelled opaque keys are not inferred from their size.
- `SigningKeyEvidenceFromSlot(slot, description, current)` retains the slot's
  state and public-key provenance. `current` is an explicit freshness decision
  made by the consumer; the helper does not refresh or accept cached evidence.
- `SigningRequestFromRSAOptions(algorithm, publicKey, input, options)` validates
  the concrete RSA request through `ValidateRSASignRequest` and preserves its
  exact input/hash/MGF1/salt semantics.

`Context` presence stays explicit. The RSA request helper fills
`SigningContextAbsent`; manually constructed RSA/ECDSA requests must do the
same. EdDSA/ML-DSA callers must distinguish absent context from present empty
context. `SigningResultRaw` and `SigningResultASN1DER` name the result encodings;
exported `SigningReason...` constants identify decisions without parsing prose.

The fragment below assumes the consumer supplied `deviceSnapshot`, a
`description` from passive slot inspection, and `acceptedCurrent` from its own
freshness policy. The options and public key are the concrete RSA operation
that will be executed. Capability matching and authorization precede PIN/touch
interaction.

```go
request, err := adapters.SigningRequestFromRSAOptions(algorithm, publicKey, input, options)
if err != nil {
    return err
}
keyEvidence, err := adapters.SigningKeyEvidenceFromSlot(slot, description, acceptedCurrent)
if err != nil {
    return err
}
report := adapters.ReportSigningCapabilities(adapter, deviceSnapshot)
decision := adapters.MatchSigningCapability(report, keyEvidence, request)
if decision.Support != adapters.SigningSupported {
    return fmt.Errorf("signing unavailable: %s (%s)", decision.Support, decision.Reason)
}
if !applicationPolicy.Allows(keyEvidence.Slot, request) {
    return errors.New("signing is not authorized")
}
// Resolve the required PIN/touch interaction, execute SignRSA, then VerifyRSA.
```

The example's device snapshot, key evidence, request and application policy are
provided by the consumer. Current authoritative metadata must be distinguished
from a certificate or stored public template. A cached supported device profile
does not prove private-key presence. Refresh evidence explicitly under the
consumer's freshness policy; loading a cache does not make it current.

`supported` currently requires a present key with current authoritative public
key metadata (`PublicKeySourceMetadata`). A certificate or stored template
cannot satisfy that requirement. YubiKey GET METADATA is available from
[firmware 5.3](https://developers.yubico.com/PIV/Introduction/Yubico_extensions.html#_get_metadata).
NEO, YubiKey 4 and YubiKey 5 before 5.3 therefore remain `unknown` in live key
matching, even when a static profile describes a supported device operation.
SafeNet signing reports also currently remain `unknown` until their
model/firmware profiles are qualified. The existing low-level operations and
coarse capability report retain their behavior.

PIN/touch fields are observations for the consumer's interaction and access
policy; they do not grant authorization through the matcher. Snapshot structs
are Go API values. A consumer owns its persistence/wire schema and freshness
rules rather than treating a cached struct as current evidence.

Slot roles are preserved: `9a` authentication, `9c` digital signature, `9e`
card authentication, and `9d`/`82`-`95` key management. Application policy
decides which eligible keys can be published for signing. Management `9b` and
attestation `f9` are excluded from ordinary signing profiles.

The existing CLI keeps its `none`/`sha256` hash interface and legacy signing
behavior. Applications should use the explicit library APIs for the new schemes.

See [hardware qualification](signing-qualification.md) and the
[remaining device work](signing-device-roadmap.md) for the supported subset.
