# Explicit signing APIs

`Client.SignRSA` and `Client.SignECDSA` accept an already computed digest.
`MLDSASigner.Sign` accepts the complete message. No API guesses a hash or mode
from the input length. Existing `Client.Sign` and `Authenticate` retain their
wire behavior for compatibility.

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
if err := piv.ValidateRSA(piv.AlgRSA2048, publicKey, digest, options); err != nil {
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
`ErrMLDSAOptionsUnsupported`.

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

```go
report := adapters.ReportSigningCapabilities(adapter, deviceSnapshot)
decision := adapters.MatchSigningCapability(report, keyEvidence, request)
if decision.Support != adapters.SigningSupported {
    return fmt.Errorf("signing unavailable: %s (%s)", decision.Support, decision.Reason)
}
if !applicationPolicy.Allows(keyEvidence.Slot, request) {
    return errors.New("signing is not authorized")
}
// Validate the exact API request, resolve PIN/touch interaction, then execute.
```

The example's device snapshot, key evidence, request and application policy are
provided by the consumer. Current authoritative metadata must be distinguished
from a certificate or stored public template. A cached supported device profile
does not prove private-key presence. Refresh evidence explicitly under the
consumer's freshness policy; loading a cache does not make it current.

Slot roles are preserved: `9a` authentication, `9c` digital signature, `9e`
card authentication, and `9d`/`82`-`95` key management. Application policy
decides which eligible keys can be published for signing. Management `9b` and
attestation `f9` are excluded from ordinary signing profiles.

The existing CLI keeps its `none`/`sha256` hash interface and legacy signing
behavior. Applications should use the explicit library APIs for the new schemes.
