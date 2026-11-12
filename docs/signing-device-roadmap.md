# Remaining signing device qualification

Research baseline: 2026-11-12. A public-key codec or algorithm constant does
not establish a working private operation on a device. Hardware qualification
remains per algorithm, model, firmware, slot and profile.

| Algorithm | Candidate and protocol evidence | Native adapter | Status / dependency |
|---|---|---|---|
| P-521 | CanoKey firmware 3.1.0+ documents a PIV extension; default ID `15` | Not implemented | Protocol identified; candidate device and independent hardware acceptance pending |
| secp256k1 | CanoKey firmware 3.0.0+ documents a PIV extension; default ID `53` | Not implemented | Protocol identified; candidate device and independent hardware acceptance pending |
| Ed448 | No device/protocol has been selected and qualified | Not implemented | Manufacturer protocol and test device required; no PIV ID assigned |

The [CanoKey PIV protocol](https://docs.canokeys.org/development/protocols/piv/)
documents configurable extension IDs. An adapter must read the configuration
using `00 EE 01 00`, handle disabled/ambiguous IDs, and keep that mapping local
to CanoKey. Default values are insufficient. Its transport uses short command
chaining and GET RESPONSE; an extended-command path cannot be assumed.

In particular, CanoKey's default `E2` selects ML-DSA-65, whereas the existing
YubiKey extension uses `E2` for ML-DSA-44. Global byte-to-algorithm normalization
must not be reused across vendors without protocol context.

## Native-adapter acceptance

For each future native path:

1. Record the exact model/firmware, manufacturer protocol, algorithm mapping,
   supported slots, PIN/touch behavior and message/digest semantics.
2. Implement vendor commands, public-key evidence and exact curve/OID parsing
   inside the owning adapter. Do not alias secp256k1 to P-256.
3. Add normalized APDU fixtures, malformed-key tests and transport limits.
   Cover P-521's 66-byte boundary and Ed448's actual key/signature format.
4. Integrate only implemented tuples into signing profiles; discovery must
   remain public and must not sign, generate/reset keys or verify PIN.
5. Qualify actual on-device signatures with OpenSSL, using designated test
   keys and recording each algorithm independently.

A vendor PKCS#11-only implementation belongs to a consumer's separate local
backend. It does not justify creating a fictitious PIV adapter or silently
switching the requested key/backend.

## Support status

The [current qualification matrix](signing-qualification.md) records the
implemented and tested subset: explicit RSA v1.5/PSS, P-256/P-384 and pure
Ed25519/ML-DSA-44/65/87 on the designated preview device. P-521 preparation is
tested off-card; secp256k1 identity is distinct from P-256. Neither establishes
native hardware support for the three algorithms above.

Native device qualification remains tracked in
[issue #15](https://github.com/PeculiarVentures/piv-go/issues/15), with the
supported-subset and release dependencies in
[issue #16](https://github.com/PeculiarVentures/piv-go/issues/16). The
[release procedure](releases/README.md) describes checks, tagging and consumer
dependency updates separately from this device roadmap.
