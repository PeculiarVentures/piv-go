---
applyTo: "pcsc/**,iso7816/**,piv/**"
---

# Core Layer Instructions

- Preserve strict layering:
  - `pcsc/` is the only layer that talks to `scard`
  - `iso7816/` owns wire-format and status-word concerns
  - `piv/` owns PIV protocol semantics built on top of a card transport
- Prefer explicit error mapping and status handling over ad hoc string checks.
- Avoid leaking vendor-specific behavior into `piv/` or `iso7816/`.
- Keep public protocol helpers small, composable, and test-covered.
- When changing APDU, TLV, or status behavior, add focused unit tests in the
  same package and avoid relying only on higher-layer integration tests.
