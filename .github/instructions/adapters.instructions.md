---
applyTo: "adapters/**"
---

# Adapter Instructions

- Put vendor-specific behavior in the appropriate adapter package. Avoid pushing
  vendor conditionals into shared adapter helpers unless the behavior is truly
  generic.
- Keep stable adapter registration semantics. Built-in adapters are registered
  in `adapters/all/`.
- Prefer extending capability reports, runtime helpers, and session-based flows
  before adding new parallel abstractions.
- When a vendor has both production and emulator behavior, keep those paths easy
  to distinguish in filenames and tests.
- Preserve traceability. Adapter operations should continue to produce useful
  observer comments and APDU logs where the package already does so.
- Add or update adapter tests with emulator coverage whenever vendor behavior or
  fallback logic changes.

## Change Hints

- Reader matching and registration changes usually touch `adapter.go`,
  `registry.go`, and `adapters/all/imports.go`.
- Initialization, reset, metadata, and mirror-object behavior should stay with
  the vendor package that owns it.
