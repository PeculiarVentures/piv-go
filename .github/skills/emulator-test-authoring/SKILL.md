---
name: emulator-test-authoring
description: Use when adding or updating emulator-backed tests, APDU trace fixtures, fake reader contexts, or command tests that should avoid real hardware. Helps align new tests with the repository's existing emulator and trace patterns.
---

# Emulator Test Authoring

Use this skill when a change needs tests but should not rely on a physical
reader or token.

## Workflow

1. Prefer the existing emulator or fake card context helpers before creating a
   new test double.
2. Keep tests scoped to the layer under change:
   - unit tests in `iso7816/` or `piv/` for protocol behavior
   - adapter tests for vendor behavior
   - CLI tests for command envelopes and stdout/stderr behavior
3. When a trace file exists, normalize and compare against the fixture rather
   than asserting long raw strings inline.
4. If a new emulator-only behavior is required, keep it clearly separated from
   production code.

## Repo Patterns

- Card and APDU emulation helpers live under `emulator/`.
- Trace normalization helpers live under `internal/testtrace/`.
- CLI fake reader contexts and JSON envelope assertions live in
  `cmd/piv/cli_test.go`.
- Vendor initialization trace tests exist in adapter package tests such as
  `adapters/safenet/initialization_test.go`.

## Test Expectations

- Assert behavior, not incidental formatting.
- For JSON commands, decode structured output.
- For APDU-heavy flows, verify the important commands, state transitions, and
  fixture alignment.
