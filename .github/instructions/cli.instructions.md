---
applyTo: "cmd/piv/**,internal/cli/app/**"
---

# CLI and App Layer Instructions

- Keep command handlers small. Parsing flags and wiring services belongs in
  `cmd/piv/`; domain behavior belongs in `internal/cli/app/` or lower layers.
- Preserve the contract that `--json` writes machine-readable output to stdout
  only. Prompts, warnings, trace lines, and human summaries stay on stderr.
- When adding or changing commands, update both command tests and output tests.
- Reuse `Formatter`, `ErrorMapper`, `OperationPlanner`, and config helpers
  instead of creating command-specific output or confirmation code.
- For state-changing commands, keep dry-run plans stable and reviewable.
- Prefer fake reader contexts and emulator-backed cards in tests rather than
  assuming hardware access.

## Change Hints

- Output rendering changes usually belong in `internal/cli/app/formatter.go`.
- Confirmation and destructive-operation behavior usually belongs in
  `internal/cli/app/planner.go` and mutation services.
- Global flag and root wiring changes usually belong in `cmd/piv/root.go`.
