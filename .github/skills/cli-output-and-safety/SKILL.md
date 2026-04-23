---
name: cli-output-and-safety
description: Use when working on cmd/piv or internal/cli/app, especially for commands, flags, formatting, JSON output, trace routing, config handling, or destructive-operation safety. Helps keep stdout/stderr contracts stable and preserves dry-run and confirmation behavior.
---

# CLI Output And Safety

Use this skill when the task changes CLI behavior, output shape, or operator
safety.

## Workflow

1. Identify whether the change belongs in `cmd/piv/` wiring or
   `internal/cli/app/` behavior.
2. Check whether the command supports `--json`, tracing, config defaults,
   prompts, or destructive mutations.
3. Preserve the output contract:
   - JSON goes to stdout only
   - warnings, prompts, summaries, and trace lines go to stderr
4. For state-changing commands, verify whether `--dry-run`, `--yes`, and
   `--non-interactive` behavior must be updated together.
5. Add or update command-level tests before finishing.

## Repo Patterns

- Root and global flag wiring lives in `cmd/piv/root.go`.
- Rendering and error output live in `internal/cli/app/formatter.go`.
- Confirmation planning lives in `internal/cli/app/planner.go`.
- Config-backed defaults live in `internal/cli/app/config.go` and related
  helpers.

## Test Expectations

- Prefer tests similar to `cmd/piv/cli_test.go`.
- Assert stdout and stderr separately.
- For JSON commands, unmarshal the envelope and assert the result payload
  instead of comparing raw strings.
