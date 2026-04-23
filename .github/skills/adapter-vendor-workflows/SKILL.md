---
name: adapter-vendor-workflows
description: Use when changing adapters, adapter runtime resolution, vendor-specific token behavior, capability reporting, initialization/reset flows, or built-in adapter registration. Helps keep vendor logic in the right package and aligned with emulator-backed tests.
---

# Adapter Vendor Workflows

Use this skill for SafeNet, YubiKey, or shared adapter-layer changes.

## Workflow

1. Decide whether the behavior is generic adapter infrastructure or
   vendor-specific behavior.
2. Keep generic logic in shared adapter helpers only when it is reused across
   vendors without vendor conditionals.
3. Keep vendor-specific command sequences, object aliases, defaults, and reset
   flows inside the owning vendor package.
4. If registration or matching changes, review `adapters/registry.go` and
   `adapters/all/imports.go`.
5. Update capability reports, traces, and tests together when behavior changes.

## Repo Patterns

- Shared adapter orchestration lives under `adapters/`.
- Built-in registrations live under `adapters/all/`.
- SafeNet-specific logic lives under `adapters/safenet/`.
- YubiKey-specific logic lives under `adapters/yubikey/`.

## Test Expectations

- Prefer emulator-backed or fake-session tests over hardware-dependent tests.
- When APDU traces are part of the behavior, keep them stable and update the
  relevant `testdata` fixtures intentionally.
- Preserve observer comments and APDU log collection where the package already
  exposes them.
