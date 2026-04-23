---
name: git-commit-workflow
description: Use when the task involves preparing, reviewing, staging, or committing repository changes. Helps keep commits focused, avoids bundling unrelated diffs, and keeps commit messages consistent with the repository's expected style.
---

# Git Commit Workflow

Use this skill when the user asks to commit changes or when you need to prepare
changes for a reviewable commit.

## Workflow

1. Inspect the current worktree before staging anything.
2. Separate task-related changes from unrelated local modifications.
3. Stage only the files that belong to the requested change.
4. Review the staged diff before writing the commit message.
5. Use a concise English commit message with an appropriate Conventional Commit
   prefix when it fits the change.

## Guardrails

- Do not include unrelated user changes in the commit.
- Do not rewrite or revert unrelated work to make the tree look clean.
- Do not create a commit automatically unless the user asked for one.
- If the worktree is mixed and the task-related subset is unclear, inspect the
  diff carefully before staging.

## Repo Expectations

- Preferred prefixes: `feat:`, `fix:`, `docs:`, `test:`, `refactor:`,
  `chore:`, `ci:`.
- Keep one logical change per commit when practical.
- Validation should happen before committing whenever the task changed code or
  behavior.

## Practical Checks

- Use `git status --short` to see the worktree shape.
- Use `git diff` and `git diff --cached` to review unstaged and staged changes.
- If only part of a file belongs in the commit, handle staging deliberately
  rather than assuming the full file should go in.
