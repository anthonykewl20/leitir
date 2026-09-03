# AGENTS.md — Working on leitir with AI agents

## Where work comes from

- The owner assigns work directly: a task naming an issue, or an issue labeled
  `ready-for-agent`. If the label pool is empty, do not wait for promotion and
  do not ask — work the assignment you were given.
- Never self-assign issues the owner did not give you.
- Current status (test counts, releases, run evidence, milestones) lives on
  GitHub and in README's dated status paragraph — never in this file.

## Agent operating rules

1. Read the assigned issue end-to-end, then the code it names; plan locally, not on GitHub.
2. Probe first: reproduce the real defect or missing behavior with the actual code before writing anything.
3. Write the failing user-level intent test ("when a user runs X, they observe Y"), then the smallest honest fix.
4. Any integrity path touched gets a tamper/reject test in the same change.
5. Preserve the conventions below without exception.
6. Run the full suite, `ruff check .`, and `mypy src`; all green before calling anything done.
7. Behavior change means the relevant ADR and README section change in the same PR.
8. One issue, one PR, template filled, `Closes #N` in the body.
9. Address review by pushing commits; at most one "addressed in `<sha>`" note per thread.
10. Comment on GitHub only when genuinely blocked after local investigation: one blocking question, then continue what you can.
11. Never close an issue manually; its PR's merge closes it.
12. Follow-ups are finished inside the PR or filed as issues with acceptance criteria — never untracked TODOs.

## Definition of done (what stops the loop)

A task is done when its PR is green (full suite, ruff, mypy), its checklist is
complete, its review lane is satisfied, and it is mergeable with `Closes #N`.
Merging may be owner-gated; the agent is not blocked on it. After merge,
verify the issue auto-closed.

## Review lanes

- Ordinary change: one independent review (reviewer-hy3, reviewer-qwen, or a
  human equivalent — any one), after CI is green.
- Security, integrity, or materialization change (verification, manifests,
  keys, fail-closed paths, error taxonomy): both reviewers, requested together;
  each reviews the diff; no review-to-review thread.
- A misclassified lane is fixed by requesting the second review, not redoing the PR.

## Conventions (non-negotiable)

- **Stdlib-only runtime**: pyproject.toml `dependencies = []`. Do not add external deps.
- **Python ≥ 3.11**, `from __future__ import annotations`, fully typed.
- **Deterministic**: outputs must be PYTHONHASHSEED-independent. Sort paths explicitly; never rely on dict/set iteration order.
- **Fail-closed**: missing/malformed/mismatched integrity data → reject, never silently accept.
- **Atomic writes**: use the existing `_write_manifest` pattern (tempfile + `os.replace` + fsync).
- **Match existing error taxonomy**: `MaterializationError`, `VerificationError`, `TreeHashError`, etc.

## Test discipline

- Run: `PYTHONPATH=src uv run --no-project --with-requirements requirements.txt python -m pytest -q`
- Gate: zero failures; skips only where an env gate holds them back. The live
  pass/skip count is not recorded here — paste suite output into the PR.
- Live tests stay behind `LEITIR_ENABLE_LIVE_E2E=1`; never ungate them in default CI.
- Do not weaken tests. If a test caught real behavior, fix production code.
- Security/integrity changes add a tamper/reject test.

## Documentation discipline

- Behavior change ⇒ relevant ADR + README section updated in the same change.
- Rule documents (this file, CONTRIBUTING.md, docs/testing.md,
  docs/adr/README.md, and the issue/PR templates) carry invariants, never
  status. Dated records — docs/STATUS.md, ADRs, PRD status blocks — are status
  by design and are exempt; the only live suite count outside them is README's
  dated status paragraph.

## Change size

Most fixes are probe → red test → fix → PR. Write an ADR for durable
architectural choices (docs/adr/README.md), not for every change. Issue #17 is
a thorough historical example, not the default arc.

## Out of scope without explicit authorization

- No unsolicited commits. When the owner asks for work, commits, tests, docs,
  and the opened PR are part of that work.
- No dependency additions. No removal of fail-closed paths. No disabling
  load-time tree verification (`materialized_tree_hash`).
