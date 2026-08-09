# AGENTS.md — Working on leitir with AI agents

## Where to find tracked work

- **v0.1.1 milestone**: https://github.com/anthonykewl20/leitir/milestone/1
- Pull available work with: `gh issue list --milestone "v0.1.1" --label ready-for-agent --state open`
- The release-criteria epic is #42; read it first. Note: v1.0 is reserved for the 10,000-users adoption milestone; production-ready quality is achieved within the 0.x series, not at a specific version number.

## Conventions (non-negotiable)

- **Stdlib-only runtime**: pyproject.toml `dependencies = []`. Do not add external deps.
- **Python ≥ 3.11**, `from __future__ import annotations`, fully typed.
- **Deterministic**: outputs must be PYTHONHASHSEED-independent. Sort paths explicitly; never rely on dict/set iteration order.
- **Fail-closed**: missing/malformed/mismatched integrity data → reject, never silently accept.
- **Atomic writes**: use the existing `_write_manifest` pattern (tempfile + `os.replace` + fsync).
- **Match existing error taxonomy**: `MaterializationError`, `VerificationError`, `TreeHashError`, etc.

## Test discipline

- Run: `PYTHONPATH=src uv run --no-project --with-requirements requirements.txt python -m pytest -q`
- Target: 1262+ passed (current), 0 failed.
- Live tests are gated on `LEITIR_ENABLE_LIVE_E2E=1`; don't ungate them in default CI.
- Do not weaken tests. If a test caught real behavior, fix production code.
- For security/integrity changes, add a tamper/reject test.

## Review discipline

- Security, integrity, or materialization changes require independent review by `reviewer-hy3` and `reviewer-qwen` (or human equivalent).
- The reference example of “how a fix should look” is issue #17: real probes → fix → tests → review → ADR.

## Documentation discipline

- If you change behavior, update the relevant ADR + README section in the same change.
- Status claims (test count, scorer decision) drift fast — re-verify before committing.

## Out of scope without explicit authorization

- No commits without explicit user request.
- No dependency additions.
- No removal of fail-closed paths.
- No disable of the load-time tree verification (`materialized_tree_hash`).

## Reference example

Issue #17 (https://github.com/anthonykewl20/leitir/issues/17) shows the full workflow: probe-driven weakness analysis → research → implementation → review → follow-ups → milestone tracking. Follow that pattern for new work.
