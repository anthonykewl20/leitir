# AGENTS.md — Working on leitir with AI agents

## Where to find tracked work

- **Milestone status:** [v0.1.4](https://github.com/anthonykewl20/leitir/milestone/4) is 12/12 complete and pending release; [v0.1.3](https://github.com/anthonykewl20/leitir/milestone/3) is 6/8; [v0.1.2](https://github.com/anthonykewl20/leitir/milestone/2) is 22/25.
- Pull available work with: `gh issue list --label ready-for-agent --state open`. **The ready-for-agent pool is currently empty; promotion is owner-gated.** v0.1.2 has only epic #52 plus owner-external exit/evaluation gates #73 and #75 open. In v0.1.3, #82 is closed: `occupied.py` landed via PR #139 and ADR-0017 is Implemented. Only #81 (tree-sitter; ADR-0012 open questions are answered on `main`: 0.23-aligned tuple, PEP 440 non-disjoint, musllinux-aarch64 fail-closed gap, and limits corpus-gated; implementation not started) and v2.0 authenticity epic #40 (ADR-0018 Proposed) remain. Production-readiness epic #42 remains open for human gates.
- The occupied gate's trust binding follows ADR-0017: policy-pinned authority, occupied rerun receipts, and complete dependency evidence are required for composition acceptance.
- ADR-0008 through ADR-0011 are Accepted and Implemented. ADR-0012 is Accepted with amendments; ADR-0013 through ADR-0017 and ADR-0019 are Accepted; ADR-0018 is Proposed for v2.0. Issues #76/#77/#78/#79/#80 are closed via PRs #132/#137/#136/#135/#134, with shared contract unification in PR #138; #128 is closed by PR #131's three-layer Windows fix. Main now includes `composition.py`, `architecture.py`, `duplicates.py`, `lineage.py` (plus bundle v2), `cost.py`, and `occupied.py`.
- Production-ready quality criteria stay tracked in epic #42 under the v0.1.1 milestone (all engineering issues closed; human gates remain). v0.1.2 carries the Behavioral Transplant Set (BTS) program — its exit criterion is in the milestone description. Note: v1.0 is reserved for the 10,000-users adoption milestone; production-ready quality is achieved within the 0.x series, not at a specific version number.
- The 2026-08-14 live-benchmark hardening added verified local-shelf search, Go API surface and license detection, and `go-module-zip` with SumDB authentication per ADR-0020 (issues #143–#148).

## Conventions (non-negotiable)

- **Stdlib-only runtime**: pyproject.toml `dependencies = []`. Do not add external deps.
- **Python ≥ 3.11**, `from __future__ import annotations`, fully typed.
- **Deterministic**: outputs must be PYTHONHASHSEED-independent. Sort paths explicitly; never rely on dict/set iteration order.
- **Fail-closed**: missing/malformed/mismatched integrity data → reject, never silently accept.
- **Atomic writes**: use the existing `_write_manifest` pattern (tempfile + `os.replace` + fsync).
- **Match existing error taxonomy**: `MaterializationError`, `VerificationError`, `TreeHashError`, etc.

## Test discipline

- Run: `PYTHONPATH=src uv run --no-project --with-requirements requirements.txt python -m pytest -q`
- Target: 2329 passed (current), 0 failed.
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
