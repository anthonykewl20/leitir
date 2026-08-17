# AGENTS.md — Working on leitir with AI agents

## Where to find tracked work

- **Milestone status:** [v0.1.4](https://github.com/anthonykewl20/leitir/milestone/4) is complete and pending its owner-held release; there are no `v*` release tags and `pyproject.toml` remains 0.1.1. v0.1.3 is complete. v0.1.2 is complete and closed: the runtime digest was ratified on 2026-08-17 (owner key `7baec2e9…` signing `sha256:72949674…` via `benchmarks/exit-corpus/ratification-v1.json`), the Phase-C gate reached `complete` on branch run 32018653190 and canonical main run 32018948262 (5/5 donors), and #73/#52 were closed on that evidence; the five-donor Phase-A corpus is repeatedly contained-green and the six-task BTS benchmark is published.
- Pull available work with: `gh issue list --label ready-for-agent --state open`. **The ready-for-agent pool is currently empty; promotion is owner-gated.** PRs #163–#183 are landed: they cover contained execution, security P2 remediation, contained benchmark baselines, the published rootfs, the ratification ceremony, and the Phase-C closure evidence. #42, #75, #148, #73, and #52 are closed with their evidence. ADR-0021's manifest-free donor mount projection removed the run-to-run staged mount-source tree digest drift; runs 32008683557 and 32009633642 measured the stabilized digest byte-identically, the 2026-08-17 owner ceremony rotated the trust root (session key 8528aa69… destroyed as documented) and re-signed, and Phase-C ran `complete` (branch 32018653190, main 32018948262).
- The occupied gate's trust binding follows ADR-0017: policy-pinned authority, occupied rerun receipts, and complete dependency evidence are required for composition acceptance.
- ADR-0008 through ADR-0011 are Accepted and Implemented. ADR-0012 is Accepted and fully implemented; ADR-0013 through ADR-0019, including ADR-0018, are Accepted. Issues #76/#77/#78/#79/#80 are closed via PRs #132/#137/#136/#135/#134, with shared contract unification in PR #138; #128 is closed by PR #131's three-layer Windows fix. Main now includes `composition.py`, `architecture.py`, `duplicates.py`, `lineage.py` (plus bundle v2), `cost.py`, `occupied.py`, and the polyglot graph modules `graph/{ts_kernel,javascript,typescript,rust,go}.py`, with graph policy/registry scaffolding and `requirements-tree-sitter.lock`.
- The contained workflow uses the published `containment-rootfs-v1` release asset, whose canonical tree digest is `sha256:ec28886a5e448e9d6b088470c85ee2e0d170e16002bd78ecc835e9d4161155ac`; consumers verify it before policy construction. The Ed25519 key sidecar and trusted-key configuration are committed and bind the ratified runtime digest `sha256:72949674…` (owner key `7baec2e9…`, 2026-08-17); acceptance evidence is the Phase-C COMPLETE exit-gate run on `main` ([32018948262](https://github.com/anthonykewl20/leitir/actions/runs/32018948262)).
- The daily `GH_TOKEN`-gated live canary is enabled and green on main. Production-readiness evidence includes the 116-package load test, dogfood evidence (with a tracked low/medium friction backlog), and post-#163 independent security sign-offs with P2 remediation. Note: v1.0 is reserved for the 10,000-users adoption milestone; production-ready quality is achieved within the 0.x series, not at a specific version number.

## Conventions (non-negotiable)

- **Stdlib-only runtime**: pyproject.toml `dependencies = []`. Do not add external deps.
- **Python ≥ 3.11**, `from __future__ import annotations`, fully typed.
- **Deterministic**: outputs must be PYTHONHASHSEED-independent. Sort paths explicitly; never rely on dict/set iteration order.
- **Fail-closed**: missing/malformed/mismatched integrity data → reject, never silently accept.
- **Atomic writes**: use the existing `_write_manifest` pattern (tempfile + `os.replace` + fsync).
- **Match existing error taxonomy**: `MaterializationError`, `VerificationError`, `TreeHashError`, etc.

## Test discipline

- Run: `PYTHONPATH=src uv run --no-project --with-requirements requirements.txt python -m pytest -q`
- Target: 2661 passed / 123 skipped (current; the six L5 ratification tests additionally run with the optional `cryptography` extra), 0 failed; installing the tree-sitter extra runs 105 additional polyglot tests.
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
