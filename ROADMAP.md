# Leitir Roadmap

## Versioning philosophy

- **v0.x** — active incremental development following SemVer. Patch releases (0.1.1, 0.1.2, 0.1.3, ...) carry **all** incremental work on the path to production-ready quality: audit findings, bug fixes, **and** feature/behavior increments alike (e.g. the Behavioral Transplant Set, composition/multi-language, Search v2). The patch number is an incrementing counter per thematic milestone, not a "bugfix-only" gate; under pre-1.0 SemVer anything may change and breaking changes are permitted, but must be called out in the changelog. There is no currently planned minor bump (0.2.0); if one is ever cut it would denote a deliberate compatibility boundary within 0.x, not a feature gate.
- **"Production-ready"** — a quality label, not a version number. Achieved within the 0.x series when the Critical/High audit findings are resolved, the self-scorecard passes, and real load testing confirms behavior at scale. The README's "Not production-ready" line changes when the quality bar is met, not when a specific version is cut.
- **v1.0** — reserved as a **major adoption milestone** (target: 10,000 users), not a feature or quality milestone. v1.0 happens when the community demonstrates the project has earned the stability commitment that SemVer 1.0 implies. Until then, we ship 0.x.

## Distribution

**Current (pre-public-release): GitHub-only.**

- Install: `pip install git+https://github.com/anthonykewl20/leitir.git`
- Release artifacts: GitHub Releases (auto-built wheel + sdist via `.github/workflows/release.yml` on `v*` tag push)
- Update notifications: poll GitHub Releases API on a 24h cache; works as soon as the first `v*` tag is pushed

**Future (when ready for public release): PyPI.**

- Install becomes `pip install leitir` (the standard users expect)
- Setup is one-time (~10 minutes): create a PyPI account, enable 2FA, register a pending publisher for trusted publishing via GitHub Actions OIDC (no API token needed)
- The existing wheel build works on PyPI unchanged — zero code changes
- A `.github/workflows/publish-pypi.yml` workflow will be added alongside the existing GitHub Releases workflow; both run on tag push
- The update-check URL in `src/leitir/_update_check.py` can optionally switch from GitHub Releases API to PyPI JSON (`https://pypi.org/pypi/leitir/json`) — the rest of the module (cache, gates, threading, notice format) stays identical
- This is deferred until the maintainer decides the project is ready for broad public visibility; no deadline

## Current status

The v0.1.0 scope is implementation-complete (load-time tree verification, ADR-006, process/docs scaffolding, cross-platform CI). v0.1.1 production-readiness evidence is complete: #42 has recorded dogfood, load-test, canary, and post-#163 security-sign-off evidence, with the remaining dogfood friction retained as a tracked backlog. The BTS code for [milestone v0.1.2 — Behavioral Transplant Set](https://github.com/anthonykewl20/leitir/milestone/2) landed on `main` via PR #127; its five-donor exit corpus is repeatedly contained-green and its six-task benchmark is published. Only runtime ratification (#73) and epic #52 remain.

## Initially implemented (v0.1.0 scope)

- v0.1.0: ADR-006 load-time tree verification (#17, #18, #19, #20 — all closed)
- ADR-005: corpus-v2 capabilities (C1-C10 complete)
- ADR-004: local source materialization
- ADR-003: categorized HTTP retry
- ADR-002: deterministic evidence scoring engine (standalone repository scorer)
- ADR-001: deterministic code-search kernel

## Recently landed

- v0.1.2 BTS program via PR #127, implementing ADR-0008 through ADR-0011.
- v0.1.3 composition and multi-language wave via PRs #131–#139: composition,
  architecture, duplicates, lineage, cost, and occupied-recipient validation;
  the Windows fix for #128; ADR-0012's fully implemented stage-1 policy/registry
  and stage-2 JavaScript/TypeScript/Rust/Go graph producers in this PR; and
  ADR-0013 through ADR-0019.
- #148's CLI surfaces are complete: `bts-compute`, architecture/lineage analysis,
  capability funnel, pipeline, transplant, occupied validation, and runnable
  exit-corpus gates. #75's six-task benchmark is published at run `88330e29…`;
  five tasks are complete and `worker-shutdown-predicate` is an honest partial.
- PRs #163–#179 completed the contained Phase-A evidence, security P2 fixes,
  release-pinned rootfs, and ratification ceremony. The published
  `containment-rootfs-v1` asset is pinned to
  `sha256:ec28886a5e448e9d6b088470c85ee2e0d170e16002bd78ecc835e9d4161155ac`.
  Ratification remains held while staged mount-source tree digests drift;
  entry-level instrumentation and re-signing after stability are the remaining
  owner steps.

## v0.1.1 — production-ready audit criteria (all engineering issues closed)

Tracked at epic #42. All Critical/High/Medium/Low engineering issues below are **closed**. The real ≥100-package load-test gate passed with 116 packages (including 29 sampled-boundary cases), independent dogfood evidence is recorded, and two post-#163 security reviews recorded no P0/P1 findings; PR #166 remediated all P2 findings. The remaining dogfood friction backlog is L1, L3, L4, L7, L8, L9, M3 items 1/2, and M4. These gates do not gate the v0.1.1 version number itself.

### Critical (blocks the "production-ready" quality label)

- #22 ADR-002 contract drift (scorer ≠ runtime trust)
- #23 Missing-evidence-as-zero violates "unknown never zero"
- #41 Self-scorecard must report `decision=pass`

### High

- #24 Trust age factor unpopulated
- #28 Symlink escape from corpus root
- #31 Snapshot tarball lacks binding to lock
- #33 Corpus bench runner fully mocked
- #34 302/424 raise statements uncovered
- #35 Trust tests don't verify weighted score

### Medium / Low

- #25 Reject NaN and infinity in trust factor clamping.
- #26 Prevent plaintext HTTP requests through configurable registry URLs.
- #27 Redact opaque secrets from URL fragments, exceptions, and private-token headers.
- #29 Add per-target locking to prevent concurrent materialization cache loss.
- #30 Clean up partial staging left by abrupt process termination.
- #32 Harden snapshot imports for membership, destination, and atomicity.
- #36 Add a live-test CI canary for provider compatibility.
- #37 Audit and label tests that mock their principal operation.
- #38 Add a CI coverage-regression gate.
- #39 Close the load-time verification TOCTOU window with corpus-wide locking.

## Next milestones (incremental, shipped as patch releases)

- **[v0.1.2 — Behavioral Transplant Set](https://github.com/anthonykewl20/leitir/milestone/2)** (2 open): ADR-0008 through ADR-0011 are implemented. All five donors repeatedly complete under the contained Phase-A workflow, the rootfs is published and pinned, and #75's benchmark is published. #73 remains pending only for a stable, independently ratified runtime digest; epic #52 remains open until that exit criterion is met.
- **[v0.1.3 — Composition and multi-language](https://github.com/anthonykewl20/leitir/milestone/3)** (complete): #76, #77, #78, #79, #80, and #82 closed via PRs #132, #137, #136, #135, #134, and #139. #81's tree-sitter stages and ADR-0018 optional detached manifest authentication are landed; #148's CLI/evidence work is complete with tracker closure pending.
- **[v0.1.4 — Search v2 (wide+deep)](https://github.com/anthonykewl20/leitir/milestone/4)** (0 open): implementation complete on `main` (all slices merged and independently cross-reviewed/hardened), but no release has been cut. This is a pre-first-release repository with zero `v*` tags, and `pyproject.toml` remains at 0.1.1; cutting the release requires the owner-held version bump, tag, and push. Local trigram index (wide) + AST/heuristic adapters (deep) + truncation-safe tree walk + verified streaming. Spec: `docs/search-v2-spec.md`. The `ready-for-agent` pool is currently empty.

## Post-production-ready (still v0.x)

- #40 Manifest authenticity (TUF/signatures) — adversarial threat model, separate from corruption detection
- [x] Real load testing with 100+ package corpora — passed with 116 exercised
  packages; 29 sampled-boundary cases are recorded in
  `docs/evidence/loadtest-100-2026-08.md`.
- TOCTOU hardening via filesystem snapshots

## Retired / historical

- v1 PRD: docs/PRD.md
- v1 operations: docs/operations.md
- v1 smoke evaluation: docs/smoke-evaluation.md
- Manual scorecards: docs/leitir-engine-scorecard.html, leitir-engine-scorecard-v2.html, leitir-engine-scorecard.png

These are retained for context but are never scorer evidence.

## How to contribute

AI agents: see AGENTS.md for workflow conventions.
Humans: the ready-for-agent pool is currently empty. The remaining v0.1.2 owner work is runtime-digest instrumentation and re-ratification for #73; check the [v0.1.2 milestone](https://github.com/anthonykewl20/leitir/milestone/2) for current status.
