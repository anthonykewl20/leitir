# Leitir Roadmap

## Versioning philosophy

- **v0.x** — active incremental development following SemVer. Patch releases (0.1.1, 0.1.2, ...) address audit findings, bug fixes, and incremental progress toward production-ready quality. A minor bump (0.2.0) is reserved for a real feature or behavior milestone, not routine audit work. Breaking changes are permitted within 0.x (pre-1.0) and must be called out in the changelog.
- **"Production-ready"** — a quality label, not a version number. Achieved within the 0.x series when the Critical/High audit findings are resolved, the self-scorecard passes, and real load testing confirms behavior at scale. The README's "Not production-ready" line changes when the quality bar is met, not when a specific version is cut.
- **v1.0** — reserved as a **major adoption milestone** (target: 10,000 users), not a feature or quality milestone. v1.0 happens when the community demonstrates the project has earned the stability commitment that SemVer 1.0 implies. Until then, we ship 0.x.

## Distribution

**Current (pre-public-release): GitHub-only.**

- Install: `pip install git+https://github.com/anthonykewl20/leitir.git`
- Pinned install: `pip install git+https://github.com/anthonykewl20/leitir.git@v0.1.0`
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

v0.1.0 shipped (load-time tree verification, ADR-006, process/docs scaffolding, cross-platform CI). Implementation-complete; design-stage software. **Not production-ready.** See milestone [v0.1.1](https://github.com/anthonykewl20/leitir/milestone/1) for the next incremental step.

## Recently shipped

- v0.1.0: ADR-006 load-time tree verification (#17, #18, #19, #20 — all closed)
- ADR-005: corpus-v2 capabilities (C1-C10 complete)
- ADR-004: local source materialization
- ADR-003: categorized HTTP retry
- ADR-002: deterministic evidence scoring engine (standalone repository scorer)
- ADR-001: deterministic code-search kernel

## Active work — [v0.1.1 milestone](https://github.com/anthonykewl20/leitir/milestone/1)

Track at epic #42. Critical items must close before claiming "production-ready" quality; they do not gate the v0.1.1 version number itself (0.1.1 can ship with partial progress).

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

## Post-production-ready (still v0.x)

- #40 Manifest authenticity (TUF/signatures) — adversarial threat model, separate from corruption detection
- Real load testing with 100+ package corpora
- TOCTOU hardening via filesystem snapshots

## Retired / historical

- v1 PRD: docs/PRD.md
- v1 operations: docs/operations.md
- v1 smoke evaluation: docs/smoke-evaluation.md
- Manual scorecards: docs/leitir-engine-scorecard.html, leitir-engine-scorecard-v2.html, leitir-engine-scorecard.png

These are retained for context but are never scorer evidence.

## How to contribute

AI agents: see AGENTS.md for workflow conventions.
Humans: pick an issue from the [v0.1.1 milestone](https://github.com/anthonykewl20/leitir/milestone/1) labeled `ready-for-agent` or `help wanted`.
