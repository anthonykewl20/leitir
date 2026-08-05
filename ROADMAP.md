# Leitir Roadmap

## Current status

Implementation-complete; design-stage software. Not production-ready (see milestone https://github.com/anthonykewl20/leitir/milestone/1 for the v1.0 release criteria).

## Recently shipped

- ADR-006: load-time tree verification (#17, #18, #19, #20 — all closed)
- ADR-005: corpus-v2 capabilities (C1-C10 complete)
- ADR-004: local source materialization
- ADR-003: categorized HTTP retry
- ADR-002: deterministic evidence scoring engine (standalone repository scorer)
- ADR-001: deterministic code-search kernel

## Active work (Production-ready v1.0 milestone)

[Production-ready v1.0 milestone](https://github.com/anthonykewl20/leitir/milestone/1)

### Critical (blocks release)

- #22 ADR-002 contract drift (scorer ≠ runtime trust)
- #23 Missing-evidence-as-zero violates “unknown never zero”
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

## Deferred to v2.0+

- #40 Manifest authenticity (TUF/signatures)
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
Humans: pick an issue from the milestone labeled `ready-for-agent` or `help wanted`.
