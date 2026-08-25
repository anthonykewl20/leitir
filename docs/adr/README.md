# Architectural Decision Records

This log lists the architectural decisions for leitir. For new ADRs,
please use [`template.md`](template.md) as the basis.

| ADR | Title | Status | Date |
|---|---|---|---|
| [0001](0001-remove-hy3-deterministic-search.md) | Remove Hy3; deterministic search | Accepted | 2026-06 |
| [0002](0002-deterministic-evidence-scoring-engine.md) | Deterministic evidence scoring engine | Accepted | 2026-07 |
| [0003](0003-categorized-http-retry.md) | Categorized HTTP retry | Accepted | 2026-07 |
| [0004](0004-local-source-materialization.md) | Local source materialization | Accepted | 2026-07 |
| [0005](0005-corpus-v2-capabilities.md) | Corpus v2 capabilities | Accepted | 2026-07 |
| [0006](0006-load-time-tree-verification.md) | Load-time tree verification | Accepted | 2026-08 |
| [0007](0007-environment-integrity-doctor.md) | Environment and integrity doctor | Accepted | 2026-08 |
| [0008](0008-behavioral-transplant-set.md) | Behavioral Transplant Set foundation | Accepted | 2026-08 |
| [0009](0009-transplant-validation.md) | Transplant validation | Accepted | 2026-08 |
| [0010](0010-capability-and-suitability.md) | Capability and suitability | Accepted | 2026-08 |
| [0011](0011-reuse-packet-and-attribution.md) | Reuse packet and attribution | Accepted | 2026-08 |
| [0012](0012-polyglot-graph-via-tree-sitter.md) | Polyglot graph via tree-sitter | Accepted | 2026-08-13 |
| [0013](0013-dependency-composition-conflict-matrix.md) | Dependency composition conflict matrix | Accepted | 2026-08-13 |
| [0014](0014-structural-architecture-compatibility.md) | Structural architecture compatibility | Accepted | 2026-08-13 |
| [0015](0015-duplicate-abstraction-detection.md) | Duplicate abstraction detection | Accepted | 2026-08-13 |
| [0016](0016-lineage-and-drift-tracking.md) | Lineage and drift tracking | Accepted | 2026-08-13 |
| [0017](0017-occupied-recipient-validation-gate.md) | Occupied-recipient validation gate | Accepted | 2026-08-13 |
| [0018](0018-manifest-authenticity.md) | Manifest authenticity | Accepted | 2026-08-13 |
| [0019](0019-integration-cost-evidence.md) | Integration-cost evidence | Accepted | 2026-08-13 |
| [0020](0020-go-module-authenticity-via-sumdb.md) | Go module authenticity via SumDB | Accepted | 2026-08-14 |
| [0021](0021-deterministic-donor-mount-projection.md) | Deterministic donor mount projection for runtime-digest stability | Accepted | 2026-08-17 |
| [0022](0022-trusted-key-lifecycle.md) | Trusted-key lifecycle: expiry and revocation in a versioned trusted-keys schema | Accepted | 2026-08-20 |
| [0023](0023-registry-only-degraded-resolution.md) | Registry-only degraded resolution when the repository tag lookup is unavailable | Accepted | 2026-08-23 |
| [0024](0024-local-first-cached-resolution.md) | Local-first resolution for exact ecosystem pins from verified cached shelves | Accepted | 2026-08-23 |
| [0025](0025-usage-evidence-and-replay-contract.md) | Usage evidence and offline replay contract | Accepted | 2026-08-25 |
| [0026](0026-conservative-admission-and-import-catalog.md) | Conservative consumer admission and distribution-to-import-root cataloging | Accepted | 2026-08-25 |
| [0027](0027-static-python-usage-resolver.md) | Static, execution-free resolution of Python consumer usage | Accepted | 2026-08-25 |
| [0028](0028-deterministic-usage-evidence-assembly.md) | Deterministic assembly of bounded, explainable usage evidence | Accepted | 2026-08-25 |
| [0029](0029-offline-usage-cli-verification-and-replay.md) | Offline usage CLI verification, replay, and opt-in pinned public-source E2E | Accepted | 2026-08-25 |

## Status vocabulary

Each ADR has a Status field with one of:

- **proposed** — open for consideration
- **accepted** — the decision is in force
- **rejected** — a record of a path not taken (kept for context)
- **deprecated** — superseded by events but not replaced
- **superseded** — replaced by a later ADR; include `Superseded by: [ADR-NNNN](...)`

Implementation state is tracked separately as `Implementation: not-started | in-progress | complete`.
Decision state and implementation state must not be conflated.

## When to write an ADR

Write an ADR when making a durable architectural choice that future contributors
need to understand. See ADR-0001 onwards for examples. For large, contested, or
cross-cutting proposals, open a design issue first and record the accepted
decision as an ADR once consensus is reached.
