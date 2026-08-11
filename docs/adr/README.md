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
