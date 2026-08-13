# ADR-0019: Integration-cost evidence

- Status: Accepted
- Deciders: leitir maintainers; consensus reviewers; consensus-terra review 2026-08-13 (ACCEPT-WITH-AMENDMENTS, amendments applied same day)
- Date: 2026-08-13
- Technical Story: #79 — Deterministic integration-cost evidence

## Context and Problem Statement

ADR-0010 section 6 already defines independent dependency-cost and extraction-
difficulty dimensions. Composition can now measure some inputs more precisely,
but many proposed "cost" values require recipient-specific plans or human
prediction. Leitir needs an advisory evidence record that feeds existing typed
dimensions without creating a new score or fabricating zeroes.

## Decision Drivers

- Measurements must come from complete, digest-bound BTS and composition inputs.
- Missing evidence and collector faults remain distinct under ADR-0002.
- Adapter instances, external identities, lines, and dependency directness have
  different authorities and must not be conflated.
- Human effort and success probability must not acquire false numeric precision.
- Advisory evidence cannot affect survivor eligibility.

## Considered Options

- Produce a scalar integration-cost score with numeric confidence.
- Treat unknown quantities as zero and infer dependency directness from lockfiles.
- Emit typed observations that feed ADR-0010's existing dimensions and preserve
  unknown/error states (chosen).

## Decision Outcome

Chosen option: "closed advisory observations mapped into ADR-0010's existing
dimension values", because it improves exact evidence without adding a
compensating rank, comparator, or eligibility path.

### 1. Mapping to existing dimensions

`IntegrationCostEvidence` feeds, but does not replace, ADR-0010 section 6:

| Evidence | Existing destination |
|---|---|
| `BTSReport.members` count | `ExtractionDifficultyValue.bts_members` |
| `BudgetCounters.source_lines` | `ExtractionDifficultyValue.source_lines` |
| counted ADAPT instances | `ExtractionDifficultyValue.adapters` |
| unique EXTERNAL target identities | `ExtractionDifficultyValue.external_interfaces` |
| proved new direct dependencies | `DependencyCostValue.new_direct` |
| proved new transitive dependencies | `DependencyCostValue.new_transitive` |

ADAPT instance count **replaces** any separate adapter count; it is not added to
one. A nonzero unresolved dependency count can never be represented as a known
`DependencyCostValue`, whose ADR-0010 contract requires unresolved zero.

### 2. Measurable components and exact authority

The following are measurable now from a validated `COMPLETE` BTS report:

- ADAPT, REPLACE, and EXTERNAL edge-classification tuples count
  `DispositionEvidence` records that have an edge. Rules and target declarations
  without an edge are not instances. Records sort by `_disposition_key`
  (`bts.py:775-777`).
- `BudgetCounters.external_interfaces` counts unique EXTERNAL target identities.
  It remains distinct from the count of EXTERNAL disposition instances; repeated
  edges can share one target.
- `adapter_template_physical_lines` is measured from catalog template UTF-8 bytes
  only after verifying `sha256(template) == template_bytes_sha256`. A digest does
  not reveal a length. Rendered line count remains unknown unless a pinned method
  proves substitution line-preserving. This observation is physical template
  lines, never "semantic LOC".

Dependency additions are known only when a recipient profile and snapshot-bound
candidate direct-requirement evidence are present and the dependency closure is
complete. `DependencyEdge` has no directness field (`lockfiles.py:25-32`), so it
cannot independently establish direct versus transitive additions. A closure
with unresolved evidence yields `unknown` or `error`, never a known count.

Dependency removals remain unknown until a pinned recipient-modification plan
proves exact before/after requirements. Test-surface change remains unknown until
a pinned relocation plan supplies exact before/after test manifests. Human
effort, success probability, and maintenance burden are unknown forever and are
never encoded as numbers.

### 3. Typed observation contract

All records are frozen, slotted dataclasses. Closed-schema decoding and
construction reject unknown fields, invalid state/value combinations, malformed
digests, unsupported method versions, duplicate keys, and noncanonical ordering.

```python
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

class CostObservationState(str, Enum):
    KNOWN = "known"
    UNKNOWN = "unknown"
    ERROR = "error"
    SKIPPED = "skipped"
    NOT_APPLICABLE = "not_applicable"

class CostConfidence(str, Enum):
    EXACT = "exact"

@dataclass(frozen=True, slots=True)
class CostMethod:
    method_id: str
    method_version: str
    input_digests: tuple[str, ...]
    method_digest: str

@dataclass(frozen=True, slots=True)
class CostObservation:
    state: CostObservationState
    value: int | None
    confidence: CostConfidence | None
    method: CostMethod
    detail_code: str

@dataclass(frozen=True, slots=True)
class DependencyDelta:
    state: CostObservationState
    confidence: CostConfidence | None
    new_direct: int | None
    new_transitive: int | None
    removed_direct: int | None
    removed_transitive: int | None
    unresolved: int
    before_manifest_digest: str | None
    after_manifest_digest: str | None
    method: CostMethod

@dataclass(frozen=True, slots=True, order=True)
class TestSurfaceChange:
    path: str
    before_sha256: str | None
    after_sha256: str | None
    change_kind: str

@dataclass(frozen=True, slots=True)
class IntegrationCostEvidence:
    schema_version: str
    candidate_key: CandidateKey
    bts_digest: str
    recipient_profile_digest: str | None
    bts_members: CostObservation
    source_lines: CostObservation
    adapt_instances: CostObservation
    replace_instances: CostObservation
    external_instances: CostObservation
    external_interfaces: CostObservation
    adapter_template_physical_lines: CostObservation
    dependency_delta: DependencyDelta
    test_surface_state: CostObservationState
    test_surface_confidence: CostConfidence | None
    test_surface_changes: tuple[TestSurfaceChange, ...]
    evidence_digest: str
```

`CostObservation` is a closed record of `state`, `value: int | None`,
`confidence`, `method`, and typed detail code. State is exactly `known`,
`unknown`, `error`, `skipped`, or `not_applicable`. `confidence="exact"` is
allowed only with `known`; every other state requires `confidence=None` and no
numeric value. Numeric confidence is forbidden. This preserves ADR-0002's
distinction between absent evidence and collector failure.

Construction rejects unknown-plus-zero substitution, including an `UNKNOWN`
state carrying `0`, an unresolved dependency observation carrying known values,
or an empty incomplete closure represented as no additions. `NOT_APPLICABLE`
requires proof from the pinned method; unsupported collection is not N/A.

### 4. Structural advisory-only guarantee

The evidence record is structurally advisory. It is not accepted as an input to
`evaluate_gates`, `GateOutcome`, or `SurvivorSet` (`suitability.py:235-287, 454`). It
cannot change `GateVerdictStatus`, eligibility, comparison authorization, or the
candidate population. It exposes no `total`, `score`, ordering method, aggregate,
or comparator. Consumers may map exact known fields only into the existing
dimension value types; unresolved fields preserve the destination's unknown
semantics.

### 5. Deterministic ordering and identity

Canonical order is pinned as follows:

- candidate subjects use the complete ADR-0010 `CandidateKey`;
- disposition instances use `_disposition_key`;
- adapter instances use `(_disposition_key, adapter_id,
  template_bytes_sha256, parameters)`;
- node identities use `_node_id_key`;
- resolved dependencies use `(ecosystem, name, version,
  resolved_sha or "", spec)`;
- declared dependencies use `DeclaredDependency` field order; and
- test changes use `(path, before_sha256 or "", after_sha256 or "",
  change_kind)`.

Each key is exhaustive; duplicate complete keys reject. Canonical JSON uses
strict UTF-8, sorted object keys, compact separators, `ensure_ascii=False`,
`allow_nan=False`, and one LF. Digests are lowercase `sha256:<64 hex>` over the
canonical payload with the digest field omitted.

### 6. Test gate

The implementation gate is `tests/test_composition_cost.py`. It covers complete
BTS disposition-instance counts versus unique targets, verified template bytes
and non-line-preserving substitutions, complete and incomplete dependency
evidence, absent directness, recipient-specific additions/removals, before/after
test manifests, every observation state, unknown-plus-zero rejection, advisory-
only API boundaries, duplicate/order permutations, canonical round trips,
tampering, and hash-seed independence.

### Positive Consequences

- Existing comparison dimensions receive more exact, reviewable evidence.
- Unknown and failed collection cannot look artificially cheap.
- Instance counts remain distinct from unique interface counts.

### Negative Consequences

- Many desirable quantities remain honestly unknown without recipient plans.
- No scalar answer is available for sorting candidates by "integration cost."
- Additional method identities and evidence digests require maintenance.

## Links

- [#79 — Integration-cost evidence](https://github.com/anthonykewl20/leitir/issues/79)
- [ADR-0002 — Deterministic evidence scoring](0002-deterministic-evidence-scoring-engine.md)
- [ADR-0010 — Capability and suitability](0010-capability-and-suitability.md)
