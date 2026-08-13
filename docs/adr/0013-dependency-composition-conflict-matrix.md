# ADR-0013: Dependency composition conflict matrix

- Status: Accepted
- Deciders: leitir maintainers; consensus reviewers; consensus-terra review 2026-08-13 (ACCEPT-WITH-AMENDMENTS, amendments applied same day)
- Date: 2026-08-13
- Technical Story: #76 — Dependency and version conflict matrix across candidates

## Context and Problem Statement

ADR-0010 can select individually suitable candidates, but does not establish
that several candidates and one recipient can coexist. Their dependency evidence
may be incomplete or may prove incompatible exact versions. Composition needs a
deterministic evidence artifact and a separate fail-closed authorization gate;
it must not silently choose a version or treat missing transitive dependencies as
an empty closure.

## Decision Drivers

- Authorizing dependency evidence must come from verified manifest bytes and the
  existing parsers, never host paths or installed packages.
- Exact version clashes are non-compensating and are never auto-resolved.
- Direct-only evidence proves direct dependencies but says nothing about absent
  transitives.
- Pair construction, record ordering, duplicate handling, limits, serialization,
  and rejection behavior must be exhaustive and deterministic.
- Evidence production and composition eligibility must remain separate.

## Considered Options

- Let the assembler pick one version or use ecosystem range resolution.
- Treat absent or direct-only transitive records as empty complete closures.
- Produce a deterministic evidence matrix and evaluate it through a separate
  three-state eligibility gate (chosen).

## Decision Outcome

Chosen option: "a deterministic conflict-evidence matrix plus a separate
three-state composition-eligibility gate", because it preserves uncertainty,
prevents an evidence report from becoming an assembler, and makes every
authorization input reviewable.

### 1. Shared composition record contract

The composition-planner cluster uses the following normative record shapes. All
records are frozen, slotted dataclasses. Enums serialize by `.value`; `NodeId`,
`SourceRef`, `Edge`, and dependency identities retain their existing ADR-0008
and `lockfiles.py` meanings. `EvidenceRef` is the existing content-bound evidence
reference type. These same shapes are repeated in ADR-0014 and ADR-0015 so that
each decision states the complete consumed contract.

```python
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

class ClosureCompleteness(str, Enum):
    COMPLETE = "complete"
    DIRECT_ONLY = "direct_only"
    UNKNOWN = "unknown"

class CompatibilityStatus(str, Enum):
    COMPATIBLE = "compatible"
    INCOMPATIBLE = "incompatible"
    UNKNOWN = "unknown"

class CompositionEligibilityStatus(str, Enum):
    ACCEPT = "accept"
    REJECT = "reject"
    INDETERMINATE = "indeterminate"

class ConflictKind(str, Enum):
    VERSION_CLASH = "version_clash"
    BLOCKING_CALL_IN_ASYNC_PATH = "blocking_call_in_async_path"
    UNKNOWN_ASYNC_EXTERNAL_EFFECT = "unknown_async_external_effect"
    EXACT_SEED_BYTES_DUPLICATE = "exact_seed_bytes_duplicate"
    BTS_MEMBER_SPAN_OVERLAP = "bts_member_span_overlap"
    DEPENDENCY_DECLARATION_OVERLAP = "dependency_declaration_overlap"

@dataclass(frozen=True, slots=True)
class CompositionCandidateRef:
    candidate_key: tuple[str | int, ...]
    bts_digest: str
    candidate_manifest_digest: str
    graph_digest: str

@dataclass(frozen=True, slots=True)
class CandidateDependencyEvidence:
    subject: CompositionCandidateRef
    ecosystem: str
    name: str
    version: str
    resolved_sha: str | None
    completeness: ClosureCompleteness
    source_path: str
    source_digest: str

@dataclass(frozen=True, slots=True)
class BlockingCallCatalogEntry:
    target: NodeId
    effect_id: str
    catalog_entry_digest: str

@dataclass(frozen=True, slots=True)
class AsyncPathEvidence:
    subject: CompositionCandidateRef
    source: NodeId
    target: NodeId
    calls: tuple[Edge, ...]
    status: CompatibilityStatus
    conflict_kind: ConflictKind
    catalog_entry: BlockingCallCatalogEntry | None
    evidence_digest: str

@dataclass(frozen=True, slots=True)
class ArchitectureAssessment:
    subject: CompositionCandidateRef
    concurrency_model: str
    async_paths: tuple[AsyncPathEvidence, ...]
    logging_observations: tuple[EvidenceRef, ...]
    error_taxonomy_observations: tuple[EvidenceRef, ...]
    config_observations: tuple[EvidenceRef, ...]
    platform_observations: tuple[EvidenceRef, ...]
    status: CompatibilityStatus
    assessment_digest: str

@dataclass(frozen=True, slots=True)
class MemberSpanOverlap:
    left: CompositionCandidateRef
    right: CompositionCandidateRef
    left_source: SourceRef
    right_source: SourceRef
    intersection_lines: int
    union_lines: int
    member_span_overlap_bps: int
    evidence_digest: str

@dataclass(frozen=True, slots=True)
class DuplicateAssessment:
    left: CompositionCandidateRef
    right: CompositionCandidateRef
    kind: ConflictKind
    status: CompatibilityStatus
    member_overlaps: tuple[MemberSpanOverlap, ...]
    evidence_refs: tuple[EvidenceRef, ...]
    assessment_digest: str

@dataclass(frozen=True, slots=True)
class ConflictRecord:
    left: CompositionCandidateRef
    right: CompositionCandidateRef
    kind: ConflictKind
    status: CompatibilityStatus
    evidence_key: tuple[str | int, ...]
    evidence_digest: str
    detail_code: str

@dataclass(frozen=True, slots=True)
class ConflictMatrix:
    schema_version: str
    recipient_subject: str
    candidates: tuple[CompositionCandidateRef, ...]
    dependencies: tuple[CandidateDependencyEvidence, ...]
    architecture: tuple[ArchitectureAssessment, ...]
    duplicates: tuple[DuplicateAssessment, ...]
    conflicts: tuple[ConflictRecord, ...]
    policy_digest: str
    matrix_digest: str

@dataclass(frozen=True, slots=True)
class CompositionEligibility:
    schema_version: str
    matrix_digest: str
    status: CompositionEligibilityStatus
    blocking_conflict_keys: tuple[tuple[str | int, ...], ...]
    unknown_evidence_keys: tuple[tuple[str | int, ...], ...]
    detail_code: str | None
    eligibility_digest: str
```

Closed-schema decoding rejects unknown or missing fields, enum values, schema
versions, malformed digests, booleans in integer fields, unbounded integers, and
duplicate exhaustive keys. Implementations may use type aliases to express the
existing `CandidateKey`, but may not narrow or reorder its elements.

### 2. Manifest-bound closure evidence

`compose()` obtains every candidate closure **only** through
`dependency_closures_from_manifest()` over candidate-manifest bytes whose length
and SHA-256 have already been verified. The function at `lockfiles.py:805-861`
is the authorizing path: it reads no host path, validates duplicate paths and
byte identities, parses only declared sources, and retains diagnostics. The
host-path `dependency_closures()` API is forbidden here, as it is for authorizing
recipient profiles under ADR-0010 section 2. ADR-0011 reuse packets are not
elevated into dependency-manifest authority.

Completeness is exactly `complete`, `direct_only`, or `unknown`. `complete`
asserts that the supported manifest source supplied the complete represented
closure. `direct_only` means the declared direct dependencies are known while
the absence of every transitive dependency is **unknown**. It therefore creates
an unknown matrix cell; it is never expanded into a fabricated empty closure and
blocks composition acceptance. `unknown` means the required dependency evidence
itself is unavailable or unresolved and has the same non-authorizing effect.

Dependency identity is the exact triple `(ecosystem, name, version)`, after the
existing ecosystem normalization. `VERSION_CLASH` is emitted when two subjects
contain the same `(ecosystem, name)` with distinct exact `version` strings.
Ranges are not solved and semantic-version preference is not inferred. A clash
is always incompatible and no planner, renderer, or assembler may choose one
version automatically. Equal triples are overlap evidence governed by ADR-0015,
not a clash.

### 3. Matrix construction and composition eligibility

`ConflictMatrix` is an **evidence artifact**, never an assembler or conflict
resolver. Candidate pairs are constructed exactly as:

```python
for left, right in combinations(sorted(candidate_keys), 2):
    ...
```

Candidate-versus-recipient evaluation uses the same sorted candidate order
against one fixed recipient subject. Candidate references sort by complete
`candidate_key`. Dependency evidence sorts by `(candidate_key, ecosystem, name,
version, resolved_sha or "", completeness.value, source_path, source_digest)`.
All emitted records sort by the complete pair key—left complete candidate key,
right complete candidate key—then `(kind.value, status.value, evidence_key,
evidence_digest, detail_code)`. Equal complete keys are rejected, never collapsed.

The separate `CompositionEligibility` gate consumes a validated matrix:

1. a known version clash, typed blocking-in-async incompatibility, or exact
   duplicate produces `REJECT`;
2. direct-only or otherwise unknown required evidence produces
   `INDETERMINATE`; and
3. only complete, non-conflicting required evidence produces `ACCEPT`.

Advisory overlaps cannot reject. A known rejection retains all simultaneous
unknowns, but rejection has summary precedence. A missing, malformed, mismatched,
or omitted consumed record raises
`BTSError(BTSRejectReason.REJECT_HARD_GATE_FAILED,
detail_code="composition_input_missing_v1")`. A present, valid `UNKNOWN` record
produces `INDETERMINATE`; it is never coerced to pass.

This is a new **post-selection** gate, not an ADR-0010 suitability dimension.
No amendment to ADR-0008, ADR-0010, or ADR-0011 is required: BTS authority,
candidate scoring/comparison, and reuse-packet authority remain unchanged.

### 4. Determinism, limits, and fail-closed behavior

The maintainer-pinned composition policy binds schema and algorithm versions,
supported ecosystems, all positive bounds, reason/detail registry identity, and
its content digest. Bounds cover candidates, manifest files/bytes, dependency
records, pairs, conflicts, architecture paths, path edges, duplicate assessments,
evidence records, and total work units. Every unit is charged prospectively in
canonical input order; exhaustion rejects and cannot yield a partial accepting
matrix.

Canonical JSON uses strict UTF-8, sorted object keys, compact separators,
`ensure_ascii=False`, `allow_nan=False`, and one LF. Digests are lowercase
`sha256:<64 hex>` over the canonical payload with the digest field omitted.
Output is byte-identical across input permutations and `PYTHONHASHSEED` values.
No filesystem order, host import, installed version, clock, locale, or network
result enters the artifact.

### Positive Consequences

- Composition cannot hide exact dependency conflicts or incomplete closures.
- Existing manifest-backed parsers remain the single dependency authority.
- Evidence reporting is cleanly separated from assembly authorization.

### Negative Consequences

- Direct-only Python dependency evidence commonly makes composition
  indeterminate until a complete, supported closure is supplied.
- Exact-version comparison deliberately rejects combinations an ecosystem solver
  might repair after a separate reviewed planning step.
- The matrix and gate add canonical schemas, limits, and policy digests to
  maintain.

## Pros and Cons of the Options

### Automatic version selection

- Good, because more candidate sets could be assembled without intervention.
- Bad, because selection changes verified dependency identity and can hide a real
  incompatibility.

### Treat incomplete closures as empty

- Good, because it produces fewer conflicts.
- Bad, because absence of transitive evidence is not evidence of no transitives.

### Evidence matrix and separate gate

- Good, because all conflicts and unknowns remain explicit and deterministic.
- Bad, because conservative evidence can leave composition indeterminate.

## Consequences

The implementation gate is `tests/test_composition_conflicts.py`. It must cover
complete, direct-only, and unknown closures; exact same-package/different-version
clashes; equal declarations; candidate and recipient pairing; input permutations;
hash-seed independence; limits; duplicate keys; and canonical round trips. Tamper
tests must reject an omitted known clash, a missing candidate closure, altered
manifest bytes/digests, a mismatched matrix digest, and malformed or substituted
eligibility input.

## Open Questions

None for the v1 semantics. Concrete corpus-measured limits and the initial
maintainer policy digest must be ratified before implementation authorizes output.

## Links

- [#76 — Dependency and version conflict matrix](https://github.com/anthonykewl20/leitir/issues/76)
- [ADR-0008 — Behavioral Transplant Set foundation](0008-behavioral-transplant-set.md)
- [ADR-0010 — Capability and suitability](0010-capability-and-suitability.md)
- [ADR-0011 — Reuse packet and attribution](0011-reuse-packet-and-attribution.md)
- [ADR-0014 — Structural architecture compatibility](0014-structural-architecture-compatibility.md)
- [ADR-0015 — Duplicate abstraction detection](0015-duplicate-abstraction-detection.md)
