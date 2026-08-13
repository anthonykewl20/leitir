# ADR-0014: Structural architecture compatibility

- Status: Accepted
- Deciders: leitir maintainers; consensus reviewers; consensus-terra review 2026-08-13 (ACCEPT-WITH-AMENDMENTS, amendments applied same day)
- Date: 2026-08-13
- Technical Story: #77 — Architectural compatibility analysis

## Context and Problem Statement

Individually suitable code can block an async recipient when a reachable call
chain invokes blocking work. Logging, errors, configuration, and platform usage
also matter to integration, but v1 lacks sound rules that make them composition
incompatibilities. The planner needs one narrow, structurally proved hard
architecture conflict while retaining all unresolved external effects and other
architecture facts as typed evidence.

## Decision Drivers

- A hard incompatibility needs a complete resolved `CALLS` path with provenance.
- Blocking identity must come from finite maintainer-pinned data, never imports,
  runtime probing, naming, or ambient packages.
- A sync helper on an async-rooted path must not hide blocking behavior.
- Uncatalogued external effects are unknown, not clean.
- Architecture observations without a ratified incompatibility rule must remain
  observations.

## Considered Options

- Infer blockingness from names, installed packages, or runtime probes.
- Treat every architecture difference as a hard incompatibility.
- Prove one catalogued blocking-in-async conflict and preserve every other fact
  or unresolved effect as typed evidence (chosen).

## Decision Outcome

Chosen option: "one provenance-complete blocking-call rule backed by a pinned
catalog", because it catches the accepted v1 failure mode without turning
heuristics or host state into authorization.

### 1. Shared composition record contract

ADR-0013 owns the shared architecture and field semantics. This ADR uses the
same normative frozen, slotted contract in full:

```python
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

`ConflictMatrix` remains evidence, never an assembler or resolver.
`CompositionEligibility` applies ADR-0013's algebra: known version clash, typed
blocking-in-async incompatibility, or exact duplicate is `REJECT`; unknown
required evidence is `INDETERMINATE`; only complete conflict-free evidence is
`ACCEPT`. Missing, malformed, or mismatched consumed records raise
`BTSError(BTSRejectReason.REJECT_HARD_GATE_FAILED,
detail_code="composition_input_missing_v1")`; a present valid unknown never
passes.

### 2. The sole v1 blocking incompatibility

V1 has **exactly one** blocking incompatibility kind:
`BLOCKING_CALL_IN_ASYNC_PATH`. It is emitted only when all four conditions hold:

1. a reachable source is `ASYNC_FUNCTION` or `ASYNC_METHOD`;
2. a deterministic path of resolved `CALLS` edges reaches a catalogued blocking
   target;
3. every edge has graph provenance; and
4. the target exactly matches one `BlockingCallCatalogEntry`.

The path may traverse sync donor helpers. Async safety is a property of all
resolved calls reachable from the async root, not merely calls whose immediate
source is async. The emitted `AsyncPathEvidence.calls` contains the complete
ordered path; zero-length paths, dangling endpoints, non-`CALLS` edges, missing
provenance, a wrong root kind, or a nonmatching catalog target cannot produce the
hard conflict.

`BlockingCallCatalog` is maintainer-pinned, content-addressed, finite, and
versioned. Its envelope binds schema, authority, catalog ID/version, sorted unique
entries, and content digest. This follows the static `_RESOURCE_BUILTIN_CALLS`
set in `graph/python.py:76` and is analogous to `StdlibIdentity.allowlist`
in `bts.py:184-203`: policy data is explicit and sorted, not discovered from the
running interpreter. The analyzer must never import an installed library to
discover blockingness.

### 3. Unknown external effects and concurrency model

An uncatalogued `DECLARED_EXTERNAL` call on an async path emits
`UNKNOWN_ASYNC_EXTERNAL_EFFECT`, with `status=UNKNOWN`; it is not evidence that
the path is clean. Composition requiring async safety therefore becomes
`INDETERMINATE`. No host import, execution, timing probe, network access, or
runtime observation may upgrade it. Evidence from `graph/runtime.py` is
diagnostic-only and cannot authorize compatibility or erase static uncertainty.

Concurrency model is exactly `sync`, `async`, `mixed`, or `unknown`. It derives
only from declared runtime/configuration facts plus bounded graph syntax. This
formalizes ADR-0010 section 2's existing rule and excludes suggestive dependency
names, imported host behavior, and runtime probing. An unresolved required fact
produces `unknown`, not the closest known model.

Logging style, error taxonomy, configuration access, and platform assumptions
are typed `EvidenceRef` observations in v1. They are not `ConflictKind` values,
cannot produce `INCOMPATIBLE`, and do not change composition eligibility. A later
hard rule requires a new schema and independently ratified evidence semantics.

### 4. Ordering, determinism, and fail-closed behavior

Candidate pairs use
`for left, right in combinations(sorted(candidate_keys), 2)`. Candidate versus
recipient uses that same candidate order against one fixed recipient subject.
`BlockingCallCatalogEntry` sorts by complete target `NodeId`, then `effect_id`
and digest. A path sorts by `(subject candidate_key, source NodeId, target NodeId,
complete edge-provenance path key, conflict_kind.value, status.value,
catalog_entry key or empty, evidence_digest)`. Architecture assessments sort by
complete subject key. Equal exhaustive keys reject.

Matrix conflicts sort by complete pair key then `(kind.value, status.value,
evidence_key, evidence_digest, detail_code)`. Graph adjacency is sorted before
bounded traversal; shortest path length, then the complete edge-path key, chooses
the one canonical proof path when several paths reach the same target. Limits
prospectively bound roots, nodes, edges, paths, path length, catalog entries,
observations, and work. Exhaustion or incomplete required graph coverage cannot
emit a clean assessment.

Canonical encoding, digesting, policy binding, duplicate rejection, and
fail-closed matrix consumption follow ADR-0013 section 4.

### Positive Consequences

- Blocking work behind sync helpers remains visible from async roots.
- The hard verdict is reproducible and reviewable against finite policy data.
- Unknown third-party effects cannot masquerade as async safety.
- Other architectural evidence can be collected without overstating v1 proof.

### Negative Consequences

- The finite catalog cannot classify every real blocking API.
- Conservative external-effect handling will make many compositions
  indeterminate.
- Logging, error, configuration, and platform mismatches remain advisory until
  separately ratified rules exist.

## Pros and Cons of the Options

### Runtime or host-package discovery

- Good, because it can inspect APIs not present in a finite catalog.
- Bad, because installed state and execution are not reproducible authority.

### Treat every architecture observation as a conflict

- Good, because it flags more integration work.
- Bad, because observations do not prove incompatibility.

### One catalogued structural rule

- Good, because every hard verdict has a complete provenance path.
- Bad, because v1 intentionally has narrow coverage.

## Consequences

The implementation gate is `tests/test_composition_arch.py`. It must cover direct
and helper-mediated blocking calls, both async root kinds, async-clean complete
graphs, exact catalog matching, unknown declared externals, sync/async/mixed/
unknown derivation, observation neutrality, multiple-path canonical selection,
limits, input permutations, and hash seeds. Tamper tests must reject missing edge
provenance, altered paths/catalog digests, omitted unknown externals, dangling
endpoints, and a hard verdict without all four required facts.

## Open Questions

None for the v1 semantic rule. Catalog membership and corpus-measured limits must
be maintainer-ratified and digest-pinned before implementation authorizes output.

## Links

- [#77 — Architectural compatibility analysis](https://github.com/anthonykewl20/leitir/issues/77)
- [ADR-0008 — Behavioral Transplant Set foundation](0008-behavioral-transplant-set.md)
- [ADR-0010 — Capability and suitability](0010-capability-and-suitability.md)
- [ADR-0013 — Dependency composition conflict matrix](0013-dependency-composition-conflict-matrix.md)
- [ADR-0015 — Duplicate abstraction detection](0015-duplicate-abstraction-detection.md)
