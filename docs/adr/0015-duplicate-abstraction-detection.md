# ADR-0015: Duplicate abstraction detection

- Status: Accepted
- Deciders: leitir maintainers; consensus reviewers; consensus-terra review 2026-08-13 (ACCEPT-WITH-AMENDMENTS, amendments applied same day)
- Date: 2026-08-13
- Technical Story: #78 — Duplicate-abstraction detection

## Context and Problem Statement

Composition can select the same organ twice or select candidates whose verified
members or exact dependency declarations overlap. Names and similarity cannot
prove equivalence, while silently deleting one candidate would change the
selected set. The planner needs narrowly typed hard and advisory signals grounded
in verified bytes, source spans, and manifest-bound dependency evidence.

## Decision Drivers

- Exact seed-byte equality is authoritative only for each BTS seed member.
- Source overlap must preserve immutable file identity and existing inclusive-line
  span semantics.
- Dependency declaration overlap must not overstate ecosystem-specific resolved
  identity fields.
- Names, fuzzy similarity, and secondary equivalence digests cannot authorize
  collapse.
- Detection blocks or advises; it never silently deletes a candidate.

## Considered Options

- Collapse candidates by symbol, qualified, or candidate name.
- Use similarity or `member_equivalence_digest` as duplicate authority.
- Use two hard exact signals and two advisory overlap signals, with no automatic
  deletion (chosen).

## Decision Outcome

Chosen option: "verified seed-byte and exact-version hard signals plus
source-span and declaration-overlap advisory signals", because each signal has a
precise evidence boundary and none requires semantic similarity guessing.

### 1. Shared composition record contract

ADR-0013 owns the shared architecture and eligibility semantics. This ADR uses
the identical normative frozen, slotted record contract:

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

`ConflictMatrix` is evidence, not an assembler or resolver. Under ADR-0013's
separate `CompositionEligibility` gate, an exact duplicate or version clash
rejects, unknown required evidence is indeterminate, and only complete
non-conflicting evidence accepts. Missing, malformed, mismatched, or omitted
consumed records raise `BTSError(BTSRejectReason.REJECT_HARD_GATE_FAILED,
detail_code="composition_input_missing_v1")`; valid unknown is never a pass.

### 2. Four closed duplicate and overlap signals

V1 has exactly four signals:

1. **Hard — `EXACT_SEED_BYTES_DUPLICATE`.** For each candidate, select the
   `MemberEvidence` whose `node == BTS.seed`. Exactly one must exist. Equal
   verified `source_bytes_sha256` values for those two seed members emit the hard
   signal. The resulting duplicate assessment uses
   `BTSRejectReason.REJECT_DUPLICATE_RESULT` and blocks selection, but does not
   delete either candidate. Missing, multiple, or digest-invalid seed members
   reject as malformed composition input.
2. **Hard — `VERSION_CLASH`.** This is consumed unchanged from ADR-0013: equal
   `(ecosystem, name)` and distinct exact versions. ADR-0015 neither reparses
   manifests nor resolves the clash.
3. **Advisory — `BTS_MEMBER_SPAN_OVERLAP`.** Compare member pairs only when
   `(slug, commit_sha, path, blob_sha)` are equal. Existing BTS span semantics
   treat both `start_line` and `end_line` as inclusive (`bts.py:755-759`). Compute
   distinct intersection and union line counts, then emit when
   `intersection_lines * 10_000 >= union_lines * member_span_overlap_bps`.
   Columns do not alter the line sets. This signal is advisory and cannot reject
   or silently consolidate either candidate.
4. **Advisory — `DEPENDENCY_DECLARATION_OVERLAP`.** Emit for the same exact
   `(ecosystem, name, version)`. `resolved_sha` strengthens evidence only when
   both values are present and equal; it never substitutes for that triple and a
   missing or unequal value does not convert equal declarations into a version
   clash. `lockfiles.py:352-375` may populate this field from `gitHead`,
   `checksum`, `integrity`, or a commit embedded in `resolved`/`source`, so it is
   not a uniform cross-ecosystem semantic identity.

The forbidden collapse signals are symbol names, qualified names, candidate
names, and similarity of any kind. A same-name/different-byte pair is not an
exact duplicate. Embeddings, edit distance, token similarity, fuzzy hashes, and
behavioral-name matching may not authorize a hard or advisory v1 record.

G7 same-family result deduplication remains separate; `candidates.py:388-401`
validates and orders proposal evidence and retrieval identity before composition.
Composition does not replace that candidate-identity owner. ADR-0008 section 5's
`member_equivalence_digest` remains secondary and non-authorizing: it is not a
duplicate signal and cannot substitute for exact seed bytes or provenance.

### 3. Ordering, evidence boundaries, and fail-closed behavior

Pairs use exactly:

```python
for left, right in combinations(sorted(candidate_keys), 2):
    ...
```

Candidate-versus-recipient checks, when applicable, use that candidate order
against one fixed recipient subject. Member pairs sort by complete left and right
`MemberEvidence` keys. `MemberSpanOverlap` sorts by complete pair key, then full
left `SourceRef`, full right `SourceRef`, intersection, union, threshold, and
evidence digest. `DuplicateAssessment` sorts by complete pair key, then
`kind.value`, `status.value`, complete member-overlap tuple, complete evidence-ref
tuple, and digest. Dependency overlap sorts by pair key then ecosystem, name,
version, both optional resolved identities, source paths, source digests, and
evidence digest. Equal exhaustive keys reject.

All matrix records sort by complete pair key and then complete conflict/evidence
key as defined by ADR-0013. Limits prospectively bound candidate pairs, member
pairs, represented line counts, dependency pairs, overlap records, evidence
records, and work units. No set/dict, manifest, or traversal iteration order may
affect output. Missing members, invalid source spans or digests, incomplete
required dependency evidence, limit exhaustion, and policy/digest mismatch fail
closed rather than producing a clean assessment.

### Positive Consequences

- Byte-identical selected organs block composition without silently dropping one.
- Span and dependency overlap expose likely consolidation work with precise
  evidence boundaries.
- Same-name distinct implementations remain distinct.
- Existing candidate deduplication and BTS digest authority are not widened.

### Negative Consequences

- V1 deliberately does not detect behaviorally equivalent but byte-distinct
  abstractions.
- Line-span overlap can be coarse for dense files and remains advisory.
- The span threshold cannot ship until corpus measurement and maintainer
  ratification are complete.

## Pros and Cons of the Options

### Name or similarity collapse

- Good, because it can identify byte-distinct implementations.
- Bad, because resemblance does not prove interchangeable behavior and can erase
  a genuinely distinct abstraction.

### Member-equivalence digest authority

- Good, because the digest already summarizes BTS content.
- Bad, because ADR-0008 explicitly makes it secondary and non-authorizing.

### Exact hard signals and advisory overlap

- Good, because hard rejection is limited to verified identities.
- Good, because integration overlap remains visible without forced deletion.
- Bad, because semantic duplicate coverage is intentionally incomplete.

## Consequences

The implementation gate is `tests/test_composition_dupes.py`. It must cover exact
seed bytes, same-name/different-bytes, missing and multiple seed members, span
identity boundaries, inclusive lines, disjoint/touching/nested spans, exact
threshold arithmetic, equal dependency triples, optional `resolved_sha`, consumed
version clashes, pair permutations, duplicate keys, limits, and hash seeds.
Tamper tests must reject a hidden exact duplicate, altered member bytes/digests,
fabricated source identity, omitted overlaps at the ratified threshold, and a
matrix that suppresses a consumed version clash.

## Open Questions

1. **What exact numeric value should `member_span_overlap_bps` use?** The value is
   **UNVERIFIED**. It requires corpus measurement and explicit maintainer
   ratification before implementation can emit an authorizing v1 matrix. The
   schema carries the field so the applied policy is auditable, but this ADR
   implies **no default value**.

## Links

- [#78 — Duplicate-abstraction detection](https://github.com/anthonykewl20/leitir/issues/78)
- [ADR-0008 — Behavioral Transplant Set foundation](0008-behavioral-transplant-set.md)
- [ADR-0010 — Capability and suitability](0010-capability-and-suitability.md)
- [ADR-0013 — Dependency composition conflict matrix](0013-dependency-composition-conflict-matrix.md)
- [ADR-0014 — Structural architecture compatibility](0014-structural-architecture-compatibility.md)
