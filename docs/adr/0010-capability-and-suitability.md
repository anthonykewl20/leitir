# ADR-0010: Capability and suitability

- Status: Accepted
- Implementation: complete (C1, C2, C3a, C3b, C4, C4b)
- Deciders: leitir maintainers; consensus reviewers (consensus-luna, consensus-terra)
- Date: 2026-08-11
- Technical Story: Epic #52; C1, C4, C4b, C2, C3a, and C3b (#65-#70)
- Proposed repository filename: `docs/adr/0010-capability-and-suitability.md`

## Context and Problem Statement

ADR-0008 computes a Behavioral Transplant Set (BTS) for a known function in a
verified donor, and ADR-0009 validates relocation of a `COMPLETE` BTS. Neither
decision identifies which donor function addresses a recipient need or whether
that donor is suitable for the recipient. Search rank and matching terms cannot
prove behavior, compatibility, licensing, dependency safety, or effect semantics.

Leitir therefore needs a deterministic, model-free capability boundary, a
recipient profile grounded in verified project artifacts, a bounded candidate
funnel, non-compensating suitability gates, and an incomparable-aware comparison.
This ADR defines that layer. It can present up to three independently justified
role selections, but never manufactures a universally “best” candidate or a
compensating suitability score. Natural-language intent compilation, packet
layout, licensing notices, and occupied-recipient transplant validation remain
outside this decision.

## Decision Drivers

- The authorizing input for a stdlib-only, model-free tool is a typed,
  content-addressed `CapabilitySpec`, not prose or inferred intent.
- Behavior is proved only by maintainer-pinned structural contracts. Search terms
  are retrieval hints and have no proof authority.
- Candidate claims must be traceable to verified immutable source and bounded,
  versioned structural evidence before they influence selection.
- Recipient facts must come from a verified manifest. Missing, malformed, skipped,
  and conflicting records must remain visible and fail closed where required.
- ADR-0002's `unknown`, `error`, `skipped`, and `not_applicable` distinctions are
  preserved. Required unresolved evidence never passes.
- A required failure rejects regardless of any strength elsewhere. Independent
  dimensions are not summed, averaged, weighted, or compared across dimensions.
- Unknown and known dimension values are incomparable; lack of evidence is not an
  adverse value and cannot be used to declare a winner.
- Retrieval, normalization, profiling, gates, comparison, rendering, and canonical
  output are prospectively bounded and `PYTHONHASHSEED`-independent.
- Existing global discovery, source identity, lockfile parsers, materialization
  verification, ADR-0008 BTS computation, and ADR-0009 validation remain the
  authorities for their mechanics and are consumed rather than forked.
- Every malformed, incomplete, contradictory, over-budget, mismatched, or
  unsupported path carries a `BTSRejectReason` and a detail code from a closed,
  versioned registry.
- V1 authorizing policies and registries are maintainer-pinned and digest-bound.

## Considered Options

- Accept natural language and use an LLM or heuristic intent parser.
- Search once and return the highest-ranked source match.
- Gate candidates, then compute one weighted aggregate suitability score.
- Use a typed capability contract, manifest-derived recipient profile, bounded
  retrieval funnel, non-compensating gates, and independent role comparison
  with explicit incomparability (chosen).
- Require the caller to supply a candidate list and omit discovery.

## Decision Outcome

Chosen option: “typed, pinned behavior contracts plus bounded retrieval,
manifest-derived profiling, non-compensating gates, and incomparable-aware role
comparison”, because it gives a model-free caller a reproducible selection
surface without converting retrieval terms, missing evidence, or canonical order
into semantic proof.

All normative records introduced here are frozen, slotted dataclasses. Enums
serialize by `.value`; unions have closed tags. Every unordered collection is
sorted by an exhaustive documented key. Unknown fields, enum values, schema
versions, malformed digests, booleans used as integers, unbounded integers,
duplicate exhaustive keys, and genuine key ties reject before evaluation.

### 1. Typed capability and pinned behavior authority (C1; `capability.py`)

`CapabilitySpec` is the sole public intent accepted by this subsystem. It has no
natural-language prompt, free-form preference mapping, callback, executable
predicate, or policy expression:

```python
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

class ConstraintMode(str, Enum):
    REQUIRED = "required"
    PREFERRED = "preferred"

class InterfaceKind(str, Enum):
    FUNCTION = "function"
    ASYNC_FUNCTION = "async_function"
    ITERATOR = "iterator"
    ASYNC_ITERATOR = "async_iterator"
    CONTEXT_MANAGER = "context_manager"
    ASYNC_CONTEXT_MANAGER = "async_context_manager"

@dataclass(frozen=True, slots=True, order=True)
class BehaviorRequirement:
    behavior_id: str
    contract_version: str
    evidence_terms: tuple[str, ...]

@dataclass(frozen=True, slots=True, order=True)
class BehaviorContract:
    behavior_id: str
    contract_version: str
    proof_rule_id: str
    proof_rule_version: str
    collector_id: str
    collector_version: str
    evidence_schema_id: str
    evidence_schema_version: str
    structural_requirements: tuple[StructuralProofRule, ...]
    content_digest: str

@dataclass(frozen=True, slots=True)
class BehaviorContractRegistry:
    registry_id: str
    registry_version: str
    authority: str
    contracts: tuple[BehaviorContract, ...]
    content_digest: str

@dataclass(frozen=True, slots=True, order=True)
class InterfaceRequirement:
    interface_id: str
    kind: InterfaceKind
    parameter_kinds: tuple[str, ...]
    return_kind: str
    effect_kinds: tuple[str, ...]
    mode: ConstraintMode

@dataclass(frozen=True, slots=True, order=True)
class PerformanceConstraint:
    metric_id: str
    collector_id: str
    collector_version: str
    operator: str
    integer_value: int
    unit: str
    mode: ConstraintMode

@dataclass(frozen=True, slots=True)
class LicensePolicy:
    policy_id: str
    policy_version: str
    allowed_spdx_expressions: tuple[str, ...]
    prohibited_spdx_expressions: tuple[str, ...]
    allow_unknown: bool             # exactly False in v1
    policy_digest: str

@dataclass(frozen=True, slots=True)
class CapabilitySpec:
    schema_version: str
    required_behaviors: tuple[BehaviorRequirement, ...]
    prohibited_behaviors: tuple[BehaviorRequirement, ...]
    target_language: str
    target_runtime: str
    interfaces: tuple[InterfaceRequirement, ...]
    performance_constraints: tuple[PerformanceConstraint, ...]
    license_policy: LicensePolicy
    prohibited_dependencies: tuple[str, ...]
    required_platforms: tuple[str, ...]
    behavior_registry_digest: str
    capability_registry_digest: str
    max_candidate_budget_id: str
    max_candidate_budget_version: str
    max_candidate_budget_digest: str
    reason_registry_digest: str
    spec_digest: str
```

`StructuralProofRule` is itself a closed tagged union of exact AST, symbol,
interface, effect, and typed evidence predicates. It cannot contain source code,
regex supplied by the caller, or an executable callback. Each accepted
`(behavior_id, contract_version)` resolves to exactly one entry in the
maintainer-pinned `BehaviorContractRegistry`. The entry defines the structural
proof rules, evidence schema, collector and proof-rule identities and versions,
and a digest over the canonical entry. Duplicate keys or conflicting digests
reject. The registry envelope's ID, version, authority, complete ordered entry
set, and content digest are validated against the release policy.

`evidence_terms` compile only to typed ADR-0001 retrieval predicates. They may
increase or narrow retrieval but can never satisfy a behavior gate, create a
`BehaviorProof`, or override a contract rule. Unsupported behavior semantics,
proof rule, evidence schema, or required collector reject at spec construction
with `REJECT_UNSUPPORTED_CONSTRUCT`; they do not make every candidate merely
unknown. A supported metric/collector whose candidate evidence is missing is a
required `unknown` at C3a, not an invalid spec.

V1 accepts exactly `leitir-capability-v1`, finite registries of canonical
language/runtime/interface/effect/metric/unit/operator values, and bounded
strict-UTF-8 strings and tuples. Numeric limits and these small registries live
in a separately versioned, corpus-measured maintainer policy. Runtime constraints
come from that registry, not host discovery or arbitrary PEP 440 evaluation.
Dependency names use existing ecosystem normalization. License expressions use
only the finite grammar and identifier registry pinned by policy; this ADR does
not introduce a general SPDX parser.

At least one required behavior is mandatory. IDs are sorted and unique. A
behavior cannot be both required and prohibited; interface/effect, dependency,
platform, performance, and license rules cannot contradict one another. Empty,
malformed, unknown, contradictory, or over-bound specs reject with the most
specific existing `BTSRejectReason` and registered capability detail code.

`spec_digest` is lowercase `sha256:<64 hex>` over canonical spec payload with
that field omitted. The payload includes the complete behavior-contract registry
digest, capability registry digest, candidate-budget policy identity/version/
digest, reason registry digest, and every referenced contract-entry digest.
Construction and deserialization resolve all references and recompute all
digests. A registry substitution therefore changes the spec identity; a mismatch
rejects rather than refreshing a cache.

Structural validation emits typed `BehaviorProof` records only by applying the
pinned contract to verified bytes. A `DonorCapabilityContract` binds the
`spec_digest`, candidate identity, exact donor `SourceRef`, seed proposal,
matched/prohibited proofs, interface/effect evidence, rule identities, and all
evidence digests. It is a donor-facing bridge, not an alternate graph or BTS.

Natural-language-to-`CapabilitySpec` compilation is a non-goal. A harness or
agent may construct the typed object, but Leitir validates only that object and
never records prose as authorizing evidence.

### 2. Manifest-bound recipient profiling (C4; `project_profile.py`)

`profile_project(manifest, policy) -> ProjectProfile` reads only verified bytes
named by a bounded, content-addressed `RecipientInputManifest`. Each entry binds
a strict relative POSIX path, role, byte length, SHA-256, and exact bytes
capability; the manifest binds its schema, ecosystem recipient-manifest version,
project-root identity, ordered entries, and digest. Filesystem discovery and
ambient host state cannot add scope.

The current path-probing `lockfiles.dependency_closures(root)` API is not
authorizing for C4: it can convert malformed input into absence and individual
parsers can skip malformed records while still labeling a graph complete. C4
therefore requires an additive manifest-backed API in `lockfiles.py`, conceptually:

```python
def dependency_closures_from_manifest(
    files: tuple[VerifiedManifestBytes, ...],
    policy: DependencyManifestPolicy,
) -> ManifestDependencyResult: ...
```

The API consumes bytes already verified against the recipient manifest and
returns a closed per-source result containing source path/digest, ecosystem,
parser ID/version, graph scope (`complete`, `direct_only`, or `unknown`), sorted
dependency records, and sorted diagnostics for absent, malformed, unsupported,
and skipped records. It reuses the parser implementations beneath the existing
API; no requirements, npm, Cargo, or Go grammar is reimplemented.

An absent optional ecosystem source is an explicit diagnostic, not an empty
complete closure. A manifest-required source that is absent or whose bytes do
not match uses `REJECT_PROVENANCE_MISMATCH`. A whole-source UTF-8, JSON, TOML, or
supported lockfile-grammar failure uses `REJECT_UNDER_COLLECTION`. Once a source
envelope parses, any parser path that would skip an individual entry—including a
non-mapping Cargo package, invalid name/version, unsupported npm package record,
malformed Python dependency, or malformed Go requirement—must instead return a
diagnostic and reject the authorizing profile with
`REJECT_COVERAGE_MISCOUNT`. Thus a prohibited dependency cannot disappear from a
supposedly complete graph. The detail-code registry distinguishes source absence,
source parse failure, malformed record, omitted record, and unsupported record.
No diagnostic is silently dropped.

The closed profile records:

- languages and declared runtime constraints;
- normalized direct/complete dependency closures, completeness, versions,
  identities, source provenance, and all parser diagnostics;
- frameworks only through a finite, exact dependency-to-framework registry;
- concurrency (`sync`, `async`, `mixed`, or `unknown`) from declared runtime/
  config and bounded syntax evidence, never one suggestive dependency;
- error, logging, configuration, and effect evidence from pinned AST/config rules,
  with unsupported forms retained as blockers or typed unresolved statuses;
- declared target platforms;
- explicit recipient license and prohibited-dependency policy; and
- for every value, an `EvidenceRef` naming manifest path, bytes digest, parser or
  rule identity/version, and bounded source span where applicable.

Observed facts and recipient policy are separate fields. A recipient-policy file
is required only when recipient-local constraints are made required gates. Its
absence otherwise remains an explicit `unknown`; it never means “all licenses
allowed” or “no dependency prohibited.” A `CapabilitySpec` and explicit recipient
policy disagreement is a known gate failure. Conflicting artifacts are retained
in sorted conflict records and make the affected required field unresolved.

The canonical `ProjectProfile` binds schema and rule versions, recipient-manifest
version/digest, dependency parser and registry digests, every evidence and
diagnostic digest, unresolved/conflict records, budget counters, and
`profile_digest`. It does not claim that an occupied recipient can safely accept
a transplant; that gate remains deferred and does not weaken ADR-0009's
empty-project validation.

### 3. Semantic example classification (C4b; `examples.py`)

The versioned examples schema receives one additive classification record:

```python
class ExampleClass(str, Enum):
    MINIMAL_USAGE = "minimal_usage"
    PRODUCTION_USAGE = "production_usage"
    ERROR_HANDLING = "error_handling"
    CONFIGURATION = "configuration"
    INTEGRATION_TEST = "integration_test"
    UNIT_TEST = "unit_test"
    DEPRECATED_EXAMPLE = "deprecated_example"
    BENCHMARK = "benchmark"
    INTERNAL_ONLY_USAGE = "internal_only_usage"
    UNKNOWN = "unknown"

@dataclass(frozen=True, slots=True)
class ExampleClassification:
    labels: tuple[ExampleClass, ...]
    method: str                    # exactly "heuristic-v1"
    confidence_bps: int | None
    evidence: tuple[ExampleRuleEvidence, ...]
```

Classification is multi-label. Labels are sorted in the pinned enum order and
unique; `UNKNOWN` is exclusive. Confidence is an integer diagnostic tied to a
pinned rule table, neither a hard gate nor a suitability value. Ambiguity emits
only `UNKNOWN` with `confidence_bps=None`. Facets are deferred.

V1 uses exact path segments, file type, parsed symbol use, and finite setup,
assertion, deprecation, configuration, and benchmark markers. It performs no
embedding, fuzzy match, host import, or prose understanding. A test path cannot
be `PRODUCTION_USAGE` solely from content. Deprecated evidence is ineligible for
positive counts; internal-only and unknown snippets remain visible but cannot
satisfy minimum example gates.

Adding classification creates a new examples schema. `_valid_examples` strictly
validates that version; old cache artifacts are regenerated through existing
corpus machinery. Rule-table identity/digest and verified source bytes are bound
to each index.

### 4. Bounded candidate funnel and seed proposals (C2; `candidates.py`)

`discover_candidates(spec, profile, plan, budget, policy) -> CandidateSet`
executes these stages in order:

1. **Repository discovery:** compile the validated spec into typed global
   discovery `SearchSpec` values and consume ADR-0001/G2-G8 results.
2. **File discovery:** retain verified immutable blob hits whose exact language,
   path, and prohibited-term retrieval predicates pass.
3. **Symbol proposal:** consume language adapters and `ApiIndex` to identify exact
   function/method source spans and emit a typed seed proposal.
4. **Local structural validation:** apply pinned behavior/interface/effect rules
   to verified bytes and emit a `DonorCapabilityContract`; unproved supported
   semantics remain typed unresolved evidence.
5. **Context expansion:** attach bounded API, dependency, license, test, and C4b
   evidence pointers. This stage cannot compute or enlarge a BTS.

A `SeedProposal` is non-authorizing and records proposal schema/version, search
hit identity, blob identity, complete symbol `SourceRef`, symbol kind and
qualified name, adapter/extraction method and version, proposal rule ID/version,
and proposal digest. C2 does not return an ADR-0008 `NodeId`, establish graph
edges, or establish a `COMPLETE` BTS. The authoritative `NodeId` is minted only
during graph extraction under a validated `DonorSnapshot`, after full tree-hash
verification and source reconciliation.

This explicitly reconciles C2 with the installed API:

```python
compute_bts(
    snapshot: DonorSnapshot,
    seed: NodeId,
    graph: GraphProvider,
    budget: BTSBudget,
    policy: ResolutionPolicy,
) -> BTSResult
```

After a proposal is selected for BTS evaluation, the composition root validates
the donor snapshot, invokes the graph provider under `compute_bts`'s lock,
resolves exactly one graph node whose complete `SourceRef` and symbol identity
match the proposal, and only then supplies that `NodeId`. Zero or multiple matches,
coordinate drift, graph mismatch, or snapshot mismatch rejects. A proposal can
never be passed in place of `NodeId` or represented as a complete BTS.

Every stage records attempted, accepted, excluded-by-reason, duplicate, and
remaining counts. G7 remains the owner of global-result deduplication. Candidate
identity includes all ADR-0008 `SourceRef` coordinates and exact proposal identity:

```text
candidate-key = (
  slug, commit_sha, path, blob_sha,
  start_line, start_col, end_line, end_col,
  seed_proposal_schema, symbol_kind, qualified_name,
  extraction_method, extraction_version,
  proposal_rule_id, proposal_rule_version, proposal_digest
)
```

Same-line distinct symbols and sites therefore cannot collapse. Duplicate keys
reject with `REJECT_DUPLICATE_RESULT`; remote or insertion order is never a
tie-breaker. Retrieval score may be retained as retrieval evidence but cannot
enter gates or dimension comparison as a quality value.

#### Candidate-budget policy and charging

`CandidateBudgetPolicy` is a closed maintainer-authorized record containing
schema version, authority, policy ID/version, every positive numeric maximum,
small registry digests, counter-equation version, charging-order version, and
content digest. The release policy names the only accepted v1 policy digest.
`CapabilitySpec.max_candidate_budget_id/version/digest` must exactly equal this
policy. The caller's `CandidateBudget` repeats the policy identity/version/digest
and every maximum; equality of every field and the recomputed budget digest is
required before any collection. A smaller, larger, partially supplied, or
same-ID/different-digest budget rejects. Callers cannot weaken completeness by
choosing a cheaper budget under an authorized spec.

The closed budget fields are `max_search_plans`, `max_queries`, `max_pages`,
`max_raw_hits`, `max_verified_blobs`, `max_blob_bytes`, `max_total_blob_bytes`,
`max_files`, `max_symbols`, `max_ast_nodes`, `max_examples`,
`max_evidence_records`, `max_context_bytes`, `max_retained_candidates`, and
`max_work_units`. All are bounded positive integers. Exact prospective equations
are normative:

- `search_plans`, `queries`, and `pages` count accepted plan, query, and recorded
  page envelopes respectively; each is checked before request or retention.
- `raw_hits` counts every hit proposed by a recorded page before filtering or
  deduplication; duplicates and rejected hits still consume the proposal charge.
- `verified_blobs` counts distinct blob identities proposed for verification;
  `blob_bytes` is the streamed byte count for one blob and `total_blob_bytes` is
  the sum of all bytes read, including a failed over-limit byte. Streaming stops
  at the applicable maximum plus one before retaining an oversized buffer.
- `files` counts distinct accepted file identities; `symbols` counts every symbol
  proposal before candidate deduplication; `ast_nodes` counts every node visited
  by the pinned parser walk. Each prospective insertion/visit is checked first.
- `examples` and `evidence_records` count proposed records before acceptance,
  including malformed, duplicate, or later-excluded records.
- `context_bytes` is the canonical length-delimited byte length proposed for
  retained context envelopes; stream and reject before retaining over-limit data.
- `retained_candidates` counts distinct validated candidate keys proposed for the
  final set and is checked before insertion.
- `work_units = plans proposed + queries proposed + pages requested + pages
  decoded + raw hits proposed + blob identities proposed + blob bytes read +
  files proposed + symbols proposed + AST nodes visited + behavior rules applied
  + evidence records proposed + context bytes read + candidate insertions
  proposed + comparison records proposed`. Every event costs one except bytes,
  which cost one per byte. Cache hits and misses have identical logical charges.

Charging order is: charge work proposal; check prospective specific and work
counters; perform bounded read/decode; charge every produced child proposal in
its canonical source order; validate; then accept/retain. A failed proposal is
charged but not accepted. No allocation may precede its applicable byte/count
check. Exhausting extraction bounds uses `REJECT_EXTRACTION_BUDGET`; exhausting
funnel work uses `REJECT_BUDGET_EXCEEDED`.

#### Completion and comparison authority

The target for ordinary GLOBAL comparison is three structurally validated,
gate-eligible survivors. Reaching that target under all declared stages and
authorized budgets yields a comparison-authorizing recorded set while global
recall remains `INDETERMINATE_GLOBAL`.

A clean remote EOF below the target is complete for the recorded funnel and is
not under-collection. It records `INDETERMINATE_GLOBAL` and returns a diagnostic,
non-authorizing set. Fewer than three survivors may authorize comparison only if
the input policy declares a finite exhaustive universe and the collector proves
exact universe membership and exhaustion with a validated manifest digest.
Otherwise no role comparison is authorized.

A page ceiling, fetch failure, malformed page, parser failure, missing declared
stage, or inability to continue before the stop condition is
`REJECT_UNDER_COLLECTION` and cannot yield a comparison-authorizing set. The
registered detail and structured stage evidence retain whether fetch, decode,
parse, or ceiling caused the under-collection. Different live pages produce a
different input digest; identical recorded pages, bytes, spec, profile, plan,
budget, and policy produce byte-identical normalization.

### 5. Non-compensating suitability gates (C3a; `suitability.py`)

C3a directly preserves ADR-0002's status vocabulary:

```python
class GateStatus(str, Enum):
    PASS = "pass"
    FAIL = "fail"
    UNKNOWN = "unknown"
    ERROR = "error"
    NOT_APPLICABLE = "not_applicable"
    SKIPPED = "skipped"

class GateVerdictStatus(str, Enum):
    PASS = "pass"
    REJECT = "reject"
    INDETERMINATE = "indeterminate"
```

When C3a consumes ADR-0002 evidence it retains the original status verbatim in a
typed `AssessmentStatusEvidence`; no conversion may collapse `error` or `skipped`
into `unknown`. If an adapter exposes a subsystem-specific status, its closed
conversion table must map one-to-one to the six statuses and retain the original
enum/value. Unknown conversion inputs reject.

Each `GateOutcome` names gate and policy rule, mode, exact status, original status
evidence, applicable spec/profile fields, evidence refs, and for every non-pass a
`BTSRejectReason` and registered detail code. Required v1 gates cover immutable
provenance, behavior-contract and candidate-contract integrity, language/runtime,
all required and prohibited behaviors, interfaces/effects, required performance,
license, dependency policy, platforms, and minimum non-deprecated evidence.

Gate precedence is ADR-0002's non-compensating algebra:

1. Any known required `fail` makes the candidate `REJECT`.
2. Otherwise, a missing required result or required `unknown`, `error`, or
   `skipped` makes it `INDETERMINATE`.
3. `not_applicable` is neutral only with a pinned applicability rule and evidence;
   unsupported, unavailable, or unmeasured is not N/A.
4. Only every applicable required gate passing can produce a survivor.
5. A known failure plus unresolved evidence remains `REJECT`, with
   `complete=false` and every blocker retained.
6. Preferred/advisory outcomes never change the verdict.

Thus unknown is never zero or pass, and required error/skipped outcomes never
pass. Missing supported metric evidence is `UNKNOWN`; collector malfunction is
`ERROR`; policy-authorized nonexecution remains `SKIPPED`; each remains distinct.

License failure uses `REJECT_LICENSE_INCOMPATIBLE`; provenance and moving-source
failures retain their specific reasons; other known incompatibilities use
`REJECT_HARD_GATE_FAILED`. Summary precedence never suppresses the complete
ordered outcome vector.

`SuitabilityPolicy` is schema-validated and separately reviewable. V1 accepts
only the maintainer authority and exact ID/version/digest named by release policy.
Caller-, repository-, or merely signer-supplied policy cannot authorize a pass or
ADR-0008 MAP/ADAPT/REPLACE/third-party EXTERNAL disposition. External signer
identity, delegation, revocation, and trust roots are deferred.

### 6. Closed dimensions and four-way comparison (C3b)

Only candidates with C3a `PASS` from a comparison-authorizing C2 set enter C3b.
The overlapping draft dimensions are resolved as follows:

- `behavioral_interface_fit` merges behavioral and interface fit because the
  interface is part of the proved callable behavior contract; and
- `runtime_portability_fit` merges language/runtime fit and portability because
  portability is compatibility across the declared runtime/platform set.

The fixed v1 dimensions are therefore:

1. `behavioral_interface_fit`
2. `dependency_cost`
3. `extraction_difficulty`
4. `test_example_evidence`
5. `documentation_evidence`
6. `maintenance_status`
7. `security_risk`
8. `license_fit`
9. `structural_complexity`
10. `runtime_portability_fit`
11. `version_stability`

There is no generic numeric value map. `DimensionAssessment` is this closed union:

```python
DimensionAssessment = (
    BehavioralInterfaceAssessment
    | DependencyCostAssessment
    | ExtractionDifficultyAssessment
    | TestExampleEvidenceAssessment
    | DocumentationEvidenceAssessment
    | MaintenanceStatusAssessment
    | SecurityRiskAssessment
    | LicenseFitAssessment
    | StructuralComplexityAssessment
    | RuntimePortabilityAssessment
    | VersionStabilityAssessment
)
```

Every member contains `status: DimensionStatus`, rule ID/version, and evidence
refs, plus exactly one dimension-specific value when known. Exact value types are:

| Assessment | Known value type and direction |
|---|---|
| `BehavioralInterfaceAssessment` | `BehavioralInterfaceValue(required_proved: int, required_total: int, preferred_proved: int, preferred_total: int, interface_match: InterfaceMatch)`; exact rational comparisons precede the closed `InterfaceMatch` ordinal. Higher is better. |
| `DependencyCostAssessment` | `DependencyCostValue(new_direct: int, new_transitive: int, unresolved: int)`; lexicographically lower is better; `unresolved` must be zero for known. |
| `ExtractionDifficultyAssessment` | `ExtractionDifficultyValue(bts_members: int, source_lines: int, adapters: int, external_interfaces: int)`; lexicographically lower is better. |
| `TestExampleEvidenceAssessment` | `TestExampleEvidenceValue(contract_tests: int, applicable_probes: int, nondeprecated_examples: int)`; lexicographically higher is better. |
| `DocumentationEvidenceAssessment` | `DocumentationEvidenceValue(api_docs: int, usage_examples: int, versioned_contracts: int)`; lexicographically higher is better. |
| `MaintenanceStatusAssessment` | `MaintenanceStatusValue(release_state: ReleaseState, supported_release_count: int)`; closed `ReleaseState` then count, higher is better. Wall-clock age is not canonical. |
| `SecurityRiskAssessment` | `SecurityRiskValue(known_critical: int, known_high: int, known_moderate: int, advisory_coverage: CoverageState)`; counts lower and coverage higher are better. Missing advisory coverage is unknown, not zero findings. |
| `LicenseFitAssessment` | `LicenseFitValue(match: LicenseMatch, obligations_count: int)`; closed compatibility state first, then lower obligations. Legal obligations remain informational and are not discharged here. |
| `StructuralComplexityAssessment` | `StructuralComplexityValue(max_cyclomatic: int, total_branches: int, dynamic_blockers: int)`; lexicographically lower is better; a known candidate has zero unresolved blockers. |
| `RuntimePortabilityAssessment` | `RuntimePortabilityValue(required_platforms_proved: int, required_platforms_total: int, runtime_match: RuntimeMatch)`; exact ratio then closed runtime ordinal, higher is better. |
| `VersionStabilityAssessment` | `VersionStabilityValue(api_stability: ApiStability, compatible_versions_proved: int)`; closed stability ordinal then count, higher is better. |

All counts are bounded integers. Ratios retain numerator and denominator and use
exact cross multiplication. The finite ordinals and their direction are pinned by
the comparison-policy digest. `DimensionStatus` is exactly `known`, `unknown`, or
proved `not_applicable`; unknown/N/A carry no known value. N/A requires a pinned
applicability proof.

Cross-dimension comparators are forbidden. A comparator accepts two assessments
of the same concrete union member and returns exactly:

```python
class ComparisonResult(str, Enum):
    BETTER = "better"
    WORSE = "worse"
    EQUAL = "equal"
    INCOMPARABLE = "incomparable"
```

Known versus unknown is `INCOMPARABLE`, never better or worse. Unknown versus
unknown is also `INCOMPARABLE`; proved N/A versus proved N/A is `EQUAL`, and N/A
versus any other status is `INCOMPARABLE`. Differing concrete dimensions reject
instead of invoking a cross-dimension comparator.

`ComparisonPolicy` retains three presentation roles without weights:

- **direct fit:** `behavioral_interface_fit`, then `runtime_portability_fit`;
- **lowest integration cost:** `dependency_cost`, `extraction_difficulty`, then
  `structural_complexity`; and
- **strongest evidence:** `test_example_evidence`, `documentation_evidence`,
  `maintenance_status`, `security_risk`, then `version_stability`.

Within a role, the next named dimension is consulted only after `EQUAL`. A
candidate is a proved role winner only if its role comparison with every other
eligible candidate is comparable and no comparison is `WORSE`; at least one
`BETTER` is required unless every candidate is exactly equal. Multiple exactly
equal maxima use canonical candidate identity only to choose a deterministic
representative, and the report labels that choice `equal_identity_tiebreak`, not
semantic superiority.

If any contender needed to establish a winner is `INCOMPARABLE`, the role is
unfilled and explicitly `UNRANKED_INCOMPARABLE`, with the incomparable pairs and
dimensions recorded. Unknown candidates are never displaced by known-poor ones.
Canonical identity cannot resolve incomparability, nondominated fronts cannot
fill the role, and an unfilled role is never described as “best.”

One candidate may win multiple roles; labels are combined. There is no vacancy
backfill to force three distinct candidates. Consequently output contains zero to
three distinct proved role winners. Every displayed candidate includes complete
gate and dimension vectors, evidence, unknowns, and deterministic finite-template
trade-off text. The artifact has no `score`, `overall_score`, `total`, weighted
policy, or aggregate field. Ranking a rejected, indeterminate, or incomparable
candidate rejects.

### 7. Closed reason and detail-code registry

`BTSEvidence.detail_code` remains a string in the shared implementation, so C1
adds a normative validation authority rather than treating arbitrary strings as
valid. `BTSReasonDetailRegistry` is a maintainer-pinned record containing registry
ID/version/authority, sorted unique entries, and content digest. Each entry is
exactly `(operation_id, BTSRejectReason.value, detail_code, schema_version,
meaning_version)`. The v1 table includes every C1/C2/C3/C4 construction,
deserialization, collection, profiling, gate, comparison, and report sad path,
including the source-absence/parse/malformed/omitted lockfile codes, unsupported
contract/collector codes, seed-proposal mismatch codes, budget mismatch/counter
codes, funnel completion codes, status-conversion codes, and incomparable-role
codes.

The initial ADR-0010 v1 table is closed as follows; operations may emit only the
listed reason/code pair. More specific pre-existing ADR-0008/0009 operations keep
their own already-pinned codes and are not reinterpreted by this table.

| Operation | `BTSRejectReason` | `detail_code` |
|---|---|---|
| capability construction/deserialization | `REJECT_HARD_GATE_FAILED` | `capability_schema_invalid_v1` |
| capability contradiction | `REJECT_HARD_GATE_FAILED` | `capability_constraint_conflict_v1` |
| behavior contract lookup | `REJECT_UNSUPPORTED_CONSTRUCT` | `behavior_contract_unsupported_v1` |
| behavior proof rule lookup | `REJECT_UNSUPPORTED_CONSTRUCT` | `behavior_proof_rule_unsupported_v1` |
| metric/collector lookup | `REJECT_UNSUPPORTED_CONSTRUCT` | `capability_collector_unsupported_v1` |
| registry digest validation | `REJECT_PROVENANCE_MISMATCH` | `capability_registry_digest_v1` |
| recipient required source absence | `REJECT_PROVENANCE_MISMATCH` | `recipient_manifest_source_absent_v1` |
| recipient source bytes mismatch | `REJECT_PROVENANCE_MISMATCH` | `recipient_manifest_bytes_mismatch_v1` |
| dependency source parse | `REJECT_UNDER_COLLECTION` | `dependency_source_parse_failed_v1` |
| dependency malformed record | `REJECT_COVERAGE_MISCOUNT` | `dependency_record_malformed_v1` |
| dependency omitted/skipped record | `REJECT_COVERAGE_MISCOUNT` | `dependency_record_omitted_v1` |
| dependency unsupported record | `REJECT_COVERAGE_MISCOUNT` | `dependency_record_unsupported_v1` |
| recipient profile conflict | `REJECT_UNRESOLVED_EDGE` | `recipient_profile_conflict_v1` |
| example classification | `REJECT_HARD_GATE_FAILED` | `example_classification_invalid_v1` |
| seed proposal construction | `REJECT_HARD_GATE_FAILED` | `seed_proposal_invalid_v1` |
| proposal/snapshot reconciliation | `REJECT_PROVENANCE_MISMATCH` | `seed_proposal_snapshot_mismatch_v1` |
| proposal/graph reconciliation | `REJECT_UNRESOLVED_EDGE` | `seed_proposal_graph_match_v1` |
| duplicate candidate | `REJECT_DUPLICATE_RESULT` | `candidate_identity_duplicate_v1` |
| candidate budget binding | `REJECT_PROVENANCE_MISMATCH` | `candidate_budget_policy_mismatch_v1` |
| extraction counter exhaustion | `REJECT_EXTRACTION_BUDGET` | `candidate_extraction_budget_v1` |
| funnel work exhaustion | `REJECT_BUDGET_EXCEEDED` | `candidate_work_budget_v1` |
| page/fetch/parse under-collection | `REJECT_UNDER_COLLECTION` | `candidate_funnel_under_collection_v1` |
| moving candidate source | `REJECT_MOVING_REFERENCE` | `candidate_moving_source_v1` |
| candidate source mismatch | `REJECT_PROVENANCE_MISMATCH` | `candidate_source_provenance_v1` |
| gate known incompatibility | `REJECT_HARD_GATE_FAILED` | `suitability_required_gate_failed_v1` |
| gate unresolved evidence | `REJECT_HARD_GATE_FAILED` | `suitability_required_gate_unresolved_v1` |
| gate status conversion | `REJECT_HARD_GATE_FAILED` | `suitability_status_conversion_v1` |
| license gate | `REJECT_LICENSE_INCOMPATIBLE` | `suitability_license_incompatible_v1` |
| dimension construction | `REJECT_HARD_GATE_FAILED` | `dimension_assessment_invalid_v1` |
| cross-dimension comparison | `REJECT_SEMANTIC_DEGRADATION` | `dimension_cross_compare_v1` |
| unauthorized ranked output | `REJECT_SEMANTIC_DEGRADATION` | `comparison_unauthorized_ranking_v1` |
| canonical report validation | `REJECT_PROVENANCE_MISMATCH` | `capability_report_artifact_v1` |
| reason-registry bootstrap validation | `REJECT_PROVENANCE_MISMATCH` | `reason_registry_bootstrap_v1` |

The release policy pins the complete table digest. Every subsystem constructor,
`BTSError`/`BTSEvidence` boundary used by this ADR, and artifact deserializer
validates that the `(operation, reason, detail_code)` tuple exists and that the
artifact's registry digest matches. `None` is accepted only for a successful
record whose schema omits failure detail. Unknown, deprecated, wrong-reason, or
wrong-operation codes reject with `REJECT_PROVENANCE_MISMATCH` and the registry's
own bootstrap-safe fixed code. Registry evolution requires a new version and
digest; free-form detail strings cannot enter canonical artifacts.
`UNRANKED_INCOMPARABLE` is an ordinary non-authorizing comparison state, not a
`BTSError`, so it has no rejection detail-code entry.

### 8. Canonical report, determinism, and fail-closed behavior

`CapabilitySuitabilityReport` binds schema and algorithm versions, `spec_digest`,
all referenced behavior-contract entry and registry digests, recipient manifest
and `profile_digest`, dependency parser diagnostics, search-plan/input-page/
candidate-set digests, candidate-budget policy/budget/counters, seed proposals,
example-classifier and capability registries, reason registry, suitability and
comparison policy authority/digests, every exclusion, gate outcome including
original status, dimension assessment, comparison result, selected or unfilled
role, trace, blocker, and `report_digest`.

Canonical JSON is strict UTF-8 with `sort_keys=True`, `separators=(",", ":")`,
`ensure_ascii=False`, `allow_nan=False`, and one LF. Digests are lowercase
`sha256:<64 hex>` over the canonical payload with the digest field omitted.
Writes use the existing same-directory temporary file, flush/fsync, `os.replace`,
and directory-fsync discipline. Artifacts are recomputed from validated inputs,
never trusted as mutable caches.

Normative invariants are:

1. Runtime code is stdlib-only, fully typed Python 3.11+ with future annotations,
   and has no model/provider/credential path.
2. Retrieval terms and natural language cannot authorize behavior, gates,
   dimensions, graph nodes, or BTS seeds. Behavior proof comes only from a pinned
   contract registry applied to verified bytes.
3. Given identical recorded pages, bytes, manifests, specs, budgets, registries,
   and policies, retrieval through rendering is byte-identical across supported
   hosts and hash seeds.
4. Clean EOF below target is complete for the recorded funnel but globally
   indeterminate and non-authorizing unless a declared finite universe is proved
   exhausted. Page/fetch/parser ceilings are under-collection.
5. No fuzzy name, host package import, host runtime probe, filesystem order,
   locale, wall time, or scheduling influences acceptance.
6. ADR-0002 statuses remain distinct. Unknown/error/skipped required evidence is
   indeterminate; N/A requires proof; none can be converted to pass.
7. Hard gates are non-compensating. Dimensions cannot compensate for one another
   and cannot be compared across types.
8. Unknown versus known is incomparable. No role winner is emitted unless all
   comparisons needed to prove that winner are comparable.
9. No aggregate suitability score is computed, serialized, cached, or rendered.
10. Unverified provenance, malformed/contradictory input, unsupported semantics,
    duplicate identity, policy/budget mismatch, under-collection, and budget
    exhaustion cannot produce a comparison-authorizing set.
11. C2 emits only a seed proposal. Only validated snapshot-bound graph extraction
    mints the `NodeId` accepted by the installed ADR-0008 `compute_bts` API.
12. Every sad path uses an existing `BTSRejectReason`, a registered detail code,
    and structured evidence; unknown exceptions cannot become empty results.
13. Candidate claims do not alter ADR-0008 graph/disposition/BTS semantics, and
    suitability does not alter ADR-0009 relocation or validation outcomes.
14. Maintainer-pinned policy is the only v1 authorizing policy. Content identity
    proves integrity and subject binding, not authenticity or authority.

### Upstream validation

The selected separation was checked against mature upstream data models:

- Nix flake inputs preserve source/dependency identity and constraints as typed,
  independently pinned inputs rather than a suitability aggregate.
- Cargo features remain independent, typed conditional dependency/capability
  constraints; feature activation is not a general quality score.
- PyPA core metadata keeps dependency requirements, environment markers, Python
  requirements, extras, and project metadata as separate typed fields.
- deps.dev exposes requirements, dependency closures, licenses, advisories, and
  provenance as separate evidence. This supports retaining independent gates and
  dimensions rather than averaging unlike claims.
- OpenSSF Scorecard's `GetAggregateScore` computes a weighted mean and skips
  inconclusive checks. ADR-0010 explicitly rejects that aggregate/skip pattern:
  it consumes only independent evidence and preserves inconclusive states under
  ADR-0002's non-compensating gate discipline.

### Positive Consequences

- Typed callers can state a need without adding a model dependency to Leitir.
- Retrieval terms cannot masquerade as behavioral proof.
- Recipient dependency facts are manifest-bound, source-provenanced, and cannot
  silently omit malformed prohibited records.
- Candidate collection is bounded by an exact authorized policy and has honest
  global-completeness semantics.
- License, provenance, runtime, and other critical failures cannot be averaged
  away, and all ADR-0002 unresolved states remain visible.
- Four-way comparison exposes uncertainty without preferring known-poor evidence
  over unknown evidence.
- Existing discovery, parser, BTS, and validation authorities remain the single
  owners of their mechanics.

### Negative Consequences

- Callers must construct a detailed typed spec and select only supported pinned
  behavior contracts; Leitir does not infer intent from prose.
- Conservative profiling and structural validation will yield many unresolved
  candidates and unfilled roles.
- A role report may contain fewer than three candidates even when many candidates
  survive, because incomparability is not resolved by canonical order.
- Global retrieval is reproducible only over recorded observations, not across
  independent live searches.
- Behavior, recipient, budget, reason, comparison, and evidence registries require
  reviewed, content-addressed migrations.
- Manifest-backed lockfile diagnostics require additive parser API work before C4
  can authorize dependency gates.

## Pros and Cons of the Options

### Natural-language or model-generated intent inside Leitir

- Good, because it is convenient for a human requester.
- Bad, because provider/model drift makes authorizing input irreproducible.
- Bad, because inferred omissions can be mistaken for permission or proof.

### Return the highest search-ranked match

- Good, because it reuses existing retrieval rank.
- Bad, because relevance terms do not prove behavior or recipient suitability.
- Bad, because first-page selection hides under-collection and critical gates.

### Hard gates followed by one weighted score

- Good, because a scalar is easy to sort and display.
- Bad, because it hides trade-offs and creates false precision.
- Bad, because omitted/inconclusive evidence can improve a weighted mean, as in
  the explicitly rejected OpenSSF aggregate pattern.

### Typed gates and incomparable-aware roles

- Good, because critical requirements remain non-compensating and typed.
- Good, because direct fit, integration cost, and evidence can identify different
  useful donors without cross-dimension arithmetic.
- Bad, because comparison can honestly leave a role unfilled.

### Caller-supplied candidate list only

- Good, because it avoids remote retrieval variability.
- Bad, because it omits C2's product value and permits cherry-picked populations
  without a separately proved exhaustive universe.

## Consequences

Implementation proceeds in dependency order: C1 capability and behavior-contract
registries; C4 recipient profile and manifest-backed lockfile API; C4b examples;
C2 candidate funnel and budget policy; C3a gates; then C3b comparison. Every
slice requires malformed/tampered input, registered sad paths, unresolved status,
ordering permutation, duplicate identity, digest mismatch, budget boundaries,
and multiple `PYTHONHASHSEED` tests. C2 live tests remain behind
`LEITIR_ENABLE_LIVE_E2E=1`; default tests perform no network access.

C5 may consume a proved role result and donor capability contract, but ADR-0011
owns packet paths, schema, attribution, and bundled license obligations. This ADR
does not generate notices, discharge legal obligations, authorize transplantation
into an occupied recipient, or bypass ADR-0009 validation.

## Resolved by consensus

1. **Q1:** Example classification is multi-label, sorted and unique, with
   `UNKNOWN` exclusive. Orthogonal facets are deferred.
2. **Q2:** The three roles are retained, but a role winner is assigned only on
   proved comparable values. Unknowns do not fill a role or imply superiority.
3. **Q3:** Numeric limits and small registries live in a separately versioned,
   corpus-measured maintainer policy and all applicable digests are bound.
4. **Q4:** Unsupported required metrics/collectors reject at spec construction.
   A supported metric with missing candidate evidence is required `UNKNOWN` and
   makes that candidate indeterminate.
5. **Q5:** V1 uses a versioned ecosystem recipient manifest. A recipient-policy
   file is required only when recipient-local constraints are required gates.
6. **Q6:** Clean EOF below the target is complete for the recorded funnel with
   `INDETERMINATE_GLOBAL`, not under-collection. Ordinary global comparison
   requires three validated survivors; fewer require proved exhaustion of a
   declared exhaustive universe.
7. **Q7:** C2 carries a non-authorizing seed proposal. The authoritative `NodeId`
   is minted only during validated donor-snapshot and graph extraction.
8. **Q8:** V1 permits only maintainer-pinned authorizing policy. External signer,
   delegation, revocation, and trust-root design is deferred.

### Remaining open questions

None for the v1 semantic contract. Corpus measurement must populate numeric
policy values and maintainers must ratify concrete registry/policy digests before
implementation can authorize results; those are required artifacts, not open
design choices.

## Links

- [Epic #52 — Behavioral Transplant Set](https://github.com/anthonykewl20/leitir/issues/52)
- [#65 — C1 CapabilitySpec](https://github.com/anthonykewl20/leitir/issues/65)
- [#66 — C4 recipient profile](https://github.com/anthonykewl20/leitir/issues/66)
- [#67 — C4b semantic examples](https://github.com/anthonykewl20/leitir/issues/67)
- [#68 — C2 candidate funnel](https://github.com/anthonykewl20/leitir/issues/68)
- [#69 — C3a hard gates](https://github.com/anthonykewl20/leitir/issues/69)
- [#70 — C3b role comparison](https://github.com/anthonykewl20/leitir/issues/70)
- [ADR-0001 — deterministic search](https://github.com/anthonykewl20/leitir/blob/main/docs/adr/0001-remove-hy3-deterministic-search.md)
- [ADR-0002 — deterministic evidence scoring](https://github.com/anthonykewl20/leitir/blob/main/docs/adr/0002-deterministic-evidence-scoring-engine.md)
- [ADR-0008 — BTS foundation](https://github.com/anthonykewl20/leitir/blob/main/docs/adr/0008-behavioral-transplant-set.md)
- [ADR-0009 — transplant validation](https://github.com/anthonykewl20/leitir/blob/main/docs/adr/0009-transplant-validation.md)
