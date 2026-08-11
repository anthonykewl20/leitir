# ADR-0008: Behavioral Transplant Set foundation

- Status: Accepted
- Implementation: not-started
- Deciders: leitir maintainers; consensus reviewers (consensus-luna, consensus-terra)
- Date: 2026-08-11
- Technical Story: Epic #52; foundation slices S1 and B2-B5b (#53, #54, #56, #57, #58, #59)

## Context and Problem Statement

Leitir can acquire, pin, verify, and cite repository source, but it cannot yet
determine which code must accompany a known Python function when that function
is moved outside its donor repository. Copying only the function can omit a
helper, base class, exception, constant, import, or environmental requirement;
copying an entire module or repository is safe only by overclaiming and is not
the smallest reusable unit.

Leitir therefore needs a deterministic, fail-closed graph and walk that computes
the smallest self-contained **Behavioral Transplant Set (BTS)** supported by
bounded static evidence. This ADR defines the foundation used by module
`bts.py` and CLI `leitir bts`: the graph contract, static Python subset,
resolution and disposition rules, unresolved-result semantics, the **BTS
budget**, and content-addressed output. The word "closure" remains reserved for
transitive dependency closure such as lockfiles and SBOMs; it is not a synonym
for a BTS and is not used as a BTS field or file name.

Relocation, runtime observation, donor banning, and behavioral reruns belong to
ADR-009. Capability discovery and recipient suitability belong to ADR-010.
Bundle layout, license policy, and attribution belong to ADR-011.

## Decision Drivers

- A missing dependency is more dangerous than an explicit refusal to produce a
  transplant.
- The same verified donor bytes, seed, policy, graph version, grammar, target
  stdlib identity, package-root manifest, and budget must produce byte-identical
  output and the same digest on every supported host.
- The implementation must be Python 3.11-or-newer, fully typed, use
  `from __future__ import annotations`, and use only the standard library at
  runtime.
- Static analysis must prove a binding inside a documented subset; it must never
  infer a likely target from a matching name or host state.
- Every non-success path must carry a stable `BTSRejectReason` from #53 and
  structured source evidence.
- The result must be minimal relative to the proved graph and supplied
  disposition policy, without pretending to establish global semantic
  minimality for dynamic Python.
- Existing verified-tree and canonical-serialization machinery must remain the
  authority for input integrity and pinning.
- Both work and memory allocation must be bounded before canonical analysis can
  begin or advance.

## Considered Options

- Copy the donor's whole module or package.
- Compute a minimal, evidence-bounded BTS from a typed static graph (chosen).
- Use static resolution only and reject unsupported behavior (chosen for this
  foundation).
- Augment static resolution with runtime observations before declaring a BTS
  complete (deferred to ADR-009, where donor execution can be gated safely).

## Decision Outcome

Chosen option: "compute a minimal, evidence-bounded BTS from a typed static
graph", because it gives an auditable and reproducible unit without copying
unrelated donor code, while explicit unsupported and partial outcomes prevent
static uncertainty from being presented as success.

### 1. Typed graph contract (`graph/model.py`)

The graph is a new immutable model. It consumes `apisurface.ApiIndex`; it never
adds fields to or mutates that index. `ApiIndex` is discovery input, not the
semantic graph authority. All schemas below are frozen, slotted dataclasses.
Every enum serializes by `.value`, never by member name or `repr`; the complete
member/value table is pinned by tests.

The normative schema has this shape (bounded integer aliases and validation
details are omitted only for readability):

```python
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

class NodeKind(str, Enum):
    MODULE = "module"
    FUNCTION = "function"
    ASYNC_FUNCTION = "async_function"
    CLASS = "class"
    METHOD = "method"
    ASYNC_METHOD = "async_method"
    CONSTANT = "constant"
    TEST = "test"
    RESOURCE = "resource"

class NodeOrigin(str, Enum):
    DONOR = "donor"
    STDLIB = "stdlib"
    DECLARED_EXTERNAL = "declared_external"
    TEST = "test"
    RESOURCE = "resource"

class EdgeKind(str, Enum):
    IMPORTS = "imports"
    INHERITS = "inherits"
    RAISES = "raises"
    CALLS = "calls"
    INSTANTIATES = "instantiates"
    READS = "reads"
    TESTED_BY = "tested_by"

@dataclass(frozen=True, slots=True, order=True)
class SourceRef:
    slug: str
    commit_sha: str
    path: str                 # strict-UTF-8 POSIX path relative to donor root
    blob_sha: str
    start_line: int           # one-based, inclusive
    start_col: int            # zero-based UTF-8 byte offset
    end_line: int             # one-based, inclusive
    end_col: int              # zero-based UTF-8 byte offset, exclusive

@dataclass(frozen=True, slots=True, order=True)
class NodeId:
    origin: NodeOrigin
    kind: NodeKind
    module: str
    qualified_name: str
    location_key: str

@dataclass(frozen=True, slots=True)
class Node:
    id: NodeId
    source: SourceRef | None
    extraction_method: str

@dataclass(frozen=True, slots=True)
class EdgeProvenance:
    site: SourceRef
    binding: SourceRef | None
    ast_kind: str
    resolution_rule: str
    protocol_base: bool       # derived and valid only for INHERITS

@dataclass(frozen=True, slots=True)
class Edge:
    kind: EdgeKind
    source: NodeId
    target: NodeId
    provenance: EdgeProvenance

@dataclass(frozen=True, slots=True)
class UnresolvedEdge:
    kind: EdgeKind
    source: NodeId
    expression: str
    provenance: EdgeProvenance
    reason: BTSRejectReason
    detail_code: str

@dataclass(frozen=True, slots=True)
class GraphCoverage:
    files: tuple[SourceRef, ...]
    parsed_files: tuple[SourceRef, ...]
    blockers: tuple[ExtractionBlocker, ...]

@dataclass(frozen=True, slots=True)
class Graph:
    schema_version: str
    nodes: tuple[Node, ...]
    edges: tuple[Edge, ...]
    unresolved: tuple[UnresolvedEdge, ...]
    coverage: GraphCoverage
```

`ExtractionBlocker` and all other evidence records are defined below as part of
the same closed schema family. `Graph.schema_version` is validated before any
traversal. Only `leitir-bts-graph-v1` is accepted by this decision. Unsupported
versions reject; a migration emits a new, independently validated canonical
graph artifact and never mutates or silently reinterprets an old one.

Every donor, test, and donor-owned resource node has full `SourceRef` identity,
including byte-precise line/column bounds. Python AST `col_offset` and
`end_col_offset` are UTF-8 byte offsets; extraction preserves those values
without converting them to Unicode code-point columns. A stdlib or
declared-external reference has `source=None` and an origin-qualified canonical
`location_key`; it names a reference but does not assert that a package is
installed or compatible.

`Graph` rejects duplicate node IDs, duplicate or genuinely tied edge/unresolved
records, and dangling endpoints. Two same-line calls to the same target remain
distinct because their column spans differ. Canonical comparison uses enum
`.value` and these exhaustive keys; nullable binding keys use a pinned sentinel
that sorts before a present binding:

```text
source-ref = (slug, commit_sha, path, blob_sha,
              start_line, start_col, end_line, end_col)
node-id    = (origin, kind, module, qualified_name, location_key)
node       = (node-id, source-ref-or-sentinel, extraction_method)
provenance = (site source-ref, binding source-ref-or-sentinel,
              ast_kind, resolution_rule, protocol_base)
edge       = (source node-id, kind, target node-id, provenance)
unresolved = (source node-id, kind, provenance, expression, reason, detail_code)
blocker    = (path, start_line, start_col, end_line, end_col,
              ast_kind, resolution_rule, reason, detail_code)
```

Thus every distinguishing field—origin, kind, module, qualified name,
location key, path, all line/column spans, binding, AST kind, resolution rule,
reason, detail code, expression, identities, and derived properties—is in the
applicable key. The keys are also used for duplicate detection. If every key
field ties, the record is a duplicate and validation rejects with
`REJECT_DUPLICATE_RESULT`; insertion order is never a tie-breaker. Conflicting
definitions for a reachable lexical binding reject with
`REJECT_UNRESOLVED_EDGE`; Python execution precedence is not used to guess a
semantic graph target.

#### Static edge origins and semantics

| Edge | Exact origin | Resolution and walk meaning |
|---|---|---|
| `IMPORTS` | `ast.Import` or non-star `ast.ImportFrom` | Module containing the statement to the absolute imported module node. Relative imports are normalized only against the pinned unique package root. Alias and binding evidence are retained. The walk retains an import when a reachable runtime edge uses that binding; it does not include every import in a module. Runtime imports themselves remain runtime requirements even if no imported name is subsequently loaded. |
| `INHERITS` | Each expression in `ast.ClassDef.bases` | Exactly one edge per base expression. The class points to a base class only when a direct `Name`/`Attribute` chain resolves through lexical or import bindings. Dynamic bases and metaclass keywords are unsupported. Protocol status is a validated derived `protocol_base` property on this edge, proved by explicit AST ancestry to `typing.Protocol`; there is no separate `IMPLEMENTS` edge and no structural-conformance inference. |
| `RAISES` | `ast.Raise` in the lexically owning function, method, or module | Owner to the resolved exception class for `raise E`, `raise E(...)`, or a qualified equivalent. A bare raise resolves only inside a handler with one statically resolved exception type. `raise ... from ...` analyzes both expressions. |
| `CALLS` | `ast.Call.func` resolved to a directly bound function | Lexical owner to one concrete callable. The callee must be a direct lexical/module/import binding. Receiver dispatch—including `self.x()`, `cls.x()`, and attribute dispatch on a receiver whose type appears proved—is unsupported in v1 and emits an unresolved edge terminating with `REJECT_UNSUPPORTED_CONSTRUCT`. |
| `INSTANTIATES` | `ast.Call.func` resolved to a directly bound class | Lexical owner to the concrete class. It replaces, rather than duplicates, `CALLS` at that call site. Constructor dependencies are reached when the class is included. Receiver-dispatched construction is unsupported. |
| `READS` | Every runtime `ast.Name(ctx=Load)` and supported `ast.Attribute(ctx=Load)`, except a callee site already represented by `CALLS`/`INSTANTIATES` | Complete runtime-reference edge: owner to every direct, statically resolved donor/import binding used as a runtime value. This includes constants/resources, function or class objects passed/stored as values, `isinstance(x, DonorType)`, exception-handler types, match-class types, and callback references such as `consume(helper)`. A load proved local, built-in, or permitted external has no donor READS target; every other nonlocal load must resolve or emit an unresolved edge. |
| `TESTED_BY` | A pinned test/probe record naming a graph target with collection provenance | Production symbol to test node. ADR-009 owns production and behavioral interpretation; B3/B4 do not synthesize it. |

B3 emits `IMPORTS`, `INHERITS`, and `RAISES`. B4 emits `CALLS`,
`INSTANTIATES`, and the complete runtime-reference `READS` pass. The latter is a
named prerequisite, **B4-runtime-references**, and B5 may not return `COMPLETE`
unless its full extraction coverage is present and valid. `TESTED_BY` remains
reserved for ADR-009.

#### Pinned grammar, scope, and well-behaved Python subset

V1 analyzes the fixed `python-3.11-v1` source grammar: a documented subset of
Python 3.11 grammar and semantics, not "whatever the host `ast.parse` accepts."
Every source file is first tokenized/parsed under that pinned grammar gate.
Syntax added after Python 3.11 is rejected on every host; for example, a newer
host that can parse Python 3.12 PEP-695 type-parameter syntax must still emit an
extraction blocker and `REJECT_UNSUPPORTED_CONSTRUCT`. The grammar ID, parser
implementation/version, and grammar-table digest are canonical inputs.

The target stdlib is likewise input, not host discovery. `StdlibIdentity`
contains the implementation (`cpython` in v1), a normalized Python version
constraint, a content digest of the maintainer-authored pure-stdlib module and
interface allowlist, and its policy version. It is included in both canonical
payload and digest. The analyzer never imports a host package to resolve an
edge. Unsupported implementation/version/allowlist combinations reject.

The analysis calls stdlib `symtable` for every complete module and nested block
and validates its result against the pinned grammar's scope rules. Whole-block
classification (`local`, `parameter`, `global`, `nonlocal`, `free`, `imported`,
or built-in candidate) is authoritative. Statement-order shadowing is not used:
an assignment anywhere in a block makes the name local throughout that block
under Python's rules. A binding that cannot be reconciled between AST and
`symtable` rejects rather than falling back to a heuristic.

The accepted subset includes:

- top-level and nested regular/async functions, classes, methods, and literal or
  statically resolved module constants;
- absolute imports, uniquely rooted relative imports, `as` aliases, and
  `from X import Y` chains without wildcard import;
- whole-block lexical local, enclosing, class, module, built-in, and import
  binding classifications;
- direct imported-module attribute chains, imported symbols, direct class and
  function names, and supported runtime-value references covered by `READS`;
- single or multiple direct base names/attribute chains, named exception raises,
  and the constrained bare raise above; and
- exact AST line and UTF-8-byte-column spans read from verified donor bytes.

Receiver dispatch is not in this subset. Lexical uniqueness of a method does
not prove the runtime receiver class: a subclass can override the method.
`self.x()`, `cls.x()`, and attribute dispatch on purportedly typed receivers
therefore emit `UnresolvedEdge(reason=REJECT_UNSUPPORTED_CONSTRUCT,
detail_code="receiver_dispatch_v1")` and terminate as `REJECT`. Widening needs
a proved closed-world/final-receiver rule and is deferred to ADR-009+ runtime
evidence or a later static-proof slice under a new schema/rule version; evidence
cannot retroactively clear the blocker in a v1 artifact.

Other reachable v1 exclusions include star imports; dynamic
`importlib`/`__import__`; `exec` or `eval`; `getattr`/`setattr`; module/class
`__getattr__`; monkey-patching; registry/assignment dispatch; decorators;
descriptors and implicit property dispatch; metaclasses/dynamic bases; ambiguous
re-exports; callable parameters or returned callables; conditional or fallback
imports; and unmodeled C-extension behavior. Each reachable exclusion records
`REJECT_UNSUPPORTED_CONSTRUCT` plus a pinned `detail_code`. Ambiguous binding
uses `REJECT_UNRESOLVED_EDGE`. Enum values and detail-code strings are pinned by
tests. A known static blocker remains terminal even if ADR-009 later adds runtime
evidence; runtime evidence may supplement but cannot erase it.

#### Annotation and type-only semantics

Imports execute normally unless guarded by a statically recognized
`if typing.TYPE_CHECKING:` or `if TYPE_CHECKING:` whose binding is proved to be
`typing.TYPE_CHECKING`. Such a guard's body is type-only and does not emit
runtime `IMPORTS`/`READS`; a noncanonical alias or dynamic condition is
unsupported rather than guessed.

Without `from __future__ import annotations`, annotation expressions evaluated
at definition time create normal `IMPORTS` support and `READS` runtime-reference
edges, including base, decorator, default, and annotation references according
to Python 3.11 evaluation semantics. With that future import, ordinary function,
method, and variable annotations are stored deferred and create no runtime
`READS` merely because they name donor symbols. They still receive type-only
coverage records. A reachable call that evaluates annotations—such as
`typing.get_type_hints`—makes the deferred names runtime requirements; unless
all names and namespaces can be statically resolved, it is unsupported.
Class bases, metaclass expressions, decorators, and default values are always
runtime expressions and are not made type-only by deferred annotations. String
annotations are not runtime references unless a supported, proved evaluator is
invoked. Runtime uses of `typing` follow the same pure-stdlib allowlist and
effect rules as other stdlib uses.

#### Analysis-scope manifest

Analysis requires an explicit `SourceRootManifest`: an ordered tuple of
`PackageRoot` records containing canonical root-relative POSIX path, package
prefix, included-file tuple, each file's Git blob SHA, and a content digest of
the record and ordered file list. The manifest itself has a schema version and
content digest and is included in canonical input. V1 accepts exactly one
source/package root and one unambiguous module name per file. Namespace packages,
overlapping roots, duplicate module names, implicit roots, and multiple-source-
root layouts reject with `REJECT_UNSUPPORTED_CONSTRUCT` and pinned detail codes.
Filesystem enumeration cannot add scope.

### 2. Resolution scope and BTS dispositions (`bts.py`)

The public API accepts validated provenance, never loose caller promises:

```python
class BTSDisposition(str, Enum):
    INCLUDE = "include"
    MAP = "map"
    ADAPT = "adapt"
    REPLACE = "replace"
    EXTERNAL = "external"
    REJECT = "reject"

class BTSStatus(str, Enum):
    COMPLETE = "complete"
    PARTIAL = "partial"
    REJECT = "reject"

@dataclass(frozen=True, slots=True)
class ValidatedDonorSnapshot:
    slug: str
    commit_sha: str
    source: str
    parity: str
    materialized_tree_hash: str
    materialized_tree_hash_algorithm: str
    materialized_tree_hash_scope: str
    checkout_root_token: str       # opaque, nonserialized capability

@dataclass(frozen=True, slots=True)
class ResolutionPolicy:
    schema_version: str
    authority: str
    policy_id: str
    policy_digest: str
    stdlib_identity: StdlibIdentity
    adapter_catalog: AdapterCatalog
    rules: tuple[DispositionRule, ...]

@dataclass(frozen=True, slots=True)
class BTSReport:
    schema_version: str
    status: BTSStatus
    inputs: AnalysisInputs
    members: tuple[MemberEvidence, ...]
    dispositions: tuple[DispositionEvidence, ...]
    traversed_edges: tuple[EdgeEvidence, ...]
    unresolved: tuple[UnresolvedEdge, ...]
    blockers: tuple[BlockerEvidence, ...]
    frontier: tuple[FrontierEvidence, ...]
    counters: BudgetCounters
    analysis_digest: str

@dataclass(frozen=True, slots=True)
class BTS:
    schema_version: str
    provenance: DonorProvenanceEvidence
    seed: NodeId
    members: tuple[MemberEvidence, ...]
    dispositions: tuple[DispositionEvidence, ...]
    required_files: tuple[RequiredFileEvidence, ...]
    required_symbols: tuple[RequiredSymbolEvidence, ...]
    bts_digest: str
    member_equivalence_digest: str

@dataclass(frozen=True, slots=True)
class BTSResult:
    status: BTSStatus
    report: BTSReport
    bts: BTS | None

def compute_bts(
    snapshot: ValidatedDonorSnapshot,
    seed: NodeId,
    roots: SourceRootManifest,
    grammar: GrammarIdentity,
    budget: BTSBudget,
    policy: ResolutionPolicy,
) -> BTSResult: ...
```

The remaining normative input and evidence schemas are explicit; there are no
free-form evidence dictionaries:

```python
@dataclass(frozen=True, slots=True)
class GrammarIdentity:
    grammar_id: str
    parser_id: str
    parser_version: str
    grammar_table_digest: str

@dataclass(frozen=True, slots=True)
class StdlibInterface:
    module: str
    qualified_name: str
    effect_kind: str             # "pure" or a pinned contract kind

@dataclass(frozen=True, slots=True)
class StdlibIdentity:
    implementation: str
    python_constraint: str
    policy_version: str
    allowlist_digest: str
    allowlist_entries: tuple[StdlibInterface, ...]

@dataclass(frozen=True, slots=True)
class PackageFile:
    path: str
    module: str
    blob_sha: str

@dataclass(frozen=True, slots=True)
class PackageRoot:
    path: str
    package_prefix: str
    files: tuple[PackageFile, ...]
    content_digest: str

@dataclass(frozen=True, slots=True)
class SourceRootManifest:
    schema_version: str
    roots: tuple[PackageRoot, ...]
    content_digest: str

@dataclass(frozen=True, slots=True)
class AnalysisInputs:
    donor: DonorProvenanceEvidence
    seed: NodeId
    roots: SourceRootManifest
    grammar: GrammarIdentity
    stdlib: StdlibIdentity
    graph_schema_version: str
    resolver_version: str
    budget: BTSBudget
    policy_digest: str
    adapter_catalog_digest: str

@dataclass(frozen=True, slots=True)
class DonorProvenanceEvidence:
    slug: str
    commit_sha: str
    source: str
    parity: str
    materialized_tree_hash: str
    materialized_tree_hash_algorithm: str
    materialized_tree_hash_scope: str

@dataclass(frozen=True, slots=True)
class InterfaceContract:
    contract_id: str
    contract_version: str
    content_digest: str

@dataclass(frozen=True, slots=True)
class EnvironmentContract:
    contract_id: str
    effect_kind: str
    constraints: tuple[str, ...]
    content_digest: str

@dataclass(frozen=True, slots=True)
class AdapterCatalogEntry:
    adapter_id: str
    template: str
    template_bytes_sha256: str
    parameter_names: tuple[str, ...]

@dataclass(frozen=True, slots=True)
class AdapterCatalog:
    catalog_id: str
    catalog_version: str
    content_digest: str
    entries: tuple[AdapterCatalogEntry, ...]

@dataclass(frozen=True, slots=True)
class MapRule:
    target: NodeId
    target_identity: str
    contract: InterfaceContract

@dataclass(frozen=True, slots=True)
class AdaptRule:
    adapter_id: str
    parameters: tuple[tuple[str, str], ...]

@dataclass(frozen=True, slots=True)
class ReplaceRule:
    target: NodeId
    target_identity: str
    contract: InterfaceContract

@dataclass(frozen=True, slots=True)
class ExternalRule:
    target: NodeId
    requirement: str
    environment: EnvironmentContract | None

@dataclass(frozen=True, slots=True)
class RejectRule:
    reason: BTSRejectReason
    detail_code: str

RulePayload = MapRule | AdaptRule | ReplaceRule | ExternalRule | RejectRule

@dataclass(frozen=True, slots=True)
class DispositionRule:
    rule_id: str
    source: NodeId
    disposition: BTSDisposition
    payload: RulePayload
    evidence_digest: str

@dataclass(frozen=True, slots=True)
class AdapterDependency:
    node: NodeId
    disposition: BTSDisposition

@dataclass(frozen=True, slots=True)
class IncludeEvidence:
    edge: Edge
    target: NodeId
    source: SourceRef
    source_bytes_sha256: str

@dataclass(frozen=True, slots=True)
class MapEvidence:
    edge: Edge
    rule_id: str
    target: NodeId
    target_identity: str
    contract_digest: str

@dataclass(frozen=True, slots=True)
class AdaptEvidence:
    edge: Edge
    rule_id: str
    adapter_id: str
    catalog_digest: str
    parameters: tuple[tuple[str, str], ...]
    shim_bytes_sha256: str
    dependencies: tuple[AdapterDependency, ...]

@dataclass(frozen=True, slots=True)
class ReplaceEvidence:
    edge: Edge
    rule_id: str
    target: NodeId
    target_identity: str
    contract_digest: str

@dataclass(frozen=True, slots=True)
class ExternalEvidence:
    edge: Edge
    rule_id: str
    target: NodeId
    requirement: str
    environment_contract_digest: str | None

@dataclass(frozen=True, slots=True)
class RejectEvidence:
    edge: Edge | None
    rule_id: str | None
    reason: BTSRejectReason
    detail_code: str

DispositionEvidence = (
    IncludeEvidence | MapEvidence | AdaptEvidence | ReplaceEvidence
    | ExternalEvidence | RejectEvidence
)

@dataclass(frozen=True, slots=True)
class MemberEvidence:
    node: NodeId
    source: SourceRef
    source_bytes_sha256: str
    disposition: BTSDisposition

@dataclass(frozen=True, slots=True)
class EdgeEvidence:
    depth: int
    edge: Edge
    disposition: BTSDisposition
    rule_id: str | None

@dataclass(frozen=True, slots=True)
class ExtractionBlocker:
    path: str
    start_line: int
    start_col: int
    end_line: int
    end_col: int
    ast_kind: str
    resolution_rule: str
    reason: BTSRejectReason
    detail_code: str

BlockerEvidence = ExtractionBlocker | UnresolvedEdge | RejectEvidence

@dataclass(frozen=True, slots=True)
class FrontierEvidence:
    depth: int
    node: NodeId
    incoming: Edge | None

@dataclass(frozen=True, slots=True)
class RequiredFileEvidence:
    path: str
    blob_sha: str
    source_bytes_sha256: str

@dataclass(frozen=True, slots=True)
class RequiredSymbolEvidence:
    node: NodeId
    source: SourceRef | None

@dataclass(frozen=True, slots=True)
class BudgetCounters:
    input_bytes: int
    files: int
    file_bytes: tuple[tuple[str, int], ...]
    ast_nodes_per_file: tuple[tuple[str, int], ...]
    edges: int
    nodes: int
    queue_entries: int
    peak_queue_entries: int
    depth: int
    work_units: int
    symbols: int
    source_lines: int
    external_interfaces: int
    config_entries: int
```

Every tuple above has its own exhaustive lexicographic key derived from the
field keys in section 1; `(name, value)` pairs sort by both fields. Unknown
fields, tags, enum strings, schema versions, or unbounded integers reject during
construction/deserialization. Tests pin every dataclass field list, union tag,
enum `.value`, and serialization key. `BlockerEvidence` is a closed union, not
an invitation to add arbitrary mappings.

The snapshot constructor is internal to materialization validation. It proves an
immutable Git commit, exact parity, and full tree hash plus algorithm. The public
operation holds the existing materialization `_target_lock` continuously across
tree-hash verification, graph extraction, and every included source-byte read.
For every read, the Git blob SHA computed from the bytes actually read is
compared with `SourceRef.blob_sha`; a path lookup verified earlier is not enough.
The extracted graph remains internal or is returned only as a canonical
artifact bound to this snapshot. Any provenance mismatch rejects.

The seed must uniquely identify a donor function/method and starts as `INCLUDE`.
The priority queue is ordered by `(depth, NodeId key, incoming Edge key)`. Each
included node examines all runtime `CALLS`, `INSTANTIATES`, `READS`, `INHERITS`,
and `RAISES`; supporting `IMPORTS` are retained when used. Runtime import
statements are themselves examined. The walk reaches a fixpoint. Non-`INCLUDE`
dispositions are terminal boundaries unless a typed ADAPT rule declares adapter
dependencies, which are prospectively budgeted and queued. Cycles use a visited
NodeId map, never recursion or unordered iteration.

"Smallest" means the union of exact donor source spans and required module
scaffolding reachable under these rules after overlap merging. It is relative
to graph schema, grammar, target stdlib, static subset, root manifest, and pinned
policy—not global semantic minimality. Relocation expansion belongs to ADR-009
and cannot silently alter this BTS.

Every reachable edge receives exactly one typed disposition:

- **`INCLUDE`** stores exact `SourceRef`, source-byte SHA-256, and verbatim span.
- **`MAP`** remaps identity/name to a pinned symbol with the same typed interface.
  It remains externally distinct from `REPLACE`, although implementations may
  share a validated internal rule envelope.
- **`ADAPT`** uses only canonical shim bytes generated by a finite adapter
  catalog pinned by catalog ID, version, **and content digest**. Arbitrary source
  and model-generated code are forbidden.
- **`REPLACE`** identifies a pinned implementation substitution; unlike MAP it
  is not merely an identity/interface remap, and unlike ADAPT it adds no wrapper.
- **`EXTERNAL`** contributes no transplanted member. It names an environment
  interface but never asserts that a package is installed or compatible.
- **`REJECT`** terminates with `BTSStatus.REJECT`, `bts=None`, reason, detail
  code, and accumulated evidence. It is not a guessed edge.

Before ADR-010, only a maintainer-authored, schema-validated, pinned,
content-addressed `ResolutionPolicy` shipped with leitir may create MAP, ADAPT,
REPLACE, or third-party EXTERNAL rules. Caller-supplied signed policy is not an
authority until ADR-010 defines a trust root and schema. Policy authority and
digest are validated before extraction.

The EXTERNAL default is limited to the policy's allowlisted **pure-stdlib**
interfaces under the pinned `StdlibIdentity`. Stateful, network, locale-, CWD-,
environment-, filesystem-, clock-, or randomness-dependent APIs—including
`time.time()`, `os.environ`, filesystem access, and random generators—require a
typed effect/environment contract in the pinned policy or reject. Third-party
and system interfaces have no default. EXTERNAL never host-imports or claims
installation/compatibility.

Disposition precedence is explicit `REJECT`; exact policy
`ADAPT`/`REPLACE`/`MAP`/`EXTERNAL`; donor `INCLUDE`; allowlisted pure-stdlib
`EXTERNAL`; otherwise `REJECT`. Contradictory rules reject with
`REJECT_DUPLICATE_RESULT`; there is no fuzzy matching, host probe, or score.

### 3. Unresolved edges, `PARTIAL`, and `REJECT`

Extraction preserves every unresolved site. Any unresolved edge reachable from
an included node prevents a BTS. Ambiguous semantics, receiver dispatch, and
other reachable unsupported constructs are terminal `REJECT`, never `PARTIAL`,
using `REJECT_UNRESOLVED_EDGE` or `REJECT_UNSUPPORTED_CONSTRUCT` and a pinned
`detail_code`. Runtime evidence may add evidence but cannot clear a known static
blocker. Malformed/dangling graph data, duplicates, and provenance mismatch also
reject.

`PARTIAL` is reserved for deterministic bounded under-collection: traversal
budget exhaustion, inability to collect a declared coverage unit, or extraction
limits. Extraction or parsing that exceeds `max_file_bytes`,
`max_ast_nodes_per_file`, `max_files`, or `max_edges` reports
`REJECT_EXTRACTION_BUDGET`. This distinct reason identifies pre-walk resource
exhaustion rather than semantic under-collection or walker budget exhaustion.
The report preserves sorted known members, frontier, unresolved sites, counters,
and blockers, but `bts=None`; it cannot be relocated or pass a hard gate.

Walker exhaustion uses `REJECT_BUDGET_EXCEEDED`; a declared unit that cannot be
read/parsed for a non-budget collection reason uses
`REJECT_UNDER_COLLECTION`. Known terminal rejects dominate `PARTIAL`, while all
blockers remain recorded. Only full extraction coverage, completed
B4-runtime-references, no unresolved requirement, and no reject can be
`COMPLETE`.

### 4. BTS budget

The complete budget is canonical input. No numeric CLI defaults are defined by
this ADR except the exact donor-source ratio rule. Until a separately versioned,
corpus-measured defaults policy lands, every caller supplies every field:

```python
@dataclass(frozen=True, slots=True)
class BTSBudget:
    max_input_bytes: int
    max_file_bytes: int
    max_ast_nodes_per_file: int
    max_files: int
    max_edges: int
    max_nodes: int
    max_queue_entries: int
    max_depth: int
    max_work_units: int
    max_symbols: int
    max_source_lines: int
    max_external_interfaces: int
    max_config_entries: int
    max_donor_source_bps: int
```

All fields are bounded nonnegative integers; all except `max_depth` and
`max_donor_source_bps` must be positive. Booleans/floats are invalid.
`max_donor_source_bps` is 0..10,000 and the required policy value is 4,000.
Exact counter equations are normative:

- `input_bytes = canonical byte length of the length-delimited source-root
  manifest, resolution policy, stdlib allowlist, and adapter catalog envelopes`;
  stream and stop at `max_input_bytes + 1` before decoding or retaining an
  over-limit aggregate.
- `files = sum(len(root.files) for root in manifest.roots)`; check
  `files <= max_files` before any file is opened.
- `file_bytes[path] = number of bytes read from that file`; stream at most
  `max_file_bytes + 1` and stop before retaining/parsing an over-limit buffer.
- `ast_nodes[path] = sum(1 for _ in ast.walk(parsed_tree))`; check immediately
  after parsing and before retaining/indexing the tree. Parser allocation is
  bounded by the already-enforced file-byte cap.
- `edges = len(resolved_edges) + len(unresolved_edges)`; check the prospective
  value before appending either record.
- `nodes = number of distinct NodeId values accepted into the graph`; check
  before graph insertion. Traversal may reference only those validated nodes.
- `queue_entries = number of queue records currently retained`, and
  `peak_queue_entries = max(queue_entries)` over the run; calculate prospective
  `queue_entries + 1` and require it to be `<= max_queue_entries` before every
  enqueue, including seed, repeated paths, and adapter dependencies. Dequeue
  decrements the current count only after the record is selected. This bounds
  frontier memory rather than merely counting dequeued work.
- `depth = minimum resolved runtime-edge count from seed`; reject the prospective
  enqueue when `depth > max_depth`.
- `symbols = number of distinct validated lexical binding records materialized
  across all symbol tables`; check before insertion.
- `external_interfaces = number of distinct canonical external NodeId values
  referenced by accepted edges or dispositions`; check before insertion.
- `config_entries = len(policy.rules) + len(source_root_manifest.roots) +
  len(stdlib_identity.allowlist_entries) +
  len(policy.adapter_catalog.entries)`; count records, not nested scalar fields, and
  check before loading their bodies.
- `source_lines = cardinality of the union of inclusive physical donor line
  numbers represented by INCLUDE spans, keyed by path`; check the prospective
  merged union before accepting a member.
- `work_units = files opened + bytes read + AST nodes visited + symbol-table
  bindings classified + graph nodes proposed + graph edges proposed + queue
  records proposed + queue records dequeued + outgoing edges examined + policy
  lookups + source intervals merged`; each listed event costs exactly one except
  bytes, which cost one per byte. Failed prospective operations are charged for
  their proposal but not their acceptance. Cache hits cost the same events as
  misses. The graph/resolver version pins this equation and event order.

No unbounded allocation may precede its applicable budget check. Manifest and
policy envelopes are length-delimited and bounded by `max_input_bytes` and
`max_config_entries`; files are streamed under the byte cap;
edge/node/list/queue insertion is prospective. Bounded memory, as well as
bounded deterministic work, is part of the contract.

Included source ratio uses the `source_lines` union above. Total donor source
lines are raw physical lines in every verified `.py` blob in manifest scope.
The limit is exceeded exactly when
`included_lines * 10_000 > total_donor_lines * 4_000`; equality passes. Zero
donor Python lines is invalid provenance.

"Work units" replaces "virtual time" because the counter makes no wall-clock
latency promise. Before each event the analyzer calculates prospective counters;
an exceed stops before acceptance and returns canonical `PARTIAL` evidence. An
operational wall-clock watchdog may abort, but then publishes **no canonical
artifact**; at most it emits a separate noncanonical envelope with no BTS or
analysis identity. No decision depends on filesystem order, process timing,
locale, or `PYTHONHASHSEED`.

### 5. Pinning and byte-reproducibility (B5b)

Analysis is permitted only through `ValidatedDonorSnapshot` with
`source="git-commit"`, `parity="exact"`, immutable commit SHA, and full
`materialized_tree_hash` plus algorithm and scope. The `_target_lock` is held
across verification, extraction, and all included-byte reads, and each read's
actual Git blob identity is verified. Missing, malformed, sampled, unsupported,
or mismatched state rejects with `REJECT_PROVENANCE_MISMATCH`; a moving donor
reference uses `REJECT_MOVING_REFERENCE`.

ADR-006 tree hashing establishes **integrity, not authenticity**, as ADR-006
itself states. A BTS digest therefore binds a verified-but-not-authenticated
donor generation. Neither digest below upgrades repository ownership, publisher
identity, or source trust.

Every report, including `PARTIAL` and `REJECT`, has an `analysis_digest` over
its canonical report payload for diagnostic comparison. A `COMPLETE` BTS has
two BTS digests:

1. `bts_digest` is primary and authorizing. It includes the full verified
   materialized-tree hash and all canonical inputs/evidence.
2. `member_equivalence_digest` covers canonical member bytes/spans, required
   scaffold, dispositions, and semantic algorithm identities while deliberately
   excluding unrelated full-tree members. It is secondary and
   **non-authorizing**: it never substitutes for provenance, never establishes
   authenticity, and cannot by itself authorize relocation or claim two donor
   generations are the same source.

Canonical serialization is strict UTF-8 JSON with schema `leitir-bts-v1`,
`sort_keys=True`, `separators=(",", ":")`, `ensure_ascii=False`,
`allow_nan=False`, and one LF. Values are null, booleans, strings, or bounded
integers. Floats, absolute host paths, timestamps, temp paths, and observable
environment iteration are forbidden. Sets/maps become arrays sorted by the
documented total key. Source bytes use SHA-256 plus byte coordinates without
newline normalization.

Each digest is lowercase `sha256:<64 hex>` over its canonical payload with that
digest field omitted. The primary payload includes:

- report/BTS and graph schema, grammar/parser/table digest, graph/resolver
  algorithms, target stdlib identity/allowlist digest, and adapter catalog ID,
  version, and content digest;
- donor slug, exact commit SHA, full materialized-tree hash and algorithm;
- content-addressed ordered source/package-root manifest;
- seed NodeId and SourceRef;
- complete budget and maintainer policy identity/content digest;
- sorted members with disposition, identity, POSIX path, full line/byte-column
  span, blob SHA, and source-byte SHA-256;
- sorted non-include typed evidence, pinned targets/rules/contracts, adapter
  bytes/dependencies, and environment constraints;
- every traversed edge with complete site/binding provenance; and
- exact required files/symbols, extraction coverage, blockers, and counters.

Any change to these changes the primary digest. Unreachable donor changes do not
change member records but do change the full tree hash and therefore the primary
identity; they may leave only the non-authorizing equivalence digest unchanged.
Volatile run metadata belongs solely in a separate envelope whose subject is a
digest.

Artifacts are recomputed from validated frozen dataclasses, never trusted as a
mutable cache. Digest mismatch fails closed. Writes use the existing atomic
manifest discipline: same-directory temporary file, flush/fsync, `os.replace`,
and directory fsync where supported.

### Determinism and fail-closed invariants

1. Runtime code is stdlib-only, fully typed Python 3.11+ with future annotations,
   no model calls, and no synthesis except a finite content-pinned ADAPT catalog.
2. Identical verified bytes and canonical inputs produce identical graph,
   report, BTS bytes, and digests across supported hosts.
3. Grammar/parser and target stdlib identities are pinned inputs; host parser,
   packages, locale, environment, and CWD cannot widen acceptance.
4. Every path is strict-UTF-8 relative POSIX; every collection has an exhaustive
   total order; genuine ties reject. No dict/set iteration is observable.
5. Every AST edge site has line and UTF-8-byte-column provenance. Same-line
   same-target sites cannot collapse.
6. Unresolved edges, receiver dispatch, unsupported constructs, malformed graph,
   under-collection, budget exhaustion, moving references, and integrity
   mismatch can never produce `COMPLETE`.
7. Every nonlocal runtime load not proved local/built-in/permitted-external is a
   resolved READS edge or an unresolved terminal blocker. The named complete
   runtime-reference pass is mandatory before `COMPLETE`.
8. Static blockers are non-compensating. Runtime evidence cannot erase one.
9. Every sad path carries stable reason/detail evidence and causal exceptions;
   no `except Exception: return None`.
10. Graph schema and all frozen evidence schemas validate before traversal;
    unsupported versions require a new canonical migration artifact.
11. Prospective checks bound extraction, graph construction, queue/frontier,
    traversal work, and retained memory.
12. A BTS is not transitive dependency closure; neither artifact is relabeled.

### Positive Consequences

- A complete static BTS has evidence for every runtime reference in its pinned
  subset, not merely obvious calls and constants.
- Small source-level units can be reused without copying unrelated package code.
- Dynamic Python limitations remain visible instead of becoming guessed calls.
- Canonical reports make extraction, budget, and unsupported failures auditable.
- Primary BTS identity binds the full verified donor generation; secondary
  member equivalence can compare members without granting authority.
- Whole-block scope classification avoids unsafe statement-order heuristics.
- Bounded memory and work prevent extraction or queue construction from becoming
  an unaccounted denial-of-service path.

### Negative Consequences

- Many real functions initially reject, especially those using receiver
  dispatch, decorators, registries, dynamic imports, or implicit resources.
- Complete READS accounting and grammar/symtable reconciliation are substantial
  work beyond obvious AST calls.
- Pinning grammar, stdlib identity, package roots, adapter content, and policy
  increases artifact and migration complexity.
- Exact spans can require relocation-time scaffold expansion and revalidation.
- Full-tree binding changes primary identity after an unrelated donor change.
- Work units are reproducible but do not promise wall-clock latency.
- Pre-ADR-010 mappings/replacements/adapters are intentionally restricted to
  maintainer-authored policy.
- Epic #52's slice ordering must change: #57 (B4) must grow to contain the named
  B4-runtime-references prerequisite, or a new prerequisite slice must be carved
  out before B5. The epic slice list will be updated when ADR-008 lands.

## Pros and Cons of the Options

### Copy the whole donor module or package

- Good, because it reduces name-resolution work and can preserve package layout.
- Bad, because it copies unrelated code, configuration, resources, licenses,
  and attack surface.
- Bad, because it still does not prove environment requirements.
- Bad, because it cannot claim the smallest evidence-supported unit and defeats
  BTS budgets.

### Minimal, evidence-bounded static BTS

- Good, because every member follows from a typed, provenance-bearing edge.
- Good, because unsupported behavior fails closed and decisions are addressed.
- Bad, because dynamic Python makes the complete subset deliberately narrow.
- Bad, because it still needs independent relocation/runtime proof in ADR-009.

### Static-only resolution

- Good, because it is offline, stdlib-only, deterministic, and does not execute
  untrusted donor code.
- Good, because every resolution cites syntax and binding evidence.
- Bad, because dispatch, registries, descriptors, and monkey-patching cannot be
  proved under v1.
- Bad, because valid dynamic donors reject rather than being guessed.

### Runtime-augmented resolution

- Good, because observations can reveal behavior hidden from static analysis.
- Good, because donor-banned reruns can strengthen behavioral evidence.
- Bad, because one execution is not exhaustive and cannot establish absence.
- Bad, because execution creates security, resource, platform, and
  reproducibility concerns.
- Bad, because it cannot clear a known static blocker under this decision.

### Upstream validation

The conservative direction was checked against mature implementations. Jedi,
PyCG, and pyan3 use useful optimistic techniques—dynamic inference, most-recent
binding approximations, or synthetic external nodes—but those techniques are
deliberately not adopted because they cannot authorize a fail-closed BTS.
Pyflakes, Python's `symtable`, and LibCST's `ScopeProvider` support whole-block
scope classification rather than statement-order shadowing. Nix fixed-output
derivations, Bazel content hashes, and pip archive hashes support the selected
full-content pinning model; the separate member-equivalence digest adds
comparison utility without weakening the provenance-bound primary.

## Resolved by consensus

1. **Q1:** V1 rejects `self`/`cls` and other receiver dispatch. Future widening
   requires a closed-world/final-receiver proof, from ADR-009+ runtime evidence
   or a later static-proof slice under a new schema/rule version; it cannot clear
   a v1 blocker.
2. **Q2:** MAP and REPLACE remain externally distinct; they may share an internal
   typed rule envelope.
3. **Q3:** A reachable unsupported construct is terminal `REJECT`. Later runtime
   evidence may add context but cannot remove the blocker.
4. **Q4:** Numeric CLI defaults are deferred to a separately versioned,
   corpus-measured policy. Callers provide a complete budget until then. The
   donor-source limit is exactly 40%, exceeded only by strict `>`; equality
   passes.
5. **Q5:** Deterministic "virtual time" is renamed **work units**. A wall-clock
   operational abort emits no canonical artifact, only an optional separate
   noncanonical envelope.
6. **Q6:** Complete BTS artifacts expose a primary full-tree-hash digest and a
   secondary, non-authorizing member-equivalence digest.
7. **Q7:** The complete READS/runtime-reference pass is named
   B4-runtime-references and is a prerequisite to `COMPLETE`.
8. **Q8:** Analysis uses a pinned, ordered, content-addressed package-root
   manifest; v1 rejects namespace ambiguity and multiple source roots.
9. **Q9:** Before ADR-010, only maintainer-authored, pinned, content-addressed
   policy can authorize MAP, ADAPT, REPLACE, or third-party EXTERNAL.
10. **Q10:** `REJECT_UNSUPPORTED_CONSTRUCT` is added with mandatory pinned
    `detail_code`; enum strings and detail-code values are pinned by tests.

### Remaining open questions

None for the ADR-008 v1 contract. Corpus measurement still must choose the
separately versioned CLI budget defaults; that is scheduled policy work, not an
unresolved semantic decision in this ADR.

## Links

- [Epic #52 — Behavioral Transplant Set](https://github.com/anthonykewl20/leitir/issues/52)
- [#53 — BTS error taxonomy](https://github.com/anthonykewl20/leitir/issues/53)
- [#54 — graph model](https://github.com/anthonykewl20/leitir/issues/54)
- [#55 — walking skeleton](https://github.com/anthonykewl20/leitir/issues/55)
- [#56 — static IMPORTS/INHERITS/RAISES](https://github.com/anthonykewl20/leitir/issues/56)
- [#57 — name-resolving CALL/runtime-reference pass](https://github.com/anthonykewl20/leitir/issues/57)
- [#58 — BTS walk and budget](https://github.com/anthonykewl20/leitir/issues/58)
- [#59 — BTS reproducibility](https://github.com/anthonykewl20/leitir/issues/59)
- [ADR-0002 — deterministic evidence scoring](0002-deterministic-evidence-scoring-engine.md)
- [ADR-0006 — load-time tree verification](0006-load-time-tree-verification.md)
