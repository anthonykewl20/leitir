# ADR-0012: Polyglot graph via tree-sitter

- Status: Proposed
- Deciders: leitir maintainers; consensus reviewers
- Date: 2026-08-13
- Technical Story: #81 — Multi-language graph via tree-sitter

## Context and Problem Statement

ADR-0008 defines a language-agnostic graph contract and BTS walk, but only
Python has a graph producer today. The corpus already acquires and materializes
JavaScript, TypeScript, Rust, and Go repositories, so the verified source set is
polyglot while graph production is not. `compute_bts` already accepts a
`GraphProvider` and does not need to know how a graph was produced.

Leitir's default runtime is deliberately stdlib-only: `pyproject.toml` retains
the literal `dependencies = []`, which is enforced by repository invariant
tests. Tree-sitter's Python runtime and language grammars are native wheels, so
making them hard dependencies would violate that boundary. At the same time,
issue #81 requires first-class typed graph production rather than the existing
regex-based API-surface heuristics.

Leitir therefore needs an optional, reproducibly pinned parser stack, an
explicit graph-producer seam, and a conservative per-language static subset.
This decision extends graph production and BTS computation only. It does not
claim that relocation, rerun, probes, or the complete transplant pipeline are
polyglot.

## Decision Drivers

- The default install must remain stdlib-only, with `dependencies = []`
  unchanged and no implicit native runtime dependency.
- The optional parser runtime and every grammar must be an exact,
  compatibility-tested, hash-locked package tuple.
- Graph producer selection must be explicit and deterministic; ambient host
  packages, entry points, environment variables, and filesystem discovery are
  not authority.
- Existing `compute_bts` graph-provider and graph-model contracts must remain
  unchanged and language-agnostic.
- Tree-sitter queries may select syntax, but syntax alone cannot prove dynamic
  dispatch, type-directed resolution, build configuration, or runtime loading.
- Every unsupported or ambiguous reference must remain visible as both typed
  unresolved evidence and an extraction blocker; no regex fallback may convert
  uncertainty into an edge.
- Source provenance must preserve tree-sitter's byte coordinates and remain
  compatible with ADR-0008 `SourceRef` semantics.
- Parsing untrusted source introduces supply-chain and denial-of-service risks
  that must be bounded and tested when the optional extra is enabled.

## Considered Options

- Add tree-sitter and four grammar wheels as mandatory runtime dependencies.
- Install a hash-locked optional Python-binding extra with exact grammar wheels
  (chosen).
- Invoke a pinned tree-sitter CLI subprocess.
- Vendor the runtime and grammars in Leitir.
- Extend the regex tier-2 API-surface extractors to emit graph edges.
- Register explicit in-process graph producers behind a language registry
  (chosen).

## Decision Outcome

Chosen option: "an optional, hash-locked tree-sitter wheel tuple behind an
explicit graph-extractor registry, with a bounded never-guess static subset",
because it adds real JavaScript, TypeScript, Rust, and Go graph production
without changing the default installation or weakening ADR-0008's fail-closed
graph semantics.

### 1. Optional, hash-locked parser dependency

Tree-sitter support is one `[project.optional-dependencies]` extra containing
exact versions of five wheels: `tree-sitter`, `tree-sitter-javascript`,
`tree-sitter-typescript`, `tree-sitter-rust`, and `tree-sitter-go`. The default
project dependency list remains literally:

```toml
dependencies = []
```

The implementation must commit `requirements-tree-sitter.lock`, containing the
same exact compatibility-tested package tuple and hashes for every accepted
artifact. Installation and CI for this feature use that requirement set with
`--require-hashes`; an unpinned version, missing hash, substituted artifact, or
incompatible runtime/grammar tuple cannot authorize graph production. The
literal-invariant tests in `tests/test_score_process.py` and
`tests/test_score_code_health.py` remain valid.

The integration mirrors the published `py-tree-sitter` binding shape verbatim:

```python
import tree_sitter_javascript as tsjavascript
from tree_sitter import Language, Parser

JAVASCRIPT_LANGUAGE = Language(tsjavascript.language())
parser = Parser(JAVASCRIPT_LANGUAGE)
```

Each other grammar is loaded through its own wheel's `language()` function in
the same form. Leitir does not compile grammars from ambient source, load shared
objects by discovered path, or select an installed grammar by version
preference.

The tree-sitter CLI subprocess option is rejected. Its published command
surface in `crates/cli/src/main.rs` serves grammar generation, parsing, querying,
testing, highlighting, tagging, and debugging; it does not define a stable
Leitir symbol/typed-edge protocol. Treating human/tool output as that protocol
would add process, encoding, version, and error-mapping ambiguity. Vendoring is
also rejected because Leitir would inherit grammar upgrades, native ABI builds,
CVE response, and platform-wheel maintenance instead of pinning reviewed
upstream releases.

### 2. Explicit graph-producer seam

Graph production receives a registry parallel to
`apisurface.register_extractor(language, extractor) -> previous`:

```python
GraphExtractor = Callable[[GraphExtractionRequest], Graph]

def register_graph_extractor(
    language: str,
    producer: GraphExtractor,
) -> GraphExtractor | None: ...
```

Registration returns the previous producer for the normalized language, making
test substitution and restoration explicit. Built-in producers are registered
explicitly at package initialization. JavaScript, TypeScript, Rust, and Go use
static modules at `src/leitir/graph/javascript.py`,
`src/leitir/graph/typescript.py`, `src/leitir/graph/rust.py`, and
`src/leitir/graph/go.py`; there is no entry-point scanning, filesystem
discovery, environment-selected module, host-package preference, or unpinned
third-party producer.

The composition root exposes this adapter:

```python
def make_graph_provider(
    snapshot: ValidatedDonorSnapshot,
    language: str,
    policy: GraphExtractionPolicy,
) -> Callable[[Path], Graph]: ...
```

The adapter resolves exactly one explicitly registered producer, binds the
validated snapshot, normalized language, and extraction policy, and returns the
existing callable form of `GraphProvider`. Missing optional wheels, an unknown
language, a missing producer, or a producer/language mismatch rejects rather
than selecting another extractor. `compute_bts` and its `GraphProvider` seam in
`src/leitir/bts.py` remain unchanged.

### 3. Bounded syntax subset and never-guess resolution

Per-language tree-sitter queries are deterministic syntax-selection mechanisms,
not semantic proof. Upstream grammar tag queries demonstrate captures such as
`@definition.function`, `@definition.method`, `@definition.class`,
`@reference.call`, and `@reference.class`. Leitir may use pinned forms of those
queries to locate candidate definitions and references, but a capture never by
itself establishes an ADR-0008 edge.

A producer emits a resolved `Edge` only when all of the following are proved:

1. exactly one syntactic binding owns the reference;
2. exactly one lexical binding or explicit static import identifies its target;
3. exactly one graph target node or policy-declared external identity matches;
   and
4. the definition, reference site, and binding evidence carry exact
   `SourceRef` provenance.

Every dynamic import or `require`, re-export or star import, property or
optional-chain dispatch, Rust macro or trait/`impl` selection, Go interface
dispatch, build tag or conditional compilation, glob import, computed name, and
other unmodeled construct emits both an `UnresolvedEdge` and an
`ExtractionBlocker`. It is never silently omitted, resolved by matching text,
or passed to the regex tier-2 extractor. Parse errors, error nodes, missing
coverage, budget exhaustion, and query/grammar identity mismatch likewise cannot
produce a complete graph.

Coordinates remain byte-based. Producers preserve tree-sitter
`Node.start_byte`, `Node.end_byte`, `Node.start_point`, and `Node.end_point`, and
convert points to ADR-0008's one-based line and zero-based UTF-8-byte-column
contract without converting columns to Unicode code points. Query, grammar,
runtime, producer, resolution-rule, and budget identities are canonical graph
inputs; output collections use exhaustive total keys and are independent of
capture, mapping, filesystem, or hash iteration order.

This subset is intentionally lower fidelity than compiler-backed SCIP indexers.
SCIP's protocol documents a precision spectrum rather than treating all symbol
relationships as equally proved, while `scip-typescript` requires project
configuration and installed npm dependencies (`tsconfig.json` for TypeScript,
or `package.json` plus inferred configuration for JavaScript). Leitir does not
run language compilers or package installers in this path. Rejecting valid but
unproved relationships is the required cost of preserving fail-closed BTS
authorization.

### 4. Scope: graph production and BTS computation only

Issue #81 covers **polyglot graph production and BTS computation only**. A
JavaScript, TypeScript, Rust, or Go graph can be produced under this decision and
consumed by `compute_bts`, but `run_bts_pipeline` remains Python-only until
separate decisions and implementations land.

The following stages are explicitly deferred:

- **Relocation (`src/leitir/relocate.py`):** relocation rewrites Python AST and
  imports and requires `.py` input. Non-Python relocation is out of scope.
- **Rerun (`src/leitir/rerun.py`):** rerun executes Python contract tests.
  Non-Python rerun is out of scope.
- **Probes (`src/leitir/probes.py`):** probes are Python contract probes.
  Non-Python probes are out of scope.
- **Donor line-budget accounting (`src/leitir/bts.py`,
  `_total_donor_lines`):** the denominator counts Python source today. It must
  become language-neutral before non-Python BTS completion can be fully
  accounted. This is a required follow-up, not an assumption that graph support
  has already solved accounting.

No result from this decision may be described as a full-pipeline polyglot
transplant. Relocation, rerun, probes, and language-neutral donor accounting each
retain their existing authority until later decisions replace or extend them.

### Positive Consequences

- Verified JavaScript, TypeScript, Rust, and Go source can produce the same typed
  graph contract consumed by the existing BTS computation.
- The default install remains stdlib-only and preserves the literal dependency
  invariant.
- Exact wheel hashes and an exact tested tuple make the enabled native parser
  stack reviewable and reproducible.
- Explicit registration keeps producer authority deterministic and testable.
- Unsupported language semantics remain visible as typed unresolved evidence
  instead of guessed edges or silent omissions.

### Negative Consequences

- Syntax-only resolution rejects many real repositories that compiler-backed
  tooling could index. This lower fidelity is an intentional fail-closed cost.
- Enabling the extra adds native supply-chain, parser-crash, memory, CPU, and
  adversarial-input denial-of-service surface.
- Wheel availability may differ across supported Python versions and platforms;
  an unavailable or unhashed platform must reject or leave the extra
  unsupported.
- Five exact package versions and all accepted wheel hashes require coordinated
  review and upgrades.
- Graph production does not make relocation, rerun, probes, donor line-budget
  accounting, or the full BTS pipeline polyglot.

## Pros and Cons of the Options

### Optional hash-locked Python bindings and grammar wheels

- Good, because the default installation retains no runtime dependencies.
- Good, because in-process node and byte-span APIs map directly to typed graph
  evidence.
- Good, because exact versions and hashes make the native tuple explicit.
- Bad, because platform wheel coverage and native-parser security become release
  concerns when the extra is enabled.

### Tree-sitter CLI subprocess

- Good, because it would keep the native parser outside the Python process.
- Bad, because the CLI is a parse, query, tag, test, generation, and debugging
  surface, not a stable symbol/edge exchange protocol.
- Bad, because process discovery, output parsing, encoding, cancellation, and
  version compatibility add new fail-closed boundaries without improving
  semantic precision.

### Vendored tree-sitter runtime and grammars

- Good, because source and build inputs could be kept in one repository.
- Bad, because Leitir would own native builds, ABI compatibility, grammar
  updates, security response, and release artifacts across platforms.
- Bad, because vendoring does not remove the need to pin and compatibility-test
  the runtime/grammar tuple.

### Regex tier-2 graph production

- Good, because the existing API-surface heuristics are stdlib-only and cheap.
- Bad, because they identify candidate declarations, not lexical bindings,
  static import targets, typed edges, or complete unresolved coverage.
- Bad, because regex fallback would violate the never-guess rule exactly where
  tree-sitter reports syntax without proving semantics.

## Consequences

Implementation must first choose and lock the exact five-wheel tuple, commit all
required hashes, define bounded extraction policy and canonical identities, then
add the registry, adapter, and static language modules. Fixture graphs must prove
byte-identical output across hash seeds and tampered fixtures must change or
invalidate the expected graph. Every language needs explicit reject coverage for
its dynamic and unmodeled constructs.

The implementation gate is `tests/test_graph_polyglot.py`. It must cover graph
contract compatibility, exact byte provenance, explicit producer selection,
missing-extra behavior, unresolved/blocker pairing, no regex fallback,
deterministic output, package-tuple compatibility, resource limits, and the
scope boundary that leaves the Python-only pipeline stages unavailable.

## Open Questions

1. Which exact five-wheel version tuple is compatibility-tested and pinned?
2. Which wheel hashes are required for every supported Python and platform
   combination?
3. What measured parser and query limits bound adversarial-input CPU, memory,
   nesting, error recovery, and output growth?
4. What exact fixtures and assertions comprise the implementation gate at
   `tests/test_graph_polyglot.py`?

## Links

- [#81 — Multi-language graph via tree-sitter](https://github.com/anthonykewl20/leitir/issues/81)
- [ADR-0008 — Behavioral Transplant Set foundation](0008-behavioral-transplant-set.md)
- [py-tree-sitter Python bindings and grammar loading](https://github.com/tree-sitter/py-tree-sitter)
- [tree-sitter CLI command surface (`crates/cli/src/main.rs`)](https://github.com/tree-sitter/tree-sitter/blob/master/crates/cli/src/main.rs)
- [tree-sitter JavaScript grammar](https://github.com/tree-sitter/tree-sitter-javascript/blob/master/grammar.js)
- [tree-sitter JavaScript `tags.scm`](https://github.com/tree-sitter/tree-sitter-javascript/blob/master/queries/tags.scm)
- [tree-sitter Rust grammar](https://github.com/tree-sitter/tree-sitter-rust/blob/master/grammar.js)
- [tree-sitter Rust `tags.scm`](https://github.com/tree-sitter/tree-sitter-rust/blob/master/queries/tags.scm)
- [tree-sitter Go grammar](https://github.com/tree-sitter/tree-sitter-go/blob/master/grammar.js)
- [tree-sitter Go `tags.scm`](https://github.com/tree-sitter/tree-sitter-go/blob/master/queries/tags.scm)
- [tree-sitter TypeScript `tags.scm`](https://github.com/tree-sitter/tree-sitter-typescript/blob/master/queries/tags.scm)
- [SCIP protocol precision spectrum (`scip.proto`)](https://github.com/scip-code/scip/blob/main/scip.proto)
- [scip-typescript project and dependency requirements](https://github.com/scip-code/scip-typescript/blob/main/README.md)
- [scip-typescript entry point (`main.ts`)](https://github.com/scip-code/scip-typescript/blob/main/src/main.ts)
