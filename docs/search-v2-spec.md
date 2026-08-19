# Search v2: Wide + Deep

**Status:** Authoritative implementation specification
**Date:** 2026-08-10
**Scope:** Local wide search and structurally deeper scoped search
**Runtime constraint:** Python >= 3.11, stdlib-only runtime

## 1. Goal

Search v2 improves two different capabilities without conflating them:

* **Wide:** a local trigram index searches the verified materialized corpus,
  followed by full-regex verification.
* **Deep:** adapters expose structural symbols and occurrences, beginning with
  Python `ast` and `symtable`, while retaining honest heuristic adapters for
  languages without a parser backend.

The result remains deterministic, provenance-bound, and explicit about
coverage. Local search is exhaustive only for the verified bytes, declared
adapter universe, and eligible per-target shelves actually examined.

Current behavior is the baseline: global discovery uses GitHub's legacy code
search and scoped search scans adapter-eligible files up to 2 MiB. See
`docs/search-capabilities.md:5-18,174-197,209-249`.

## 2. API Pivot Non-goal

GitHub exposes no public advanced code-search result API. GraphQL has no `CODE`
search type; `codeCount` is only a repository count field. REST
`GET /search/code` is the legacy endpoint and does not provide regex or symbol
result semantics. The GitHub CLI explicitly describes API code search as
legacy, while its web option opens the product UI rather than an API.

Therefore Search v2 does **not** migrate the global path. Global REST search
stays as-is, including fail-closed rejection of `REGEX` and other syntax the
endpoint cannot guarantee. Never flatten regex into a keyword query.
Research evidence: `docs/research/search-upgrade-research.md:8-28,269-287`.

## 3. Design Principles

1. A result is valid only with immutable `(slug, commit, path, blob)` identity.
2. Missing, malformed, mismatched, stale, sampled, or unverified integrity
   evidence rejects or becomes uncovered; it never becomes complete for
   indexed-search eligibility. A direct local-shelf scoped search may report
   complete only when every served local blob is byte-verified against the
   pinned upstream tree listing (size and git blob SHA equality); any mismatch
   is a hard failure with no API fallback.
3. Every set and path traversal has an explicit sorted order.
4. Parser failure, transport failure, budget exhaustion, and unsupported
   unbounded matching are visible as partial coverage.
5. The read path never lazily builds an index.
6. Ranking orders a deduplicated result set and never hides a match.
7. The existing stdlib-only dependency rule remains decisive.

## 4. Architecture

### 4.1 Adapter package

Create `src/leitir/adapters/`:

| Module | Contract |
|---|---|
| `registry.py` | `build_adapters(...) -> tuple[LanguageAdapter, ...]`; deterministic ordered tuple and first-eligible routing |
| `languages.py` | Reuse the canonicalizer currently in `apisurface.py:312-321` |
| `python_ast.py` | Reuse and extend the stdlib AST extraction mechanics; AST mode with regex fallback |
| `javascript.py` | Tier-2 reviewed regex adapter |
| `typescript.py` | Tier-2 reviewed regex adapter |
| `java.py` | Tier-2 reviewed regex adapter |
| `c_cpp.py` | Tier-2 reviewed regex adapter for C and C++ |

Keep `src/leitir/adapters.py` as a compatibility re-export shim. Do not
replicate the mutable extractor dictionary at `apisurface.py:305-309` for
search routing. Ordered routing is load-bearing once Python AST and Python
regex coexist: the first eligible adapter wins.

The existing Python AST implementation at `apisurface.py:144-221` is the
source to reuse, not a second extractor to copy. Existing JS/TS heuristic
patterns at `apisurface.py:53-71,229-289` are evidence to reconcile with the
Tier-2 search adapters, not a promise of parser precision.

### 4.2 Matching and searchers

`IndexedSearcher` has the same `search(spec) -> SearchReport` shape as
`ScopedSearcher`. It plans a regex against trigram postings, verifies every
candidate against source bytes, and merges candidates with a scoped fallback
when a shelf is not eligible or the query cannot be indexed. `ScopedSearcher`
remains the exhaustive fallback for declared scopes.

### 4.3 Index package

Create `src/leitir/index/` with:

| Module | Responsibility |
|---|---|
| `builder.py` | Build immutable per-shelf postings and metadata |
| `postings.py` | Sorted posting representation and intersection |
| `query.py` | Extract literal runs/trigrams and plan candidates |
| `rank.py` | Explicit deterministic index ranking signals |
| `verify.py` | Manifest, shelf, source, and schema verification |

Index storage is per shelf:

```text
corpus_root/.search-index/<host>/<owner>/<repo>/<commit>/
    index
    manifest.json
```

There is also a top-level index manifest. The index owns an independent
`schema_version` and refuses unknown versions. A shelf is not a corpus-wide
snapshot; the query result is the union of independently re-verified shelf
states.

### 4.4 Streaming

Create `src/leitir/streaming.py` with an overlap-window reader and
`read_blob_stream(slug, blob_sha) -> Iterable[bytes]`. It uses the token-gated
Git Blobs API path `api.github.com/git/blobs/{sha}` and
`Accept: application/vnd.github.raw`. The reader uses bounded memory and
incremental decoding/search state.

## 5. Interface Contracts

### 5.1 Spans and methods

`SpanMatch` gains optional `start_col: int | None` and `end_col: int | None`.
The extraction method is `method: str`, represented by a StrEnum with exactly
`ast` and `heuristic` values. Do not add or substitute a floating-point
`confidence` field.

`method="ast"` means the span came from a parser-backed structural extraction.
`method="heuristic"` means a regex or other non-parser strategy. Heuristic
references must remain labeled heuristic.

### 5.2 Adapter invocation

```python
find_matches(
    content,
    predicates,
    *,
    whole_file: bool = False,
)
```

`whole_file` is keyword-only and defaults to `False`, preserving all existing
callers and same-line behavior. In default mode, required content predicates
intersect on one line as currently implemented by `engine.py:59-63,91-95`.

In whole-file mode, every `must` predicate must have at least one verified
match anywhere in the blob. Return deterministic evidence spans sorted by line,
column, and predicate kind. `must_not` and `should` semantics must be defined
at the same file/span boundary and documented; they must not silently inherit
an accidental line-only interpretation.

### 5.3 SearchSpec

Add `whole_file: bool = False` as a first-class `SearchSpec` field. Include it
in `_canonical()` and therefore in `spec_digest`; `search.py:225-251` is the
current digest boundary. The CLI `--language` becomes `Predicate.language`, so
the language is also digest identity.

`SearchSpec.__post_init__` rejects conflicting languages among required
(`must`) predicates in both global and scoped modes. Canonical aliases use
`apisurface.py:312-321`; do not invent a second alias table.

### 5.4 Python AST semantics

The Python AST adapter supports these predicate mappings:

| Predicate | Structural source |
|---|---|
| definition | `FunctionDef`, `AsyncFunctionDef`, `ClassDef`, `Assign`, `AnnAssign`, `Import`, `ImportFrom` |
| reference | `Name` with `Load`, resolved lexically via `symtable` where possible |
| call | `Call` |
| signature | function arguments and return annotation |
| import | `Import` and `ImportFrom` |

The first release guarantees structural spans and lexical scope resolution,
not cross-module type inference. A `SyntaxError` uses the regex fallback and
marks the report parser-unavailable/partial; it never emits false-complete
coverage. Multi-line span semantics must be pinned to definition-line spans or
to a separately documented source-slice contract. Duplicate spans are removed
before ranking.

### 5.5 Tier-2 adapters

JS, TS, Java, C, and C++ adapters derive small reviewed regex sets from
tree-sitter query inventories. They must include fixtures for definitions,
calls, comments, strings, multiline declarations, and false positives.
They may report definitions heuristically, but references are explicitly
`method="heuristic"` until a parser backend exists.

### 5.6 Tree enumeration

Add `TreeSource.list_blobs_ex() -> tuple[tuple[BlobEntry, ...], bool]`, returning
blobs and `was_recovered`. Keep `list_blobs()` as the raising compatibility
wrapper. Add a new `TreeEnumerationError` base. `TreeWalkBudgetError` is its
sibling to `TreeTruncatedError`, not a subtype of it.

> Superseded 2026-08-19: `list_blobs()` now completes truncation recovery via the paginated walk (PR #209 / issue #187); see docs/search-capabilities.md.

Recovery expands non-recursive tree responses by SHA with a visited set,
explicit depth/request/entry budgets, validated types, validated SHAs, and
sorted paths. Cycles and budget exhaustion are incomplete, never success.
`ScopedSearcher.search` catches enumeration failures and reports `PARTIAL`.
The truncation handler is `engine.py:140`; the size/read skip is a distinct
path at `engine.py:205-216`.

### 5.7 Streaming verification

For a blob of declared size `size`, hash exactly:

```text
b"blob %d\\0" % size + every received byte
```

Commit spans only if the final SHA-1 equals the declared blob SHA. A path and
commit alone never authorize bytes. Boundary matches are deduplicated by
stable source identity and span coordinates. `incomplete=True` is reserved for
actual truncation, an unbounded/unsupported pattern, or an exhausted budget;
ordinary successful streaming is not partial merely because it used chunks.
Retry accounting is per attempt, not shared incorrectly across retries.

## 6. Index Integrity: Primary Risk

Build and query must hold the per-target `_target_lock` from ADR-0006 across
manifest verification and every dependent read. The existing lock is
`materialize.py:173-202`. A process must not read a stored hash and trust it
outside that lock.

Before serving any shelf, call `read_valid_manifest` while holding the lock and
re-verify the materialized target. The manifest validation and artifact parity
rules are at `materialize.py:405,487,496-513`. The following eligibility rule
is exact and non-negotiable for a scoped query:

```text
source == "git-commit"
and parity == "exact"
and materialized_tree_hash_scope == "full"
```

Registry-artifact, sampled, drift, unknown, or otherwise unverified shelves
share the namespace but contain different bytes or weaker evidence. They are
uncovered, not index hits. The sampled/full distinction is grounded in
`treehash.py:100-103,197-222`.

An ineligible shelf falls back to `ScopedSearcher` and the report is `PARTIAL`.
If fallback cannot inspect it, reject/partial according to the existing error
taxonomy; never report complete. Tamper tests must cover manifest identity,
source, parity, scope, index bytes, and concurrent build/read behavior.

Index lifecycle is intentionally separate from materialization:

* `leitir index` explicitly builds or refreshes; there is no lazy read-path
  build.
* `--require-index` fails closed when an eligible index cannot be served.
* Export/import does not carry the index; rebuild after import.
* `gc` does not sweep index shelves.
* `doctor` reports stale or invalid index shelves.
* Unknown index schema versions are refused.

The index result is a union of independently re-verified per-shelf states, not
a corpus-wide snapshot. Before `order_source_matches`, deduplicate merged
index and fallback results. `ranking.py:71-73` deliberately raises on duplicate
source identities, so bypassing that check is not acceptable.

## 7. Coverage and Ranking

Coverage describes the declared universe, not merely returned hits. Excluded
large files, read errors, parser failures, tree recovery failures, budget
exhaustion, and uncovered index shelves remain visible. Ranking is deterministic
and must not convert a partial candidate scan to complete or remove matches.

`--max-results`, `--max-pages`, and `--language` are global-only in this
release. Capping scoped results would break the exhaustive contract and change
normalized scores, P6 order, and benchmark digests. The existing deterministic
benchmark artifact uses `BenchmarkRun.digest()` at `bench.py:238-240`; ASV
pins `PYTHONHASHSEED=0` at `asv.conf.json:17-19`, so ASV alone is insufficient
for the AST default flip.

## 8. SCIP-shaped Data Model Decision

Adopt a SCIP-shaped model in Phase 2 without adding protobuf or another
dependency. Use typed stdlib dataclasses:

* `Symbol`: stable local ID, display name, kind, language, definition range.
* `Occurrence`: symbol ID when resolved, role, source range, enclosing symbol
  or range.
* `Document`: slug, commit, path, blob SHA, language, generated/vendor/test
  classification, and completeness flags.

Roles are definition, reference, and call. Unresolved names are represented
explicitly. This permits AST and heuristic adapters to share plumbing without
claiming equal precision. The model is adapted from the SCIP shape, not copied
from its protobuf runtime. Research basis: `search-upgrade-research.md:389-404`.

## 9. Resolved Decisions

| ID | Decision |
|---|---|
| D1 | AST coexists with regex first; flip the default only after pinned `BenchmarkRun.digest()` equality and multi-seed determinism, not ASV alone. |
| D2 | Indexing requires explicit `leitir index`; `--require-index` fails closed; no lazy build in reads. |
| D3 | Index artifacts have their own schema version and refuse unknown versions; add versioning documentation; export/import excludes them. |
| D4 | Streaming uses incremental SHA-1 full verification; do not downgrade from path+commit identity. |
| D5 | Result/page caps are global-only. |
| D6 | Adapter registry returns a deterministic ordered tuple; package plus `adapters.py` shim is preferred. |
| D7 | `whole_file` is a `SearchSpec` field and digest input. |
| D8 | `TreeWalkBudgetError` is a sibling of `TreeTruncatedError` under `TreeEnumerationError`. |
| D9 | Only git-commit + exact parity + full tree-hash shelves serve scoped index queries. |
| D10 | Dedupe spans and merged index/fallback results before ranking. |

## 10. Slice Plan

Each slice is independently mergeable, fail-closed, suite-green, and ruff and
mypy clean. Integrity slices require tamper/reject tests and independent
review by `reviewer-hy3` and `reviewer-deepseek` (or human equivalents).

| Order | Slice | Deliverable | Dependencies |
|---:|---|---|---|
| 1 | S2a | Full `(slug, commit, path, blob)` report validation; four tamper tests | none |
| 2 | S1 | Global-only result/page budgets and language CLI plumbing; two-arg factory seam update | none |
| 3 | S0 | Ordered adapter registry refactor; zero behavior change | none |
| 4 | S3 | Repair existing live canary, surface failures, add new-surface canaries | none |
| 5 | S2b | Language routing, conflicting-must rejection, denominator decision and docs | S0 |
| 6 | S-wholefile | Digest field, adapter kwarg, engine branch, CLI and coverage | S0 |
| 7 | S7 | Truncation-safe bounded tree recovery and partial handling | none |
| 8 | S5 | Python AST search adapter and guarded default flip | S0, S-wholefile |
| 9 | S6 | Tier-2 JS/TS/Java/C/C++ adapters and benchmark universe | S0 |
| 10 | S9 | Verified streamed reads over 2 MiB | S5/S6 adapter contracts; verified-read primitive |
| 11 | S8 | Trigram index, lock/eligibility verification, fallback, CLI and operations | S9, S5, S6 |

S6 must widen `bench.py:26` and update
`leitir-benchmark-manifest-v1` and scorecard `output.pinned_benchmark`. S8
depends on S9's verified-read primitive and the stable adapter universe from S5
and S6.

## 11. License Matrix

No upstream runtime dependency is added. Exact versions, notices, and
transitive files must be recorded before distributing adapted code.

| Project | License | Intended use | Handling |
|---|---|---|---|
| sourcegraph/zoekt | Apache-2.0 | trigram index/query mechanics | Adapt with NOTICE |
| hound-search/hound | MIT | simpler index reference | Adapt with notice |
| BurntSushi/ripgrep | MIT/Unlicense | incremental reader ideas | Adapt with applicable notices |
| go-git/go-git | Apache-2.0 | bounded tree-walk model | Reimplement; NOTICE if adapting |
| isomorphic-git | MIT | tree expansion model | Reimplement; notice if adapting |
| tree-sitter runtime/grammars | MIT | structural/query inventory | Review repository notices |
| ast-grep/ast-grep | MIT | structural matching concepts | Adapt concepts |
| mkdocstrings/griffe | ISC | Python extraction mechanics | Adapt with notice |
| davidhalter/jedi | MIT | lexical reference algorithm | Algorithm reference; do not vendor Parso |
| scip-code/scip | Apache-2.0 | symbol/occurrence data model | Adapt model; no protobuf |
| cli/cli | MIT | API boundary evidence | Inspect only or adapt with notice |
| nvim-treesitter queries | repository-specific | node inventory | Do not copy blindly; review files |
| livegrep | BSD-2-Clause | search reference | Reference-only; review obligations |
| OpenGrok | CDDL | search behavior reference | Do not vendor |
| Semgrep | LGPL-2.1 | structural reference | Do not vendor |
| Universal-ctags | GPL-2.0 | symbol reference | Do not vendor |
| PyGithub | LGPL-3.0 | client reference | Do not vendor |
| pygit2/libgit2 | GPL-2.0 | object access reference | Do not vendor |
| searchcode-server | AGPL-3.0 | search reference | Do not vendor |

Source matrix: `docs/research/search-upgrade-research.md:406-434`.

## 12. Changelog & testing policy

The changelog is deterministic and generated from Conventional Commits by
`tools/sync_changelog.py`. A CI drift gate, `tests/test_changelog_sync.py`,
fails when `CHANGELOG.md` is out of sync. Therefore every slice or PR must use
a proper Conventional Commit message such as `feat(scope): ...` or
`fix(scope): ...`: the commit is the changelog source. Internal refactors,
documentation, and chore commits are intentionally omitted from the
user-facing changelog. Breaking changes use `!` in the type/scope or a
`BREAKING CHANGE:` footer.

Every slice follows the iterational user-level-intent loop in
`docs/testing.md`: probe -> red intent test -> green -> refine. Acceptance
criteria are phrased as observable user-level outcomes. Security and integrity
slices add tamper/reject tests, and deterministic behavior is asserted under
`PYTHONHASHSEED=0`, `1`, and `42`. `docs/testing.md` is the authoritative
testing method; this section states the Search v2 application of that method.

## 13. Verification Gates

Every implementation slice runs:

```text
PYTHONPATH=src uv run --no-project --with-requirements requirements.txt python -m pytest -q
ruff check .
mypy src
```

The suite must remain at or above the current 2347 passing tests with zero
failures. The scorecard decision must be `pass`. Live tests remain gated by
`LEITIR_ENABLE_LIVE_E2E=1`. AST default changes additionally require pinned
benchmark digest equality and runs under multiple `PYTHONHASHSEED` values.
ASV is relevant for performance measurement, but its seed pin does not replace
the multi-seed gate.

## 14. References

* Research: `docs/research/search-upgrade-research.md:8-39,121-197,219-265,289-387,389-434`.
* Current capabilities: `docs/search-capabilities.md:5-18,158-264,291-360`.
* API extraction and canonicalization: `src/leitir/apisurface.py:53-71,144-221,229-321`.
* Search identity: `src/leitir/search.py:225-251`.
* Engine coverage and line semantics: `src/leitir/engine.py:61,93,140,205-216`.
* Tree errors, reads, and blob hash: `src/leitir/tree.py:123-214`.
* Materialization lock and artifact parity: `src/leitir/materialize.py:173-202,405,487-513`.
* Sampled tree hashing: `src/leitir/treehash.py:100-103,197-222`.
* Duplicate identity guard: `src/leitir/ranking.py:71-73`.
* Benchmark digest and language universe: `src/leitir/bench.py:26,238-240`.
* ASV seed pin: `asv.conf.json:17-19`.
* GitHub REST/GraphQL and client evidence: links in the research document's
  References section.
