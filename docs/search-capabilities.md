# GitHub Search Capabilities

## Direct answer

**Partial.** Leitir has a real wide path for global, cross-repository discovery
and a real deep path for scoped, within-repository search. Both paths produce
deterministically ordered, commit- and blob-pinned results, but neither supports
an unqualified claim of universal GitHub code search.

The wide path uses GitHub's legacy REST `GET /search/code` endpoint. Its
defaults are 30 candidate-verification attempts and 10 pages; callers can set
`--max-results`, `--max-pages`, and `--language`. Coverage remains
`INDETERMINATE_GLOBAL` because the remote index is neither pinned nor proven
exhaustive. (`src/leitir/discovery_search.py:184-249`,
`src/leitir/discovery_search.py:441-486`, `src/leitir/cli.py:391-405`,
`src/leitir/cli.py:1830-1858`.)

The deep path scans a pinned tree through adapters for Python, Rust, Go,
JavaScript, TypeScript, Java, C, and C++. Python uses the unchanged heuristic
adapter by default; `--ast` opts into stdlib `ast` plus `symtable` lexical
classification. Blobs above 2 MiB are streamed in line-aligned windows and
verified incrementally against their Git blob SHA-1. Truncated recursive trees
are recovered through a bounded non-recursive walk, with recovery or an
incomplete walk reported as `PARTIAL`. (`src/leitir/adapters/registry.py:17-59`,
`src/leitir/cli.py:377-405`, `src/leitir/adapters/python_ast.py:164-226`,
`src/leitir/streaming.py:37-168`, `src/leitir/tree.py:136-210`,
`src/leitir/engine.py:236-260`.)

This report distinguishes **Leitir behavior** from **GitHub-side facts**.
File-and-line citations refer to this checkout; service limits are linked to
GitHub's documentation.

## 1. Wide search: global discovery

### Contract, budgets, and endpoint

The CLI accepts global discovery as:

```text
leitir search --global --must kind:value[:language] ... \
  [--max-results N] [--max-pages N] [--language NAME]
```

`--global` is mutually exclusive with repository and package scope. A search
requires at least one `--must`; the three global controls are rejected outside
global mode. (`src/leitir/cli.py:324-405`, `src/leitir/cli.py:1790-1825`.)

The production transport calls `/search/code`, caps `per_page` at 100, and
sends the GitHub JSON media type and API-version header. A token is sent only
when the configured endpoint is HTTPS on `api.github.com`.
(`src/leitir/discovery_search.py:184-249`.)

`GlobalSearcher` defaults to `max_results=30` and `max_pages=10`; both the CLI
and constructor enforce service-aligned maxima of 1000 results and 100 pages.
It requests `min(max_results, 100)` items per page, and stops on its candidate
budget, GitHub's `incomplete_results`, a short/empty page, a page failure, or
the page budget. Candidate-budget stops are reported incomplete whenever the
remote count shows uncollected results. Candidate fetch/verification attempts,
including promoted candidates, are also bounded by `max_results`.
(`src/leitir/discovery_search.py:441-519`,
`src/leitir/discovery_search.py:532-560`.)

### Query translation and language routing

Global query construction is fail-closed for required predicates the legacy
endpoint cannot express. Required `REGEX` is rejected. Exact text,
identifiers, and token sequences become GitHub terms; path and structural
predicates become a GitHub superset followed by local filtering. `should` and
`must_not` are local filters, while their `PATH` form is rejected. Conflicting
required languages are rejected and a canonical language value is stored in
the search spec (so aliases and case variants share an identity); that
qualifier is added to the query. (`src/leitir/discovery_search.py:349-433`.)

Both search paths canonicalize language aliases and require a matching adapter.
An unsupported required language is rejected before candidates are scanned.
(`src/leitir/adapters/languages.py:5-17`,
`src/leitir/discovery_search.py:466-479`,
`src/leitir/discovery_search.py:659-668`, `src/leitir/engine.py:217-229`,
`src/leitir/engine.py:399-408`.)

### Provenance, validation, and coverage

An API hit is accepted only when the commit in its API `ref` agrees with the
commit in its HTML `/blob/<sha>/` URL. Leitir fetches the path at that commit
and verifies the bytes against the claimed Git blob SHA-1.
(`src/leitir/discovery_search.py:61-75`,
`src/leitir/discovery_search.py:251-284`,
`src/leitir/discovery_search.py:575-611`,
`src/leitir/discovery_search.py:642-657`.)

Report validation authorizes every source against the complete global
provenance tuple `(slug, commit_sha, path, blob_sha)` from the byte-verified hit
set. It rejects a moving reference, invalid score, out-of-range span, or exact
duplicate. (`src/leitir/discovery_search.py:671-707`.) Results are therefore
strong evidence for accepted bytes, but wide coverage remains
`INDETERMINATE_GLOBAL`; the first page's remote `total_count` is not an
exhaustive local denominator. (`src/leitir/discovery_search.py:503-505`,
`src/leitir/discovery_search.py:621-640`.)

### GitHub-side constraints

These are **GitHub-side**, not Leitir guarantees:

| Constraint | Evidence |
|---|---|
| REST code search returns at most 100 results per page and up to 1,000 results per search | [GitHub REST search documentation](https://docs.github.com/en/rest/search/search#about-search) |
| Only the default branch is considered | [GitHub code-search considerations](https://docs.github.com/en/rest/search/search#search-code) |
| Only files smaller than 384 KB are searchable by this endpoint | [GitHub code-search considerations](https://docs.github.com/en/rest/search/search#search-code) |
| Authenticated code search has a separate low request rate | [GitHub REST search rate limit](https://docs.github.com/en/rest/search/search#rate-limit) |
| Responses can report `incomplete_results` | [GitHub timeout documentation](https://docs.github.com/en/rest/search/search#timeouts-and-incomplete-results) |

These service limits compound Leitir's local budgets. Wide search is discovery
with evidence, not a global-recall guarantee.

## 2. Deep search: scoped exhaustive mode

### Pinned tree and truncation recovery

Scoped search accepts a repository plus exact commit SHA, or a package resolved
to such a scope. `GitHubTreeSource.list_blobs_ex` first requests a recursive
tree. If GitHub marks it truncated, Leitir performs a deterministic,
non-recursive subtree walk with depth, request, and entry budgets. Malformed
responses, nested truncation, path collisions, and exhausted budgets fail
closed with any blobs safely recovered so far attached to the enumeration
error. The `list_blobs()` wrapper completes the same recovery walk for a
truncated recursive listing and returns the full blob universe (paths, blob
SHAs, modes) — large repositories such as microsoft/TypeScript enumerate
without a sampled downgrade — while `list_blobs_ex()` remains the variant
that additionally reports whether recovery walked.
(`src/leitir/tree.py:141-261`, `src/leitir/tree.py:388-476`.)

`ScopedSearcher` searches recovered blobs. Successful recovery and failed
recovery with partial blobs both produce real matches but set coverage to
`PARTIAL` and `incomplete_results=True`; a normal complete tree can still earn
`COMPLETE_FOR_DECLARED_UNIVERSE`. (`src/leitir/engine.py:236-277`.)

### Scan universe and large-blob streaming

The eligible universe is selected by adapter, required canonical language, and
required path filters. Unsupported required languages are rejected before the
scan. (`src/leitir/engine.py:217-229`, `src/leitir/engine.py:279-311`.)

Blobs at or below 2 MiB use the ordinary blob read. Larger blobs use
the raw streaming read and are not automatically omitted: Leitir decodes
incrementally, evaluates line-aligned windows, rebases line spans, tracks the
declared byte count, and computes the Git blob SHA-1 incrementally. A size or
digest mismatch, an over-budget line, or a stream failure excludes that blob
and makes coverage partial. (`src/leitir/engine.py:317-350`,
`src/leitir/streaming.py:37-168`, `src/leitir/tree.py:239-252`.)

Whole-file `must` cannot be evaluated safely window-by-window, so a blob above
2 MiB is excluded when `--whole-file` is active; ordinary-sized blobs support
whole-file matching. (`src/leitir/streaming.py:51-52`,
`src/leitir/engine.py:380-395`.)

### Language adapters and matching model

The deterministic registry contains eight languages: Python, Rust, Go,
JavaScript, TypeScript, Java, C, and C++. (`src/leitir/adapters/registry.py:17-37`.)
The latter five are Tier-2 regex adapters with hand-adapted patterns attributed
to nvim-treesitter; emitted matches record `method=heuristic`.
(`src/leitir/adapters/_tier2/__init__.py:1-7`,
`src/leitir/adapters/_tier2/_base.py:23-99`,
`src/leitir/adapters/_tier2/javascript.py:1-34`.)

Heuristic matching remains the default, including for Python. `--ast` replaces
only the Python adapter with `PythonAstAdapter`; structural predicates then use
stdlib `ast`, and references receive `symtable`-based lexical classification.
On parse failure it falls back to regex and marks the parser unavailable. On
`symtable` failure it retains AST structure, marks reference provenance unknown,
and also marks the result incomplete; the engine converts either condition to
`PARTIAL`. (`src/leitir/adapters/registry.py:40-59`,
`src/leitir/adapters/python_ast.py:186-226`,
`src/leitir/adapters/python_ast.py:273-290`,
`src/leitir/engine.py:369-395`.)

**Comments and string literals are excluded by the five Tier-2 adapters.** All five Tier-2 adapters (JavaScript, TypeScript, Java, C, C++) run
`mask_comments_and_strings()` on the file before evaluating any content
predicate (`exact_text`, `regex`, `identifier`, `token_sequence`, `signature`,
`call`, `import`, `symbol_definition`/`symbol_reference`); an occurrence that
exists only inside a comment or a string/template literal is never returned,
even though the raw bytes are present in the file and a plain-text tool such as
`grep` would report them. (`src/leitir/adapters/_tier2/_base.py:48`,
`src/leitir/adapters/_tier2_patterns.py`.) **Python, Rust and Go heuristic adapters instead scan raw text.** The default heuristic Python adapter matches against
raw, unmasked source lines, so a required predicate can match text inside a
Python string literal or `#` comment. `--ast`'s structural predicate kinds
(`symbol_definition`, `symbol_reference`, `call`, `import`, `signature`)
consult the parsed AST and so cannot match inside a comment (comments are not
nodes) or, for those kinds specifically, inside a string; but any *content*
predicate on a Python file that is not one of those structural kinds (for
example `exact_text` or `regex`) still falls back to the same raw, unmasked
line scan as the non-AST default. (`src/leitir/adapters/__init__.py:119`,
`src/leitir/adapters/python_ast.py:233-244`.) If a diff against
`grep` shows leitir "missing" matches on a JS/TS/Java/C/C++ file, check whether
they are inside a comment or string literal first -- that is expected,
by-design behavior, not a bug.

By default, required content predicates intersect on one line. `--whole-file`
sets `SearchSpec.whole_file_must`, allowing required predicates to occur on
different lines in one ordinary-sized file. (`src/leitir/cli.py:377-389`,
`src/leitir/search.py:198-223`, `src/leitir/adapters/__init__.py:111-161`,
`src/leitir/engine.py:380-391`.)

### Ranking and deterministic provenance

Every result identifies repository, commit, path, blob, and exact line span.
Scores are normalized through `Decimal` and sorted by the P6 total order
`(-normalized_score, slug, commit_sha, path, blob_sha, start_line, end_line)`.
Duplicate identities are rejected. (`src/leitir/ranking.py:13-24`,
`src/leitir/ranking.py:27-81`.) Explicit sorting in tree enumeration, adapter
construction, streaming result emission, and ranking makes output independent
of hash iteration order for identical inputs.

## 3. Local-corpus path: corpus-wide search

### Overview and motivation

Corpus-wide search fans a scoped-exhaustive query out across every eligible
materialized shelf in the local corpus. It is fully offline and commit- and
blob-pinned: it does not discover new sources and does not require network
access. The motivating use case is answering "where in anything I depend on does
X happen?" when a developer has many materialized shelves but doesn't know which
one holds the answer. (`src/leitir/index/query.py:335-462`,
`src/leitir/cli.py:816-827`, `src/leitir/cli.py:3026-3053`.)

```text
leitir search --corpus --must kind:value[:language] ... \
  [--index] [--require-index]
```

`--corpus` is mutually exclusive with `--global`, `--repo`, and `--package`.

### Eligibility, exclusion, and coverage honesty

A shelf is eligible for corpus search if it is present in the corpus index.
`CorpusSearcher` performs a cheap pre-check (`_corpus_eligibility()`) that loads
manifest metadata without reading source trees, then instantiates a
`ScopedSearcher` (or `IndexedSearcher` with `--index`) for every eligible shelf.
Each shelf's report is aggregated: coverage statistics are summed, matches are
merged, and shelf-level outcomes are recorded.

Shelf exclusion is named with a structured reason. A shelf is excluded (rather
than searched) when:
- `unindexed`: it has no built trigram index and `--require-index` was specified.
- `verification_failed`: load-time verification (tree integrity or checksum) fails
  after the cheap pre-check passes.
- `drift_parity`: the shelf's parity metadata is `drift` or `unknown`.
- `registry_provenance`: the shelf was resolved registry-only without a git
  commit pinning.
- `unsupported_host`: the shelf is on a host not yet supported by the adapter
  for generic tree enumeration.
- `partial_tree_scope`: the shelf's materialized-tree hash covers only a
  partial-tree scope (incomplete source).

Excluded shelves are always named in `shelves_excluded` with both identity and
reason; this is never silent. (`src/leitir/search.py:495-504`,
`src/leitir/index/query.py:405-418`, `src/leitir/cli.py:3041-3046`.)

`corpus_status` is `CoverageStatus.COMPLETE_FOR_DECLARED_UNIVERSE` only when
both of these hold: (1) the `shelves_excluded` list is empty, and (2) every
searched shelf itself reported `COMPLETE_FOR_DECLARED_UNIVERSE` coverage at the
file level. Any named exclusion or any per-shelf partial result forces
`corpus_status` to `PARTIAL`. An empty corpus (zero shelves materialized) is
reported honestly: zero searched, zero excluded, no matches, and `corpus_status`
remains `PARTIAL` (never a false "complete" claim about dependencies that were
never materialized). (`src/leitir/search.py:559-616`,
`src/leitir/index/query.py:446-450`.)

### Indexing and fallback

Like scoped search, `--index` uses local trigram indexes when available and
falls back to full-tree scanning for unindexed shelves. `--require-index`
rejects unindexed shelves instead, excluding them with reason `unindexed`.
This is per-shelf: a corpus search with `--require-index` still searches all
indexed shelves and reports the unindexed ones as excluded, never aborting the
whole operation. (`src/leitir/index/query.py:400-413`.)

## 4. Exit codes

`leitir search` uses the same four-tier `ExitCode` as the rest of the CLI
(`src/leitir/cli.py:64-70`): `SUCCESS = 0`, `CORPUS_FAILURE = 1`,
`MALFORMED_USAGE = 2`, `INFRASTRUCTURE_FAILURE = 3`. The dispatcher wraps all
four scopes -- `--corpus`, `--global`, and the scoped `--repo`/`--package`
branch -- in one `try` block (`src/leitir/cli.py:3604-3733`) with a shared
exception ladder, so the mapping below is uniform across scopes rather than
scope-specific:

- **0 (success):** the search ran to completion and produced a report,
  including a `--corpus` run where individual shelves were excluded (see
  below) and a partial/incomplete result on the deep or wide path -- an
  incomplete-but-honest report is still a successful command invocation.
- **1 (`CORPUS_FAILURE`):** `SearchSpecError` is not raised, but a
  `VerificationError` propagates out of the scope's own search call
  (`src/leitir/cli.py:3728-3730`). Concretely this covers:
  - a corrupt or unreadable corpus catalog (`leitir-sources.json`) under
    `--corpus`, raised before any shelf is even considered
    (`src/leitir/corpus.py:94-99`, surfaced through
    `_corpus_eligibility()`'s `shelves_from_corpus(root, strict=True)` at
    `src/leitir/index/query.py:320`);
  - a local materialized shelf whose bytes fail load-time tree-hash
    verification, reached directly (not caught locally) on the scoped
    `--repo`/`--package` path via `ScopedSearcher`/`IndexedSearcher`
    (`src/leitir/engine.py:76-194` raises; nothing between there and
    `src/leitir/cli.py:3728` catches it for this path).

  This is **not** reachable on `--global`: `GlobalSearcher`
  (`src/leitir/discovery_search.py:768-`) is built from a GitHub-backed
  `CodeSearchPort` and `TreeSource` only, never a `corpus_root`, and never
  touches `leitir.materialize.read_valid_manifest` or
  `leitir.engine._LocalShelfReader` -- there is no local-shelf verification
  step on the global-discovery path to fail.
- **2 (`MALFORMED_USAGE`):** `SearchSpecError` (an invalid predicate/spec) or
  an invalid scope combination caught earlier in argument handling -- e.g.
  `--corpus` combined with `--repo`/`--package`/`--global`
  (`src/leitir/cli.py:3725-3727`).
- **3 (`INFRASTRUCTURE_FAILURE`):** everything else -- network/transport
  errors, an unresolvable package reference, a malformed commit SHA, and any
  other exception not typed as `SearchSpecError` or `VerificationError`
  (`src/leitir/cli.py:3731-3733`).

### `--corpus` is the one scope where the exit code alone is not the whole story

Under `--corpus`, a per-shelf `VerificationError` (a tampered or otherwise
unverifiable shelf) does **not** propagate to the top-level handler above --
`CorpusSearcher.search()` catches it itself, excludes that one shelf, and
keeps going (`src/leitir/index/query.py:410-427`). The command still exits
**0**. The only way `--corpus` exits 1 is the catalog-level failure described
above (nothing to iterate over at all), which is a materially different
situation from "one shelf out of many was unverifiable."

This means: **a caller that checks only the exit status of `--corpus` will
not learn that some shelves were skipped.** The honesty lives entirely in the
JSON payload, not the exit tier: `corpus_status` is forced to `"partial"`
whenever anything was excluded, and `shelves_excluded` names every skipped
shelf and its reason (`unindexed`, `verification_failed`, `drift_parity`,
`registry_provenance`, `unsupported_host`, `partial_tree_scope` -- see
section 3 above). Any agent or script consuming `leitir search --corpus`
programmatically must read `corpus_status`/`shelves_excluded` from the
payload, not just branch on the process exit code, or it will silently treat
a partial, integrity-compromised result as if it were a complete one.

## 5. Honest limitations

### Wide path

- The transport still uses legacy REST `/search/code`, not a local index or the
  newer GitHub.com code-search experience. (`src/leitir/discovery_search.py:184-249`.)
- GitHub-side indexing, result, and rate limits prevent a global recall claim.
- Global required `REGEX` remains fail-closed rejected; structural predicates
  use remote supersets plus local filtering. (`src/leitir/discovery_search.py:349-433`.)
- Coverage is always `INDETERMINATE_GLOBAL` even when all returned candidates
  verify. (`src/leitir/discovery_search.py:621-640`.)

### Deep path

- Matching is heuristic and line-oriented by default. The Python AST adapter is
  opt-in, and the JavaScript/TypeScript/Java/C/C++ adapters remain heuristic.
  (`src/leitir/adapters/registry.py:40-59`,
  `src/leitir/adapters/_tier2/_base.py:23-99`.)
- Large blobs are streamed and SHA-1 verified, but a line over 512 KiB, a
  verification/read failure, or whole-file mode on a large blob yields a
  partial exclusion. (`src/leitir/streaming.py:17-20`,
  `src/leitir/streaming.py:126-168`.)
- Truncated trees are recovered within fixed budgets. Recovery is reported as
  partial, and failures preserve only safely enumerated blobs.
  (`src/leitir/tree.py:136-210`, `src/leitir/engine.py:236-260`.)
- Python parse or symbol-table failure is fail-soft through explicit partial
  coverage, not silently treated as parser-backed completeness.
  (`src/leitir/adapters/python_ast.py:207-226`,
  `src/leitir/engine.py:369-395`.)
- Tier-2 (JavaScript, TypeScript, Java, C, C++) content predicates exclude matches inside comments and
  string/template literals (the Tier-2 adapters mask them out before
  matching); Python content predicates other than the structural `--ast`
  kinds do not, and match raw source text including comments and string
  contents. This asymmetry is intentional (code-search, not plain-text
  search) but is easy to mistake for a bug when comparing byte-for-byte
  against `grep`. (`src/leitir/adapters/_tier2/_base.py:48`,
  `src/leitir/adapters/__init__.py:119`.)

### Local-corpus path

- Corpus search is offline but local-only: it does not discover new sources.
  The set of searched shelves is determined entirely by prior materialization;
  sources not yet downloaded are never searched.
- An empty corpus (no shelves materialized) produces zero results and
  `corpus_status=PARTIAL`, not a false "complete" claim.
- Coverage depends on shelf-level eligibility and individual search success;
  each excluded shelf is named with its reason and prevents corpus_status from
  claiming completeness. (`src/leitir/search.py:559-616`.)

### Verification and operations

- Real-provider tests are opt-in, and the live canary is fail-closed: its
  classifier exits non-zero for configuration or product failures on enabled
  surfaces. Search-v2 probes for baseline live search, truncated-tree recovery,
  verified large-blob streaming, and index-vs-scan recall are wired into the
  workflow. (`docs/ci.md`.)
- Retry cannot remove remote-index incompleteness or service-side limits.

## 6. Improvement opportunities

Search v2 shipped the adapter expansion, Python AST option, large-blob
streaming, truncation recovery, whole-file mode, language routing, and exposed
global budgets. The remaining opportunities are:

| Opportunity | Why | Effort | Risk | Stdlib-only feasibility |
|---|---|---:|---|---|
| Investigate migration to newer GitHub Code Search | The current transport is legacy REST `/search/code`; endpoint semantics, auth, pagination, and immutable provenance require fresh API research. (`src/leitir/discovery_search.py:184-249`) | M-L | Medium | Possible, subject to a supported API |
| Support global `REGEX` through a bounded superset | The legacy endpoint cannot express arbitrary regex; fail-closed rejection is safer than pretending a term is equivalent. (`src/leitir/discovery_search.py:349-377`) | L / hard | High | Possible only for safely bounded subsets |
| Completed: live-search canary (S3 slice #88; PRs #106/#121) | Search-v2-specific real-provider probes for index drift, truncation recovery, and large-blob streaming are in the opt-in workflow. (`docs/ci.md`) | S | Low | Yes |

## 7. References

- [ADR-0001: Remove Hy3 and make Leitir a deterministic code-search kernel](adr/0001-remove-hy3-deterministic-search.md)
- Global transport, translation, verification, and provenance validation:
  `src/leitir/discovery_search.py`.
- Scoped scan and coverage: `src/leitir/engine.py`.
- Adapter registry and implementations: `src/leitir/adapters/registry.py`,
  `src/leitir/adapters/__init__.py`, `src/leitir/adapters/python_ast.py`, and
  `src/leitir/adapters/_tier2/`.
- Large-blob streaming: `src/leitir/streaming.py`.
- Pinned tree enumeration and reads: `src/leitir/tree.py`.
- [GitHub REST search documentation](https://docs.github.com/en/rest/search/search)

GitHub-side behavior can change independently of Leitir; re-check the linked
documentation before treating it as a current operational contract.

Search corrections (#312, 2026-09-05): `should` predicates contribute independently, once per overlapping predicate. `must_not` content predicates exclude documents in buffered, indexed and streamed searches; direct scoring follows the same rule. Each serialized match carries `method: ast|heuristic`, including fallback results. CLI predicates accept a closed JSON object (`kind`, `value`, optional `language`) for unambiguous literals; shorthand uses a recognized final language suffix. `ask` emits JSON predicates whenever needed for exact replay.
C++ header eligibility (#328): explicit `cpp` language selection includes ordinary `.h` headers, including the pinned fmt benchmark sources. With no explicit language, the existing adapter order keeps C as the default for ambiguous `.h` files.
