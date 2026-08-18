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

## 3. Honest limitations

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

### Verification and operations

- Real-provider tests are opt-in, and the live canary is fail-closed: its
  classifier exits non-zero for configuration or product failures on enabled
  surfaces. Search-v2 probes for baseline live search, truncated-tree recovery,
  verified large-blob streaming, and index-vs-scan recall are wired into the
  workflow. (`docs/ci.md`.)
- Retry cannot remove remote-index incompleteness or service-side limits.

## 4. Improvement opportunities

Search v2 shipped the adapter expansion, Python AST option, large-blob
streaming, truncation recovery, whole-file mode, language routing, and exposed
global budgets. The remaining opportunities are:

| Opportunity | Why | Effort | Risk | Stdlib-only feasibility |
|---|---|---:|---|---|
| Investigate migration to newer GitHub Code Search | The current transport is legacy REST `/search/code`; endpoint semantics, auth, pagination, and immutable provenance require fresh API research. (`src/leitir/discovery_search.py:184-249`) | M-L | Medium | Possible, subject to a supported API |
| Support global `REGEX` through a bounded superset | The legacy endpoint cannot express arbitrary regex; fail-closed rejection is safer than pretending a term is equivalent. (`src/leitir/discovery_search.py:349-377`) | L / hard | High | Possible only for safely bounded subsets |
| Completed: live-search canary (S3 slice #88; PRs #106/#121) | Search-v2-specific real-provider probes for index drift, truncation recovery, and large-blob streaming are in the opt-in workflow. (`docs/ci.md`) | S | Low | Yes |

## 5. References

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
