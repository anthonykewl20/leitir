# GitHub Search Capabilities

## Direct answer

**Partial.** Leitir has a real wide path for global, cross-repository discovery
and a real deep path for scoped, within-repository search. Both paths produce
deterministically ordered results with commit- and blob-pinned provenance, but
neither supports an unqualified claim of universal GitHub code search. Wide
search uses GitHub's legacy REST `GET /search/code` surface and is bounded by
Leitir's default budget of 30 results and 10 pages, as well as GitHub-side
limits. Deep search is exhaustive only over adapter-eligible blobs no larger
than 2 MiB that can be read successfully. Its implemented adapters cover
Python, Rust, and Go using line-oriented regular-expression heuristics, not
AST or semantic matching. (Wide path: `src/leitir/discovery_search.py:42-44`,
`src/leitir/discovery_search.py:231-246`, `src/leitir/discovery_search.py:459-481`;
deep path: `src/leitir/engine.py:34`, `src/leitir/engine.py:214-269`,
`src/leitir/adapters.py:73-75`, `src/leitir/adapters.py:216-217`,
`src/leitir/adapters.py:348-349`.)

This report distinguishes **Leitir behavior** from **GitHub-side facts**. A
file-and-line citation refers to the current checkout and was checked against
the files on disk while this document was written. GitHub-side limits are
identified separately and linked to GitHub's documentation.

## 1. Wide search: global discovery

### Entry point and contract

The CLI accepts global discovery as:

```text
leitir search --global --must kind:value[:language] ...
```

`--global` is mutually exclusive with `--repo` and `--package`; predicates are
provided through repeatable `--must`, `--should`, and `--must-not` options.
The CLI rejects a search with no `--must` predicate. (`src/leitir/cli.py:324-375`,
`src/leitir/cli.py:1772-1779`.)

The global branch constructs `SearchMode.GLOBAL_DISCOVERY`, runs the
`GlobalSearcher`, and reports coverage as indeterminate. The scoped branch is
not used for this command. (`src/leitir/cli.py:1811-1827`,
`src/leitir/discovery_search.py:484-488`, `src/leitir/discovery_search.py:623-640`.)

### Endpoint, credentials, and redirects

The production transport targets `https://api.github.com/search/code` and
limits `per_page` to 100 when constructing the request. (`src/leitir/discovery_search.py:42-44`,
`src/leitir/discovery_search.py:231-246`.) It sends GitHub's JSON media type,
the Leitir user agent, and API version header. A token is validated and is
sent as `Authorization: Bearer ...` only when the configured endpoint is
HTTPS on `api.github.com`. (`src/leitir/discovery_search.py:212-229`.)

The shared HTTP redirect handler removes credential headers when a redirect
changes origin. This prevents an authorization header from crossing to a
different scheme, host, or port. (`src/leitir/_http.py:72-105`.)

### Pagination and local budget

The internal `GlobalSearcher` defaults to `max_results=30` and `max_pages=10`.
It requests `min(max_results, 100)` results per page and loops from page 1
through `max_pages`. (`src/leitir/discovery_search.py:453-481`,
`src/leitir/discovery_search.py:484-506`.)

Pagination stops when any of these conditions occurs:

- enough adapter-eligible, deduplicated candidates have been collected;
- GitHub marks the page `incomplete_results`;
- the page is empty or shorter than the requested page size;
- the configured page budget is reached; or
- a later-page request fails, in which case the report is marked incomplete.

These conditions are implemented at `src/leitir/discovery_search.py:507-528`.
The first page's `total_count` becomes `files_eligible`; it is a count reported
by the remote index, not a proof that Leitir examined that many files.
(`src/leitir/discovery_search.py:512-514`.)

Candidate verification attempts are also bounded by `max_results`, including
promoted representatives after a verification failure. (`src/leitir/discovery_search.py:542-557`.)

### GitHub-side constraints

The following are **GitHub-side**, not Leitir guarantees:

| Constraint | Evidence |
|---|---|
| `GET /search/code` returns at most 100 results per page and up to 1,000 results per search | [GitHub REST search documentation](https://docs.github.com/en/rest/search/search#about-search), [Search code](https://docs.github.com/en/rest/search/search#search-code) |
| Only the default branch is considered | [GitHub Search code considerations](https://docs.github.com/en/rest/search/search#search-code) |
| Only files smaller than 384 KB are searchable | [GitHub Search code considerations](https://docs.github.com/en/rest/search/search#search-code) |
| Authenticated code search is limited to 10 requests per minute | [GitHub REST search rate limit](https://docs.github.com/en/rest/search/search#rate-limit), [Search code](https://docs.github.com/en/rest/search/search#search-code) |
| A response may set `incomplete_results` when a query times out or otherwise cannot finish | [GitHub REST timeout documentation](https://docs.github.com/en/rest/search/search#timeouts-and-incomplete-results) |

These service limits compound Leitir's smaller default budget. A wide query
therefore cannot establish global recall, even if every returned hit is
verified.

### Retry and failure behavior

The shared retry classifier treats HTTP 429, rate-signaled 403 responses,
408/425, most 5xx responses, and ordinary operating-system/network failures as
retryable; other 4xx responses and non-I/O exceptions are fatal.
(`src/leitir/_http.py:173-208`.) The default retry policy allows four total
calls, caps transient waits at 60 seconds and rate-limit waits at 300 seconds,
and re-raises the final exception after exhaustion. (`src/leitir/_http.py:262-315`.)

### Query translation

Global query construction is deliberately fail-closed for `must` predicates
that the legacy endpoint cannot express. `REGEX` is rejected rather than
flattened into a weaker term. `EXACT_TEXT`, `IDENTIFIER`, and `TOKEN_SEQUENCE`
are emitted as `github_query`; `PATH`, symbol definition/reference, signature,
call, and import predicates are emitted as a GitHub superset and evaluated
locally. (`src/leitir/discovery_search.py:358-414`.)

`should` and `must_not` predicates are local filters. `PATH` in either of those
clauses is rejected, because this translator only supports a `PATH` qualifier
for a required predicate. A language qualifier on required predicates is
appended to the GitHub query; conflicting required languages are rejected.
(`src/leitir/discovery_search.py:416-442`.)

### Provenance and verification

Each accepted API item must provide a valid blob SHA and a commit SHA that
matches both the `ref` query parameter in the API URL and the commit component
of the HTML `/blob/<sha>/` URL. (`src/leitir/discovery_search.py:61-75`,
`src/leitir/discovery_search.py:260-292`.) Leitir then fetches bytes at the
pinned commit and checks the bytes against the Git blob SHA-1 calculation.
(`src/leitir/discovery_search.py:637-652`.)

The report records `ResolutionStrategy.INDEXED_COMMIT` and
`INDETERMINATE_GLOBAL`, and every returned source must derive from a
byte-verified hit at the exact `(slug, commit_sha, path, blob_sha)`.
(`src/leitir/discovery_search.py:623-642`,
`src/leitir/discovery_search.py:666-702`.) The searcher verifies fetched bytes
against the indexed Git blob SHA before building the report, and the validator
authorizes only against those byte-verified hits, so a source can never be
authorized by a hit the pipeline collected but excluded. The validator also
rejects matches with non-finite or negative scores, spans that exceed the line
count of the byte-verified content, and exact-duplicate matches.
(`src/leitir/discovery_search.py:637-652`.) This is strong provenance for the
accepted bytes, but it does not turn the remote index into a pinned or
exhaustive input.

### Deduplication and coverage

Global hits are first ordered deterministically, then inconsistent claims for
the same `(slug, commit, path)` are excluded, followed by collapse by blob
SHA. Collapsed members are index claims and are not all fetched unless a
representative fails and a deterministic promotion is attempted.
(`src/leitir/discovery_search.py:133-165`, `src/leitir/discovery_search.py:530-557`.)

Global coverage is always `INDETERMINATE_GLOBAL`; `files_eligible` is the first
page's remote `total_count`, while `files_indexed` counts successfully checked
candidate blobs. (`src/leitir/discovery_search.py:512-514`,
`src/leitir/discovery_search.py:623-630`.) The correct verdict is therefore
**discovery with evidence**, never exhaustive global search.

## 2. Deep search: scoped exhaustive mode

### Entry point and pinned tree

The CLI accepts either:

```text
leitir search --repo owner/repo --commit <sha> --must ...
leitir search --package name --version <version> --ecosystem <ecosystem> --must ...
```

The explicit repository path creates a `RepoScope` from the supplied commit;
the package path resolves a package to a scope. Both construct
`SearchMode.SCOPED_EXHAUSTIVE`. (`src/leitir/cli.py:324-350`,
`src/leitir/cli.py:1828-1847`, `src/leitir/cli.py:1621-1635`.)

`GitHubTreeSource.list_blobs` requests the recursive Git tree for that commit
at `/repos/{slug}/git/trees/{sha}?recursive=1`, retains blob entries, and
raises `TreeTruncatedError` when GitHub reports truncation. (`src/leitir/tree.py:123-142`.)
There is no recovery path in this source: the exception aborts the scoped
search rather than silently treating a truncated tree as complete.
(`src/leitir/tree.py:127-128`, `src/leitir/engine.py:163-178`.) The tree
transport applies the same HTTPS `api.github.com` token gate as the global
transport. (`src/leitir/tree.py:95-109`.)

### Scan universe and partial results

The scanner starts with blobs for which an adapter exists and optionally
applies required `PATH` matching. `files_eligible` is the resulting count.
(`src/leitir/engine.py:205-230`.) A blob larger than `MAX_BLOB_SIZE` (2 MiB)
is excluded and makes coverage partial. A read failure is also excluded and
makes coverage partial. (`src/leitir/engine.py:34`,
`src/leitir/engine.py:235-246`.) Readable bytes are decoded as UTF-8 with
replacement characters. (`src/leitir/engine.py:248-256`.)

When a search declares a required predicate language, the eligible universe is
restricted to that canonical language. Blobs in other languages are neither
eligible nor counted as exclusions, so complete coverage remains achievable
over readable, size-eligible blobs in the requested language. An unsupported
required language is rejected before scanning.

Coverage becomes `COMPLETE_FOR_DECLARED_UNIVERSE` only when every eligible
blob is indexed and no partial condition occurred; otherwise it is `PARTIAL`.
(`src/leitir/engine.py:175-186`.) Thus scoped search **is exhaustive over the
declared pinned tree modulo adapter eligibility, the 2 MiB skip, and read
failures**. It is not exhaustive over every byte in the repository.

The 2 MiB search limit is not the materialized-tree integrity limit. Integrity
verification uses `VERIFY_MAX_FILES = 1,000` and `VERIFY_MAX_BYTES = 64 MiB`
when deciding whether to sample extracted files. (`src/leitir/materialize.py:53-54`,
`src/leitir/materialize.py:906-938`.) The underlying tree-hash module exposes
the same 1,000-file and 64 MiB bounds and records `sampled` separately from
`full`. (`src/leitir/treehash.py:41-51`, `src/leitir/treehash.py:100-103`.)
Those are integrity-hashing bounds, not search-scan bounds. A shelf can be
`verified="sampled"` while scoped search still scans every adapter-eligible
blob at or below 2 MiB.

### Language adapters and matching model

The scoped adapters are extension-based: Python accepts `.py`, Rust `.rs`, and
Go `.go`. (`src/leitir/adapters.py:66-75`, `src/leitir/adapters.py:209-217`,
`src/leitir/adapters.py:341-349`.) The CLI's adapter set is assembled for
Python, Rust, and Go. (`src/leitir/cli.py:508-516`.) The adapter implementations
use line splitting, regular expressions, word boundaries, and simple keyword
heuristics rather than a language parser or AST. (`src/leitir/adapters.py:79-101`,
`src/leitir/adapters.py:123-196`, `src/leitir/adapters.py:258-338`,
`src/leitir/adapters.py:390-463`.)

Supported predicate behavior is:

- `EXACT_TEXT`: substring on a line.
- `REGEX`: Python regular-expression matching on a line.
- `IDENTIFIER`: word-boundary regular expression.
- `TOKEN_SEQUENCE`: whitespace-separated tokens joined into a line regex.
- `SYMBOL_DEFINITION`: definition-like line regexes (`def`/`class`, Rust
  declarations, or Go declarations).
- `SYMBOL_REFERENCE`: word occurrences minus the adapter's heuristic definition
  lines, not a resolved reference graph.
- `SIGNATURE`: regex gated by declaration keywords.
- `CALL`: a name followed by a call-like delimiter.
- `IMPORT`: language-specific line/substr checks.

The implementations for these cases are at `src/leitir/adapters.py:123-196`,
`src/leitir/adapters.py:264-313`, and `src/leitir/adapters.py:396-446`.
`pred.language` is parsed into predicates but is not independently enforced by
the adapters; eligibility is selected from the file extension. This is an
important distinction from semantic language routing. (`src/leitir/cli.py:121-135`,
`src/leitir/engine.py:271-280`, `src/leitir/adapters.py:73-75`.)

Required content predicates must intersect on the same candidate line. The
adapter computes per-predicate line sets and intersects them before producing
spans. (`src/leitir/adapters.py:103-115`.) `must_not` content can exclude the
whole blob, and it also excludes an individual candidate span when it occurs on
that span's line. (`src/leitir/engine.py:65-78`, `src/leitir/engine.py:282-294`.)
`should` contributes a boost only when it matches the candidate line.
(`src/leitir/engine.py:99-112`.) `PATH` is a required-path filter implemented as
a substring or regular expression; invalid path regexes are ignored.
(`src/leitir/engine.py:50-62`, `src/leitir/engine.py:205-227`.)

### Ranking and determinism

Scores are normalized through `Decimal` values derived from score text and
then ranked by the P6 total order:

```text
(-normalized_score, slug, commit_sha, path, blob_sha, start_line, end_line)
```

(`src/leitir/ranking.py:27-61`, `src/leitir/ranking.py:64-81`.) Candidate
lines are sorted before spans are emitted, and source matches are ordered by
that total order. (`src/leitir/adapters.py:90-101`,
`src/leitir/ranking.py:64-81`.) The explicit sorting and total-order keys make
the result ordering independent of `PYTHONHASHSEED` for the same inputs.

## 3. Predicate and language coverage matrix

| Predicate kind | Global `must` | Global `should` / `must_not` | Scoped |
|---|---|---|---|
| `EXACT_TEXT` | `github_query` | `local_filter` | heuristic line substring |
| `REGEX` | `reject` | `local_filter` | heuristic line regex |
| `IDENTIFIER` | `github_query` | `local_filter` | heuristic word-boundary regex |
| `TOKEN_SEQUENCE` | `github_query` | `local_filter` | heuristic line regex |
| `SYMBOL_DEFINITION` | `github_superset_local_filter` | `local_filter` | heuristic declaration regex |
| `SYMBOL_REFERENCE` | `github_superset_local_filter` | `local_filter` | word occurrences minus heuristic defs |
| `SIGNATURE` | `github_superset_local_filter` | `local_filter` | declaration-keyword-gated regex |
| `CALL` | `github_superset_local_filter` | `local_filter` | call-like regex |
| `IMPORT` | `github_superset_local_filter` | `local_filter` | language-specific line heuristic |
| `PATH` | `github_superset_local_filter` (`path:`) | `reject` | substring/regex path filter |

Global dispositions are defined at `src/leitir/discovery_search.py:358-442`.
Scoped matching behavior is implemented at `src/leitir/engine.py:50-62`,
`src/leitir/engine.py:205-227`, and `src/leitir/adapters.py:123-196`.

The scoped language universe is currently Python, Rust, and Go, selected by
`.py`, `.rs`, and `.go` extensions. The adapter path does not enforce a
predicate's language field as a second condition; route selection is based on
the path. (`src/leitir/adapters.py:73-75`, `src/leitir/adapters.py:216-217`,
`src/leitir/adapters.py:348-349`, `src/leitir/engine.py:271-280`.)

## 4. Honest limitations

### Wide path

- It uses the legacy REST `/search/code` endpoint, not a local index or the
  newer GitHub.com code-search experience. (`src/leitir/discovery_search.py:184-246`.)
- Leitir's defaults are 30 results and 10 pages, with no CLI flags currently
  exposing those constructor settings. (`src/leitir/discovery_search.py:453-481`,
  `src/leitir/cli.py:352-375`.)
- GitHub-side limits include 100 results per page, 1,000 results per query,
  roughly 10 authenticated code-search requests per minute, default-branch
  indexing, and a 384 KB searchable-file limit. See the official links in
  [GitHub-side constraints](#github-side-constraints).
- Wide coverage is always `INDETERMINATE_GLOBAL`; `total_count` is not an
  exhaustive local denominator. (`src/leitir/discovery_search.py:512-514`,
  `src/leitir/discovery_search.py:623-630`.)
- Global `REGEX` is rejected. Structural predicates use a GitHub superset and
  local filtering rather than a lossless remote structural query.
  (`src/leitir/discovery_search.py:381-412`.)
- `validate_report` requires exact `(slug, commit_sha, path, blob_sha)`
  membership against the byte-verified hit set, not merely the collected index
  claims, so an excluded (never-fetched or mismatched) hit cannot authorize a
  source. It also rejects non-finite/negative scores, spans beyond the verified
  content, and exact-duplicate matches. (`src/leitir/discovery_search.py:637-652`,
  `src/leitir/discovery_search.py:666-702`.)

### Deep path

- Blobs larger than 2 MiB are skipped and make coverage partial.
  (`src/leitir/engine.py:34`, `src/leitir/engine.py:235-239`.)
- A truncated recursive GitHub tree raises and aborts; this implementation does
  not recover with another tree-walking API. (`src/leitir/tree.py:123-128`.)
- Only Python, Rust, and Go are adapter-eligible, by extension.
  (`src/leitir/adapters.py:73-75`, `src/leitir/adapters.py:216-217`,
  `src/leitir/adapters.py:348-349`.)
- Matching is heuristic and line-oriented, not AST or semantic analysis.
  (`src/leitir/adapters.py:79-101`, `src/leitir/adapters.py:258-338`.)
- `SYMBOL_REFERENCE` means word occurrences minus heuristic definition lines;
  it is not name binding or reference resolution. (`src/leitir/adapters.py:146-153`,
  `src/leitir/adapters.py:287-293`.)
- Multiple required content predicates must co-occur on one line, not merely in
  one file. (`src/leitir/adapters.py:103-115`.)
- The adapter path does not independently enforce `pred.language`.
  (`src/leitir/cli.py:121-135`, `src/leitir/engine.py:271-280`.)

### Verification and operations

- Live tests are opt-in behind `LEITIR_ENABLE_LIVE_E2E=1`; the default CI path
  does not exercise real GitHub search. (`docs/ci.md:1-8`,
  `tests/test_global_e2e_live.py:1-22`, `.github/workflows/live-canary.yml:45-52`.)
- Retry protects against transient transport failures, but it cannot remove
  GitHub index incompleteness or service-side search limits.
  (`src/leitir/_http.py:262-315`, `src/leitir/discovery_search.py:512-528`.)

## 5. Improvement opportunities

The following are concrete options, not promises. All preserve the current
stdlib-only runtime constraint unless explicitly changed later.

| Opportunity | Why | Effort | Risk | Stdlib-only feasibility |
|---|---|---:|---|---|
| Expose `--max-results`, `--max-pages`, and `--language` | Makes existing internal controls and language intent visible to callers; no new search semantics required. (`src/leitir/discovery_search.py:459-481`, `src/leitir/cli.py:352-375`) | S | Low | Yes |
| Investigate migration to newer GitHub Code Search | The current transport is REST `/search/code`; a migration could improve query capability, but endpoint semantics, auth, pagination, and provenance need research against the current GitHub product/API contract. (`src/leitir/discovery_search.py:184-246`) | M-L | Medium | Possible: GraphQL/HTTP can use `urllib`, but API support must be verified first |
| Add JavaScript/TypeScript, Java, C, and C++ adapters | Expands scoped coverage while retaining the current heuristic model. (`src/leitir/adapters.py:66-75`, `src/leitir/adapters.py:209-217`, `src/leitir/adapters.py:341-349`) | M | Low | Yes |
| Add AST-based Python matching | Python's stdlib `ast` can make Python definitions, references, and signatures more precise than line regexes. (`src/leitir/adapters.py:143-162`) | M | Low | Yes |
| Recover from truncated recursive trees | Fall back to a paginated non-recursive tree walk or contents API instead of aborting. (`src/leitir/tree.py:123-128`) | M | Medium | Yes |
| Stream or index large blobs | Avoid converting every blob over 2 MiB into an automatic exclusion. (`src/leitir/engine.py:235-239`) | M | Medium | Yes |
| Add whole-file `must` mode | Permit required predicates to co-occur anywhere in one file, while retaining current same-line behavior by default. (`src/leitir/adapters.py:103-115`) | S-M | Low | Yes |
| Enforce `pred.language` in adapters | Reject or route mismatched predicates instead of relying only on extensions. (`src/leitir/cli.py:121-135`, `src/leitir/engine.py:271-280`) | S | Low | Yes |
| Support global `REGEX` through a bounded superset | Usually not feasible without a remote regex-capable index or a potentially huge, lossy term expansion; fail-closed rejection is safer than pretending a term is a regex. (`src/leitir/discovery_search.py:381-386`) | L / hard | High | Possible in theory, but not a generally sound stdlib-only solution |
| Add a live-search canary | Exercise real GitHub search in the existing opt-in live-canary workflow and detect API/index drift. (`.github/workflows/live-canary.yml:45-52`, `tests/test_global_e2e_live.py:1-22`) | S | Low | Yes |

## 6. References

### Local design records

- [ADR-0001: Remove Hy3 and make Leitir a deterministic code-search kernel](adr/0001-remove-hy3-deterministic-search.md)
  defines the distinction between scoped exhaustiveness and indeterminate
  global discovery and requires immutable result provenance. (`docs/adr/0001-remove-hy3-deterministic-search.md:21-31`.)
- [ADR-0002: Build a deterministic, evidence-bound scoring engine](adr/0002-deterministic-evidence-scoring-engine.md)
  records the P6 ranking order and the requirement that global recall cannot be
  treated as known. (`docs/adr/0002-deterministic-evidence-scoring-engine.md:328-375`.)

### Relevant implementation

- Global transport, query translation, provenance, pagination, and validation:
  `src/leitir/discovery_search.py`.
- Shared retry and redirect credential handling: `src/leitir/_http.py`.
- Pinned Git tree enumeration and blob reads: `src/leitir/tree.py`.
- Scoped scan and coverage accounting: `src/leitir/engine.py`.
- Python, Rust, and Go predicate adapters: `src/leitir/adapters.py`.
- Stable score normalization and ordering: `src/leitir/ranking.py`.
- Materialization verification bounds: `src/leitir/materialize.py` and
  `src/leitir/treehash.py`.

### GitHub-side documentation

- [REST API: Search](https://docs.github.com/en/rest/search/search)
- [REST API: Search code](https://docs.github.com/en/rest/search/search#search-code)
- [REST API: Search timeouts and incomplete results](https://docs.github.com/en/rest/search/search#timeouts-and-incomplete-results)

GitHub-side limits and product behavior can change independently of Leitir;
re-check the linked documentation before treating them as a current operational
contract.
