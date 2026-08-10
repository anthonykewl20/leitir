# GitHub Code Search Upgrade Research

**Date:** 2026-08-10  
**Scope:** read-only research for Leitir's GitHub-backed and local code search

## Executive Finding

**GitHub exposes no public API for the new Blackbird code search.** The REST
`GET /search/code` endpoint is the legacy surface. Current REST documentation
describes it as returning at most 100 results per page, with at most 1,000
results per search, authenticated code-search traffic limited to 10 requests
per minute, default-branch-only indexing, and a 384 KB searchable-file limit.
The endpoint does not expose the advanced github.com code-search language:
`/regex/`, `symbol:`, and related syntax are web UI capabilities, not a
replacement API contract.

The GraphQL `search` query has no `CODE` search type. It exposes `codeCount`
as a count field on repositories, but it cannot return code-result nodes. The
GitHub CLI source makes the boundary explicit: its code-search command warns
that results use the legacy engine and that regex search is not yet available
through the GitHub API. The CLI's `--web` path opens the website; it is not an
API adapter.

Therefore, **migrating to a "new code-search API" is not possible today**.
Leitir's fail-closed rejection of `REGEX` in the global path must stay. Do not
flatten a regex into a weaker GitHub keyword query and call that equivalent.

The useful pivot is local:

- **Wide:** build a Zoekt-style trigram inverted index over Leitir's
  materialized corpus cache. Use trigram candidate filtering, then full regex
  verification. This bypasses GitHub's remote result and file-size caps for
  content Leitir has actually materialized.
- **Deep:** replace line-oriented symbol heuristics with real structural
  extraction. Start with Python's stdlib `ast` and `symtable`; add a
  language-neutral symbol/occurrence model shaped like SCIP.
- **Coverage and robustness:** recover from GitHub's truncated recursive trees,
  do not abort a walk merely because one response hit a service cap, and stream
  large blobs instead of skipping them.

This is not a claim of universal GitHub recall. Local results are exhaustive
only for the verified, materialized corpus and the declared parser/index
universe. Every incomplete walk, failed read, capped line, or unavailable
parser must remain visible in coverage metadata.

## Easy Wins: Small, Low-Risk, Stdlib

### 1. Expose result and page budgets

**Status:** Internal capability exists; CLI exposure is missing. The global
searcher already accepts `max_results=30` and `max_pages=10`.

**Proven source:** Leitir `src/leitir/discovery_search.py`, global searcher
constructor and pagination loop; Leitir `src/leitir/cli.py`, search argument
construction. License: Leitir project license.

**Copy/adapt feasibility:** Trivial argparse wiring; validate positive values
and retain a bounded maximum so a user cannot defeat resource budgets.

**Recommendation:** Add `--max-results`, `--max-pages`, and `--language` to
the search command. Pass the first two to the global searcher and use the
language option as the explicit required language filter. Document that these
are budgets, not a completeness guarantee; GitHub still caps the endpoint at
100 per page and 1,000 per search.

### 2. Validate the complete provenance tuple

**Status:** The fetch path verifies path/blob bytes before report creation, but
`validate_report` itself is weaker than the report contract.

**Proven source:** Leitir `src/leitir/discovery_search.py` global candidate
validation and report validation; Leitir `src/leitir/search.py` `SourceRef`.
License: Leitir project license.

**Copy/adapt feasibility:** Small internal change. Build the accepted set from
`(slug, commit_sha, path, blob_sha)` and reject any source outside it. Keep the
existing byte-level Git blob verification as an additional check.

**Recommendation:** Implement immediately and add tamper tests for each tuple
component. A matching repository and commit must not authorize a different
path or blob claim.

### 3. Enforce language routing in adapters

**Status:** Language is present on `Predicate`, but adapters currently route
by extension and do not enforce `pred.language` independently.

**Proven source:** Leitir `src/leitir/search.py:101-129`,
`src/leitir/engine.py`, and `src/leitir/adapters.py` language properties and
`find_matches` methods. License: Leitir project license.

**Copy/adapt feasibility:** Low risk. Normalize the requested language once
and require it to match the adapter's canonical language. Conflicts remain a
rejected search spec, not an empty success.

**Recommendation:** Make routing explicit at the adapter boundary. Preserve
extension eligibility as a separate check. Add tests for aliases only if a
canonical alias table is deliberately defined; do not guess from arbitrary
user strings.

### 4. Add a live search canary

**Status:** The repository has live-canary infrastructure, but no search
canary is wired into it.

**Proven source:** `.github/workflows/live-canary.yml` (existing workflow) and
Leitir's global/scoped search entry points. License: project-owned workflow;
no third-party code is copied.

**Copy/adapt feasibility:** Low-risk configuration and test work. Gate it with
`LEITIR_ENABLE_LIVE_E2E=1`, use a small pinned public repository, and assert
provenance and coverage rather than a brittle ranking position.

**Recommendation:** Add one authenticated REST smoke and one scoped pinned-tree
smoke. Treat rate-limit, timeout, and unavailable-service outcomes as canary
infrastructure failures, not as reasons to weaken production fail-closed
behavior.

## Medium: Depth, Language Coverage, and Robustness

### 5. Python AST matching

**Status:** Python matching is currently regex-based. This is the highest-value
deep-search improvement for the existing adapter set.

**Proven sources:**

- `python/cpython`, stdlib `Lib/ast.py` and `symtable` documentation, PSF
  license: parser and scope primitives are already available on Python >=3.11.
- `mkdocstrings/griffe`, ISC: concrete mechanics for walking definitions,
  members, signatures, and source ranges.
- `davidhalter/jedi`, MIT: useful algorithm reference for names, scopes, and
  references. Jedi depends on Parso, so it is an algorithm reference, not a
  vendorable runtime dependency.

**Copy/adapt feasibility:** Adapt the mechanics, not the implementations.
`ast` and `symtable` satisfy the stdlib-only rule. Griffe is permissive enough
to inspect and adapt with attribution review; Jedi's dependency graph makes
wholesale copying inappropriate.

**Recommendation:** Build a two-pass Python adapter:

1. Parse once with `ast.parse`, record module/class/function/lambda scopes,
   definitions, arguments, assignments, imports, and source ranges.
2. Walk expressions and statements again. Emit `Name` nodes with `Load`
   context as references, `Call` nodes as calls, and signatures from function
   arguments/returns. Resolve names lexically through the scope chain; mark
   unresolved and dynamic cases rather than inventing targets.

The first release should guarantee structural spans and lexical scope
resolution, not cross-module type inference. Syntax errors produce a
parser-unavailable/partial result, never a false complete result.

### 6. More language adapters

**Status:** Current adapters cover Python, Rust, and Go only, and use heuristic
line patterns. JavaScript/TypeScript/Java/C/C++ coverage is absent.

**Proven sources:**

- `nvim-treesitter/nvim-treesitter`, `queries/<lang>/highlights.scm`: a
  maintained inventory of language node names and capture conventions.
- `tree-sitter/tree-sitter` and the corresponding language grammar
  repositories: structural grammar model; the runtime and grammars are MIT.
- `ast-grep/ast-grep`, MIT: structural matching concepts and pattern
  semantics, useful as a design reference.

**Copy/adapt feasibility:** Do not copy query files blindly. Derive small,
reviewed regex sets from the structural inventory, or later use a permitted
tree-sitter runtime if the dependency policy changes. A regex adapter can be
vendored as stdlib-only code, but references remain heuristic and must be
labelled as such.

**Structural north star:** These are representative target queries to drive
the adapter test corpus, not claims that a regex can reproduce a parser:

```scheme
; Python
(function_definition name: (identifier) @definition.function)
(class_definition name: (identifier) @definition.class)
(call function: (identifier) @call)

; Rust
(function_item name: (identifier) @definition.function)
(struct_item name: (type_identifier) @definition.struct)
(call_expression function: (identifier) @call)

; Go
(function_declaration name: (identifier) @definition.function)
(method_declaration name: (field_identifier) @definition.method)
(call_expression function: (identifier) @call)
```

**Recommendation:** Add Tier-2 regex adapters for JS/TS/Java/C/C++ only after
each has fixtures for definitions, calls, comments, strings, multiline forms,
and false positives. Report `SYMBOL_REFERENCE` as heuristic until a parser
back-end exists. Keep Python AST as the Tier-1 semantic adapter.

### 7. Whole-file `must` mode

**Status:** Existing adapter matching intersects predicates on the same line,
which is precise for line-local evidence but cannot express a definition on one
line and a call or import elsewhere in the file.

**Proven source:** Leitir `src/leitir/adapters.py` `find_matches` and candidate
line intersection; Leitir `src/leitir/search.py` predicate contract. License:
Leitir project license.

**Copy/adapt feasibility:** Small model change. Evaluate each required
predicate over a file-level result set, while retaining matched source spans
for evidence. Do not broaden existing line-local predicate semantics without
an explicit mode.

**Recommendation:** Add an explicit whole-file `must` mode in Phase 1. A file
passes when every `must` predicate has at least one verified match anywhere in
the blob; output all deterministic evidence spans, sorted by line and kind.
Coverage and provenance rules remain unchanged.

### 8. Recover truncated recursive trees

**Status:** GitHub recursive trees can be truncated at 100,000 entries or 7 MB.
Leitir currently raises `TreeTruncatedError` and aborts scoped enumeration.

**Proven sources:**

- `go-git/go-git`, Apache-2.0, `plumbing/object/tree.go`: stack-based
  `TreeWalker` traversal over tree objects.
- `isomorphic-git/isomorphic-git`, MIT, `src/commands/walk.js`: explicit walk
  expansion and callback-driven traversal.
- GitHub REST Git trees documentation: recursive responses may be truncated;
  non-recursive tree requests return entries and subtree SHAs.

**Copy/adapt feasibility:** The traversal algorithm is straightforward to
  reimplement in Python stdlib. Do not copy Go or JavaScript runtime code.
Use the existing HTTP/retry and validation facilities.

**Recommendation:** On truncation, fetch `/git/trees/{sha}` without
`recursive=1`, expand subtrees by SHA, sort entries by path, maintain a visited
set, and enforce explicit depth, request, and entry budgets. A cycle or budget
exhaustion is a failed/partial enumeration, not success.

Minimal sketch:

```python
pending = [(root_sha, "", 0)]
visited: set[str] = set()
blobs: list[BlobEntry] = []
while pending:
    tree_sha, prefix, depth = pending.pop()
    if tree_sha in visited or depth > max_depth or len(blobs) > max_entries:
        raise TreeWalkBudgetError("tree walk incomplete")
    visited.add(tree_sha)
    entries = fetch_tree(tree_sha, recursive=False)
    for entry in sorted(entries, key=lambda item: item.path):
        path = f"{prefix}/{entry.path}".lstrip("/")
        if entry.type == "blob":
            blobs.append(BlobEntry(path, entry.sha, entry.size, entry.mode))
        elif entry.type == "tree":
            pending.append((entry.sha, path, depth + 1))
return tuple(sorted(blobs, key=lambda item: item.path))
```

The production implementation must count requests and discovered entries,
validate SHAs/types/sizes, and preserve deterministic ordering. It should
record whether the result came from recursive or recovered enumeration.

## Larger: Wide Search and Large Blobs

### 9. A new GitHub code-search API: not viable

**Status:** Blocked by the public API surface, not by Leitir engineering.

**Proven sources:** GitHub REST search documentation (`GET /search/code`),
GitHub GraphQL search reference, and `cli/cli` MIT source
`pkg/cmd/search/code/code.go`. The CLI source explicitly says the API code
search is legacy and regex is not yet available through the API.

**Copy/adapt feasibility:** There is no public Blackbird result API to adapt.
The web URL opened by `gh search code --web` is an interactive product
surface, not a stable authenticated data contract. GraphQL's `codeCount` is
not a code-result connection.

**Recommendation:** Defer this item. Keep rejecting global `REGEX`,
`symbol:`, and other syntax that the REST contract cannot guarantee. Revisit
only after GitHub publishes a documented endpoint with result schema,
pagination, permissions, rate limits, and stability guarantees. The practical
replacement is item 9-prime.

### 9-prime. Local Zoekt-style trigram index

**Status:** Proposed; this is the actual wide-search investment.

**Proven sources:**

- `sourcegraph/zoekt`, Apache-2.0: `index/builder.go` for index construction,
  `index/eval.go` for regex-to-n-gram planning, `index/score.go` for ranking,
  and `index/matchtree.go` for match aggregation.
- `hound-search/hound`, MIT: simpler code-search index/reference implementation.
- Russ Cox, “Regular Expression Matching with a Trigram Index”: the classic
  candidate-filtering method.
- GitHub's Blackbird engineering article: n-gram indices, sorted posting
  lists, lazy iterators, regex candidate verification, and ranking. This
  validates the shape, not an implementation-license grant from GitHub.

**Copy/adapt feasibility:** A minimal immutable local index is feasible in
stdlib Python. Zoekt is Apache-2.0 and can be adapted with NOTICE/license
compliance; Hound is MIT. Do not copy Blackbird code or imply access to its
private implementation. Start with a simple on-disk format and optimize only
after measurements.

**Recommendation:** Index the verified materialized corpus cache by stable
document identity. Store `gram -> sorted doc IDs`, metadata, and enough source
location information to fetch or verify content. Query planning extracts
literal runs from a regex, chooses useful trigrams, intersects posting lists,
then performs full-regex verification on candidates. Regexes with no useful
literal grams fall back to a bounded scan and report the cost/coverage state.

Minimal sketch:

```python
postings: dict[str, list[int]] = {}
for doc_id, text in enumerate(sorted_documents):
    grams = {text[i:i + 3] for i in range(len(text) - 2)}
    for gram in sorted(grams):
        postings.setdefault(gram, []).append(doc_id)

def search(pattern: re.Pattern[str]) -> list[Document]:
    literals = extract_literal_runs(pattern.pattern)
    grams = sorted({run[i:i + 3] for run in literals for i in range(len(run) - 2)})
    candidates = intersect_sorted(postings[g] for g in grams) if grams else all_doc_ids()
    verified = [doc for doc in candidates if pattern.search(read_text(doc))]
    return sorted(verified, key=rank)
```

Ranking signals should be explicit and deterministic: path, basename, symbol
match, word boundary, and match quality should help; generated, vendor, and
test paths should incur configurable penalties. Ranking must never remove
matches or turn an incomplete candidate scan into a complete claim. Later
versions can use compressed postings, lazy iterators, sparse/dynamic grams,
blob deduplication, and incremental rebuilds.

### 10. Stream blobs larger than 2 MiB

**Status:** Current scoped search skips blobs over 2 MiB. GitHub raw blobs can
be up to 100 MB through the Git Blobs API, so the current cutoff is a Leitir
policy, not a universal Git limitation.

**Proven sources:** `BurntSushi/ripgrep`, MIT/Unlicense,
`crates/searcher/src/searcher/core.rs`: incremental reader/searcher mechanics.
GitHub Git Blobs API documentation: raw blob size limits and response
behavior. License: ripgrep permits adaptation subject to its dual licensing
and attribution terms.

**Copy/adapt feasibility:** The reader loop is portable, but Python's `re`
engine is not a streaming regex engine. Use byte/text chunks with overlap,
and define bounded behavior for pathological patterns and very long lines.
Keep a maximum response/body budget and make incompleteness explicit.

**Recommendation:** Stream raw content with `urllib`, decode incrementally,
and retain an overlap window at least as large as the maximum supported
cross-chunk match width. For line-oriented predicates, scan bounded lines. For
regexes that can span arbitrary input, either use the local index or reject
the streaming mode as unsupported rather than pretending it is exhaustive.

Sketch:

```python
decoder = codecs.getincrementaldecoder("utf-8")(errors="replace")
carry = ""
line_no = 1
for chunk in response:
    text = decoder.decode(chunk)
    window = carry + text
    for match in pattern.finditer(window):
        emit_span(line_no + window.count("\n", 0, match.start()), match)
    carry = window[-overlap_width:]
    line_no += max(0, window.count("\n") - carry.count("\n"))
tail = decoder.decode(b"", final=True)
if tail:
    verify_window(carry + tail)
```

The real implementation must avoid duplicate boundary matches, cap
very-long lines, verify blob identity where the transport permits it, and
record `incomplete=True` for truncation, decode uncertainty, unsupported
unbounded patterns, or budget exhaustion. A streamed file can improve recall
without changing the honest coverage status.

## Cross-Cutting Data Model

Use `scip-code/scip`, Apache-2.0, as a language-neutral model reference:
`Symbol`, `Occurrence`, `SymbolRole`, and `enclosing_range`. Adapt the model,
not the protobuf dependency. Leitir can represent the useful subset as typed
stdlib dataclasses:

- `Symbol`: stable local ID, display name, kind, language, definition range.
- `Occurrence`: symbol ID when resolved, role (definition/reference/call),
  source range, and enclosing symbol/range.
- `Document`: slug, commit, path, blob SHA, language, generated/vendor/test
  classification, and completeness flags.

Preserve immutable `(slug, commit, path, blob_sha)` identity and source ranges;
represent unresolved names explicitly. Regex and AST adapters can then share
plumbing without claiming equal depth.

## License Matrix

Before distribution, record exact upstream versions, retain notices, and review
transitive files.

| Project | License | Use in Leitir | Handling |
|---|---|---|---|
| sourcegraph/zoekt | Apache-2.0 | Index/query mechanics | OK to vendor/adapt with NOTICE |
| hound-search/hound | MIT | Simpler index reference | OK to vendor/adapt with notice |
| BurntSushi/ripgrep | MIT/Unlicense | Incremental reader mechanics | OK to adapt; retain applicable notices |
| go-git/go-git | Apache-2.0 | Tree walker model | OK to adapt with NOTICE |
| isomorphic-git/isomorphic-git | MIT | Tree walk model | OK to adapt with notice |
| tree-sitter runtime/grammars | MIT | Parser/query model | OK to vendor/adapt per repository notices |
| ast-grep/ast-grep | MIT | Structural matching concepts | OK to adapt with notice |
| mkdocstrings/griffe | ISC | Python extraction mechanics | OK to adapt with notice |
| davidhalter/jedi | MIT | Scope/reference algorithm | Algorithm reference; do not vendor Parso casually |
| scip-code/scip | Apache-2.0 | Symbol/occurrence model | OK to adapt; protobuf not required |
| cli/cli | MIT | API/client boundary evidence | OK to inspect/adapt client concepts |
| livegrep | BSD-2-Clause | Search reference | Reference-only; review obligations |
| OpenGrok | CDDL | Search/reference behavior | Reference-only; legal review |
| nvim-treesitter queries | See repository files | Structural pattern inventory | Adapt patterns; do not copy blindly |
| Semgrep | LGPL-2.1 | Structural search | Do not vendor |
| Universal-ctags | GPL-2.0 | Symbol extraction | Do not vendor |
| PyGithub | LGPL-3.0 | GitHub client | Do not vendor |
| pygit2/libgit2 | GPL-2.0 | Git object access | Do not vendor |
| searchcode-server | AGPL-3.0 | Search server | Do not vendor |

The project's stdlib-only runtime rule remains decisive even for permissively
licensed projects: license compatibility does not make a dependency desirable
or permitted. Prefer algorithm and data-model adaptation over copied runtime
code.

## Phased Roadmap

### Phase 0: now, S

1. Expose `--max-results`, `--max-pages`, and `--language`.
2. Strengthen `validate_report` to the full provenance tuple and add tamper
   tests.
3. Enforce predicate language routing in adapters.
4. Add the gated search live canary.

Success means observable budgets, stronger validation, explicit language
behavior, and a repeatable smoke; global search remains indeterminate.

### Phase 1: deep, M

1. Implement the Python `ast` + `symtable` adapter with two-pass scope/def/ref
   extraction.
2. Add JS/TS/Java/C/C++ Tier-2 regex adapters derived from tree-sitter query
   inventories, with heuristic reference labels.
3. Add explicit whole-file `must` mode.

Gate on fixture precision/recall, deterministic ordering, malformed-source
behavior, and no false complete coverage after parser failure.

### Phase 2: robustness, M

1. Replace truncated recursive-tree aborts with bounded non-recursive
   expansion.
2. Stream large blobs with overlap-aware matching and incompleteness records.
3. Introduce the SCIP-shaped symbol/occurrence model.

Gate on nested subtrees, repeated SHAs, budget exhaustion, boundary matches,
huge lines, and blob/provenance checks.

### Phase 3: wide, L

Build the local Zoekt-style trigram index over the verified corpus cache, then
add deterministic ranking. Measure index build time, disk size, candidate
reduction, regex verification cost, and recall against exhaustive scans. This
is the phase that delivers useful wide search without pretending GitHub's API
is Blackbird.

### Deferred / blocked

Defer improvement 9, the hypothetical new GitHub code-search API. Reconsider
only if GitHub ships a public advanced-code-search endpoint with documented
results, pagination, permissions, rate limits, and stability guarantees.

## References

### GitHub API and client evidence

- [REST search documentation](https://docs.github.com/en/rest/search/search)
- [REST Search code endpoint](https://docs.github.com/en/rest/search/search#search-code)
- [GraphQL Search query reference](https://docs.github.com/en/graphql/reference/queries#search)
- [GraphQL SearchType reference](https://docs.github.com/en/graphql/reference/enums#searchtype)
- [`cli/cli` code search command](https://github.com/cli/cli/blob/trunk/pkg/cmd/search/code/code.go)

### Indexing and matching

- [`sourcegraph/zoekt`](https://github.com/sourcegraph/zoekt)
- [`hound-search/hound`](https://github.com/hound-search/hound)
- [Russ Cox: Regular Expression Matching with a Trigram Index](https://swtch.com/~rsc/regexp/regexp4.html)
- [The technology behind GitHub's new code search](https://github.blog/engineering/architecture-optimization/the-technology-behind-githubs-new-code-search/)

### Parsing, walking, and streaming

- [`mkdocstrings/griffe`](https://github.com/mkdocstrings/griffe)
- [`davidhalter/jedi`](https://github.com/davidhalter/jedi)
- [`tree-sitter/tree-sitter`](https://github.com/tree-sitter/tree-sitter)
- [`nvim-treesitter/nvim-treesitter` queries](https://github.com/nvim-treesitter/nvim-treesitter/tree/master/queries)
- [`ast-grep/ast-grep`](https://github.com/ast-grep/ast-grep)
- [`go-git/go-git` tree walker](https://github.com/go-git/go-git/blob/master/plumbing/object/tree.go)
- [`isomorphic-git/isomorphic-git` walk](https://github.com/isomorphic-git/isomorphic-git/blob/main/src/commands/walk.js)
- [`BurntSushi/ripgrep` searcher core](https://github.com/BurntSushi/ripgrep/blob/master/crates/searcher/src/searcher/core.rs)
- [GitHub Git Blobs API](https://docs.github.com/en/rest/git/blobs)
- [`scip-code/scip`](https://github.com/sourcegraph/scip)
