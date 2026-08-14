# Search v2 Issue Bodies

The following bodies are ready to paste into GitHub issues. They intentionally
repeat the acceptance and safety contracts so each slice can be implemented and
reviewed independently.

```text
S2a: Validate the complete global provenance tuple

## Summary
Strengthen `validate_report` to authorize the complete `(slug, commit, path, blob)` tuple, not only repository and commit.

## Why it matters
`docs/search-capabilities.md:137-142` records that report validation is weaker than the fetch-time verification. A matching repository and commit must not authorize a different path or blob claim.

## Real-world acceptance criteria
- [ ] Accepted identities are exact `(slug, commit_sha, path, blob_sha)` tuples.
- [ ] All existing valid reports remain valid.
- [ ] Four tamper tests reject changed slug, commit, path, and blob.
- [ ] Existing byte-level Git blob verification remains in place.

## Sad paths (must reject)
- [ ] Matching only slug and commit.
- [ ] A path changed to another path in the same commit.
- [ ] A blob SHA changed while path and commit remain unchanged.
- [ ] Missing or malformed provenance fields.

## Test-driven requirements
- [ ] Add table-driven offline validator tests and the four tuple-component tamper/reject tests.
- [ ] Assert no accepted source escapes the verified tuple set.
- [ ] Run under `PYTHONHASHSEED=0`, `1`, and `42`.

## Engineering workflow gates
- [ ] No new dependency; suite remains >= current 2279 passed, 0 failed.
- [ ] `ruff`, `mypy`, scorecard decision `pass`.
- [ ] Independent hy3 and deepseek security/integrity review.

## Dependencies
Blocked by: none. Blocks: index provenance and all later report consumers.

## References
`src/leitir/discovery_search.py:609-624,633-648`; `src/leitir/search.py:254-264`; S8.

```

```text
S1: Expose global search budgets and language

## Summary
Add global-only `--max-results`, `--max-pages`, and `--language`; route language into `Predicate.language` and declare the `global_searcher_factory` seam change from two arguments to the new argument set.

## Why it matters
The internal global searcher already has budgets, but callers cannot control them. Language intent must become part of the immutable search spec and digest.

## Real-world acceptance criteria
- [ ] Flags validate positive bounded budgets and are accepted only by global search.
- [ ] `--language` creates the canonical `Predicate.language` value.
- [ ] The two-argument `global_searcher_factory` seam is updated, including call sites `test_cli.py:343,388` and `test_global_e2e.py:107,224`.
- [ ] Scoped search rejects or ignores no global-only cap silently; document the contract.

## Sad paths (must reject)
- [ ] Zero, negative, malformed, or over-limit budgets.
- [ ] `--language` with a conflicting required language.
- [ ] Passing scoped caps as if scoped completeness were preserved.

## Test-driven requirements
- [ ] CLI parser and factory call-site tests cover defaults, validation, and propagation.
- [ ] Assert language is present in the resulting spec digest.
- [ ] Run multi-seed determinism probes.

## Engineering workflow gates
- [ ] Suite >= current 2279 passed, ruff clean, mypy clean, scorecard `pass`.
- [ ] Live checks remain behind `LEITIR_ENABLE_LIVE_E2E=1`; ASV not required.

## Dependencies
Blocked by: none. Blocks: S2b documentation alignment.

## References
`src/leitir/discovery_search.py:431-497`; `src/leitir/cli.py:313-364,1740-1784`; `docs/search-capabilities.md:58-79`.

```

```text
S0: Introduce the deterministic adapter registry

## Summary
Create `src/leitir/adapters/registry.py::build_adapters(...) -> tuple[LanguageAdapter, ...]`, package adapters, and retain `adapters.py` as a compatibility re-export shim.

## Why it matters
Python AST and Python regex must coexist with first-eligible routing. A mutable dictionary or unordered collection makes adapter choice and results unstable.

## Real-world acceptance criteria
- [ ] Registry returns an explicitly ordered tuple.
- [ ] Existing Python, Rust, and Go behavior is unchanged.
- [ ] CLI construction at `src/leitir/cli.py:480-488,513` uses the registry.
- [ ] Existing imports through `src/leitir/adapters.py` continue through the shim.

## Sad paths (must reject)
- [ ] Duplicate language registrations or ambiguous first eligibility.
- [ ] Unsorted set/dict iteration determining adapter order.
- [ ] Unknown language being silently routed to a different adapter.

## Test-driven requirements
- [ ] Assert exact adapter tuple order and first-eligible behavior.
- [ ] Run the existing adapter fixture suite under multiple hash seeds.

## Engineering workflow gates
- [ ] Zero behavior change; suite >= current 2279 passed, ruff, mypy, scorecard `pass`.

## Dependencies
Blocked by: none. Blocks: S2b, S-wholefile, S5, S6, S8.

## References
`src/leitir/cli.py:480-488,513`; `src/leitir/apisurface.py:305-331`; `docs/search-capabilities.md:209-239`.

```

```text
S3: Repair and extend the live search canary

## Summary
Enable the existing nightly workflow, stop swallowing failures, and add canaries for tree recovery, streamed large blobs, and index-vs-scan recall.

## Why it matters
The canary already exists but is currently not scheduled and `continue-on-error` hides regressions. Live service failures must be classified as infrastructure failures, not production success.

## Real-world acceptance criteria
- [ ] Uncomment/enable the nightly schedule at `.github/workflows/live-canary.yml:13-14`.
- [ ] Canary failures fail the job and are visible in workflow output.
- [ ] Add pinned public-repository canaries for truncated-tree recovery, >2 MiB streaming, and index-vs-exhaustive-scan recall as surfaces land.
- [ ] Rate limit and timeout are labeled infrastructure failures.

## Sad paths (must reject)
- [ ] `continue-on-error` masking a failed assertion.
- [ ] Rate-limit/timeout treated as a passing product result.
- [ ] Live canary used to weaken offline fail-closed behavior.

## Test-driven requirements
- [ ] Offline classification tests use deterministic fake transport.
- [ ] Live tests stay gated by `LEITIR_ENABLE_LIVE_E2E=1` and assert provenance/coverage, not brittle rank positions.
- [ ] Multi-seed offline outputs are identical.

## Engineering workflow gates
- [ ] Suite >= current 1917, ruff, mypy, scorecard `pass`; no ASV requirement.

## Dependencies
Blocked by: none. Extends: S7, S9, S8 when those slices land.

## References
`.github/workflows/live-canary.yml:13-14,45-52`; `docs/research/search-upgrade-research.md:101-117`.

```

```text
S2b: Enforce predicate language routing

## Summary
Route `Predicate.language` explicitly through the ordered registry, reject conflicting required languages in `SearchSpec.__post_init__`, and settle coverage-denominator semantics.

## Why it matters
Current adapter selection is extension-based while `pred.language` is not independently enforced. A requested language must not become an unrelated successful search.

## Real-world acceptance criteria
- [ ] Canonicalize aliases using `apisurface.py:312-321` only.
- [ ] Conflicting languages among `must` predicates reject in global and scoped modes.
- [ ] Adapter routing requires canonical language plus extension eligibility.
- [ ] Document and test the chosen denominator: either shrink eligible files or count excluded files and report `PARTIAL`.

## Sad paths (must reject)
- [ ] Conflicting required languages accepted as an empty success.
- [ ] Unknown aliases guessed or silently mapped.
- [ ] A path extension overriding an explicit incompatible language.

## Test-driven requirements
- [ ] Alias, conflict, unknown, global, and scoped tests.
- [ ] Coverage tests prove the denominator decision and partial status.
- [ ] Multi-seed deterministic routing tests.

## Engineering workflow gates
- [ ] Suite >= current 1917, ruff, mypy, scorecard `pass`.

## Dependencies
Blocked by: S0. Updates: `docs/search-capabilities.md`.

## References
`src/leitir/search.py:207-223,231-251`; `src/leitir/apisurface.py:312-321`; `src/leitir/engine.py:189-199,241-245`.

```

```text
S-wholefile: Add explicit whole-file must semantics

## Summary
Add `whole_file` to `SearchSpec`, adapter matching, engine execution, CLI, digest canonicalization, and coverage documentation.

## Why it matters
The current `must` intersection is line-local at `engine.py:61,93`; it cannot express a definition and call/import occurring on different lines.

## Real-world acceptance criteria
- [ ] `whole_file: bool = False` is keyword-safe and included in `_canonical()`.
- [ ] `find_matches(..., *, whole_file=False)` preserves current default behavior.
- [ ] Whole-file mode requires every `must` predicate somewhere in the blob and emits sorted evidence spans.
- [ ] CLI flag, digest, coverage, `should`, and `must_not` semantics are documented.

## Sad paths (must reject)
- [ ] Positional-only or undocumented whole-file behavior changing existing callers.
- [ ] One missing required predicate treated as a match.
- [ ] Whole-file partial evidence reported complete.

## Test-driven requirements
- [ ] Same-line regression fixtures and cross-line positive/negative fixtures.
- [ ] Digest differs only when `whole_file` differs.
- [ ] Multi-seed span order tests.

## Engineering workflow gates
- [ ] Suite >= current 1917, ruff, mypy, scorecard `pass`.

## Dependencies
Blocked by: S0. Blocks: S5.

## References
`src/leitir/search.py:225-251`; `src/leitir/engine.py:50-63,78-113`; `docs/search-upgrade-research.md:199-217`.

```

```text
S7: Recover from truncated Git trees safely

## Summary
Add `list_blobs_ex()` with recovery metadata, bounded non-recursive subtree expansion, sibling error taxonomy, and partial scoped handling.

## Why it matters
`tree.py:127-128` currently raises on truncation and `engine.py:140` aborts the search. A truncated response is not proof that no remaining files exist.

## Real-world acceptance criteria
- [ ] `list_blobs_ex()` returns `(tuple[BlobEntry, ...], was_recovered)`; `list_blobs()` remains the raising wrapper.
- [ ] Recovery requests non-recursive trees by SHA, tracks visited SHAs, validates entries, enforces depth/request/entry budgets, and sorts paths.
- [ ] `TreeEnumerationError` is the base; `TreeWalkBudgetError` is a sibling of `TreeTruncatedError`.
- [ ] Scoped search catches enumeration failures and reports `PARTIAL`, never complete.

## Sad paths (must reject)
- [ ] Cycle, malformed SHA/type, or budget exhaustion reported complete.
- [ ] Recursive truncation silently discarded.
- [ ] `TreeWalkBudgetError` caught as a truncation-specific success path.

## Test-driven requirements
- [ ] Fixtures for nested recovery, repeated SHAs, cycles, depth/request/entry budgets, malformed entries, and deterministic ordering.
- [ ] Assert truncation and budget errors produce partial coverage.
- [ ] Run multi-seed tests.

## Engineering workflow gates
- [ ] Suite >= current 1917, ruff, mypy, scorecard `pass`.
- [ ] Independent hy3 and deepseek integrity review.

## Dependencies
Blocked by: none. Enables: S3 recovery canary. S8 may consume recovered shelves.

## References
`src/leitir/tree.py:123-142`; `src/leitir/engine.py:129-162`; `docs/research/search-upgrade-research.md:219-265`.

```

```text
S5: Add Python AST search adapter

## Summary
Reuse the stdlib AST extraction, add lexical occurrence semantics, expose `--ast`, retain regex fallback on `SyntaxError`, and gate any default flip.

## Why it matters
Current scoped matching is heuristic. The existing AST implementation at `apisurface.py:144-221` provides reusable parsing and signature mechanics without adding dependencies.

## Real-world acceptance criteria
- [ ] Definitions map FunctionDef/AsyncFunctionDef/ClassDef/Assign/AnnAssign/import nodes; refs use loaded Names and lexical symtable resolution; calls, signatures, and imports map structurally.
- [ ] Spans use a pinned multi-line policy and `method="ast"`; regex fallback is `method="heuristic"`.
- [ ] SyntaxError emits parser-unavailable/partial, never false-complete.
- [ ] Duplicate spans are deduped before ranking; default flip requires `BenchmarkRun.digest()` equality and multi-seed determinism.

## Sad paths (must reject)
- [ ] Dynamic/unresolved names invented as resolved targets.
- [ ] Parser failure reported complete.
- [ ] Duplicate `SourceRef` identities passed to `order_source_matches`.
- [ ] AST default flipped based on ASV alone.

## Test-driven requirements
- [ ] Fixtures for nested scopes, async functions, classes, assignments, imports, calls, args/returns, unresolved names, syntax errors, and multiline spans.
- [ ] Recall/precision and benchmark digest comparisons against the pinned baseline.
- [ ] Multi-seed tests and AST-vs-regex fallback coverage.

## Engineering workflow gates
- [ ] Suite >= current 1917, ruff, mypy, scorecard `pass`.
- [ ] ASV measurements plus independent hy3/deepseek review for semantic/integrity changes.

## Dependencies
Blocked by: S0, S-wholefile. Blocks: S9 and S8 adapter-universe stability.

## References
`src/leitir/apisurface.py:144-221`; `src/leitir/ranking.py:71-73`; `src/leitir/bench.py:238-240`; D1, D10.

```

```text
S6: Add Tier-2 language adapters

## Summary
Add independently tested heuristic adapters for JavaScript, TypeScript, Java, C, and C++, reconciled with existing JS/TS regexes.

## Why it matters
Deep coverage currently centers on Python, Rust, and Go. Regex can widen language coverage, but it cannot honestly claim parser-grade references.

## Real-world acceptance criteria
- [ ] Each language has a separate adapter and canonical language routing.
- [ ] Fixtures cover definitions, calls, comments, strings, multiline declarations, and false positives.
- [ ] References are labeled `method="heuristic"`.
- [ ] `bench.py:26` `_LANGUAGES` is widened and `leitir-benchmark-manifest-v1` plus scorecard `output.pinned_benchmark` are updated.

## Sad paths (must reject)
- [ ] Comment/string text reported as a symbol without fixture evidence.
- [ ] Heuristic references labeled AST or semantic.
- [ ] New languages silently omitted from the benchmark universe.

## Test-driven requirements
- [ ] Split per-language fixture tests with negative cases and deterministic ordering.
- [ ] Benchmark has at least four tasks per language and updated digest.
- [ ] Multi-seed tests; no parser dependency added.

## Engineering workflow gates
- [ ] Suite >= current 1917, ruff, mypy, scorecard `pass`; ASV where benchmark surface changes.

## Dependencies
Blocked by: S0. Blocks: S9 and S8 stable adapter universe.

## References
`src/leitir/apisurface.py:53-71,229-289`; `src/leitir/bench.py:26,54-59,126-137`; research `:154-197`.

```

```text
S9: Stream and fully verify blobs over 2 MiB

## Summary
Implement `read_blob_stream(slug, blob_sha)` over the raw Git Blobs API with bounded overlap matching and incremental Git blob SHA-1 verification.

## Why it matters
`engine.py:205-209` currently skips files over 2 MiB. Streaming improves recall without weakening identity or coverage claims.

## Real-world acceptance criteria
- [ ] Use token-gated `/git/blobs/{sha}` and `Accept: application/vnd.github.raw`.
- [ ] Hash `b"blob %d\\0" % size` plus every received byte incrementally and accept spans only on exact SHA match.
- [ ] Deduplicate boundary matches and scope retries per attempt.
- [ ] `incomplete=True` only for actual truncation, unsupported/unbounded patterns, or budget exhaustion.

## Sad paths (must reject)
- [ ] Path+commit-only downgrade without blob digest verification.
- [ ] Truncated or mismatched stream accepted as complete.
- [ ] Duplicate boundary spans returned.
- [ ] Arbitrary long-line/unbounded regex behavior pretending exhaustive coverage.

## Test-driven requirements
- [ ] Chunk-boundary matches, multibyte decoding, empty blobs, large blobs, retry attempts, truncation, and SHA mismatch tests.
- [ ] Tamper/reject tests for changed bytes and declared blob SHA.
- [ ] Multi-seed span order tests and >2 MiB live canary fixture.

## Engineering workflow gates
- [ ] Suite >= current 1917, ruff, mypy, scorecard `pass`.
- [ ] Independent hy3/deepseek security review; ASV where memory/performance is measured.

## Dependencies
Blocked by: S5 and S6 adapter contracts; S2a is required for provenance consumers. Enables: S8.

## References
`src/leitir/tree.py:144-161,188-214`; `src/leitir/engine.py:205-216`; research `:342-387`; D4.

```

```text
S8: Build the local trigram index and indexed searcher

## Summary
Implement per-shelf trigram build/query/verify storage, lock-held manifest verification, strict eligibility, fallback, dedupe, explicit index CLI, and operational documentation.

## Why it matters
This is the wide-search replacement for the unavailable advanced GitHub API. The primary risk is false-complete results from registry artifacts, sampled hashes, drift, stale manifests, or a concurrent shelf mutation.

## Real-world acceptance criteria
- [ ] Add `index/{builder,postings,query,rank,verify}.py` and `IndexedSearcher` with the existing `search(spec) -> SearchReport` shape.
- [ ] Store per-shelf artifacts under `.search-index/<host>/<owner>/<repo>/<commit>/` plus a top-level manifest with own `schema_version`; refuse unknown versions.
- [ ] Hold `_target_lock` across `read_valid_manifest` verification and all dependent reads.
- [ ] Serve scoped index only when `source=git-commit`, `parity=exact`, and `materialized_tree_hash_scope=full`; otherwise fallback and report `PARTIAL`.
- [ ] Add explicit `leitir index` and fail-closed `--require-index`; no lazy read build.
- [ ] Dedupe index/fallback spans before `order_source_matches`.
- [ ] Document export/import exclusion, gc behavior, and doctor staleness reporting.

## Sad paths (must reject)
- [ ] Trusting a stored hash without re-verification under the target lock.
- [ ] Serving registry-artifact, sampled, drift, unknown, stale, or malformed shelves as complete.
- [ ] Unknown schema accepted or index silently rebuilt during a read.
- [ ] Duplicate merged identities reaching ranking.
- [ ] Trigram candidate omission or no-useful-gram fallback reported complete without exhaustive verification.

## Test-driven requirements
- [ ] Tamper/reject tests for manifest identity, source, parity, hash scope, index bytes, schema, stale shelf, and concurrent build/read.
- [ ] Recall equality against exhaustive scan for supported bounded regexes; candidate reduction and deterministic ranking tests.
- [ ] Fallback/partial coverage tests and `--require-index` failure tests.
- [ ] Export/import, gc, and doctor lifecycle tests; multi-seed tests.

## Engineering workflow gates
- [ ] Suite >= current 1917, ruff, mypy, scorecard `pass`.
- [ ] Independent hy3/deepseek security/integrity review and ASV measurements for build/query costs.
- [ ] Add versioning/operations docs and ADR-0006-compatible lock rationale.

## Dependencies
Blocked by: S9, S5, S6, and S2a. Depends on verified-read primitive. Final slice.

## References
`src/leitir/materialize.py:173-202,405,487-513`; `src/leitir/treehash.py:100-103,197-222`; `src/leitir/ranking.py:71-73`; `src/leitir/search.py:225-251`; research `:289-340`; D2, D3, D9, D10.

```
