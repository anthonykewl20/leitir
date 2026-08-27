# Warm process mode (#272): verified premise report

**Date:** 2026-08-27 · **Scope:** measurement and code-path verification only —
no production code changed. This is the evidence base for
[ADR-0035](../adr/0035-warm-process-invalidation-contract.md).

## Method

Measured against a real, previously-materialized corpus at `~/.leitir`
(`LEITIR_HOME`): 160 entries in `sources.json`, 119 shelves actually present
under `repos/github.com/**` (the rest are index/pointer/registry-artifact
entries or shelves removed since indexing). This is the same order of
magnitude as the 131-shelf corpus the dogfood report (`docs/evidence/dogfood-2026-08-15.md`)
and the issue cite, so it is a realistic stand-in, not a synthetic fixture.

Commands were run with `PYTHONPATH=src`, unmodified `main`-equivalent code
(the current worktree, no changes made), `python3.14.6`. Timing via `time`;
call-graph attribution via `python -m cProfile -o out.prof -m leitir.cli ...`
read back with `pstats`. Two runs of each timed command are reported (cold OS
page cache vs. warm) since shelf bytes must be read from disk either way.

## Finding 1 — interpreter startup and import are not the dominant cost

```
bare `python3 -c "pass"`:                    ~0.01s
`PYTHONPATH=src python3 -c "import leitir.cli"`: 0.07-0.11s
```

Interpreter startup plus importing the full CLI module graph is on the order
of **100ms**. This is the cost the issue's title ("cold Python start") most
naturally suggests warm mode should eliminate. It turns out to be a rounding
error next to the real cost below — **two to three orders of magnitude**
smaller.

## Finding 2 — the dominant cost is corpus-wide manifest re-verification, and it is not limited to `search --corpus`

This is the load-bearing correction to the issue's framing.

Profiling a single `leitir info <one-shelf-spec> --brief` call (a command
that resolves exactly **one** shelf) shows:

```
223,057,870 function calls in 97.373 seconds total
  cli.py:_run_corpus_command                          97.278s cumulative
    corpus.py:find_materialized_sources                96.534s cumulative
      corpus.py:enumerate_shelved_sources               (scans ALL 163 catalog entries)
        materialize.py:read_valid_manifest  (x163 calls) 96.702s cumulative
          materialize.py:verify_materialized_integrity   96.568s cumulative
            treehash.py:_scan_entries / _sorted_regular_files / verify_file_digest_map
              -> full per-file SHA-256 re-hash of every regular file in every shelf
```

`read_valid_manifest` was called **163 times** — once per catalog entry, not
once for the one shelf the `info` spec actually names. `find_materialized_sources`
(used by `info`, `get`, `api`, `examples`, `trust`, and every other
spec-resolving command) calls `enumerate_shelved_sources`, which fully
load-time-verifies **every shelved source in the corpus** before filtering
down to the one(s) matching the spec. This is necessary today because spec
resolution must disambiguate against the whole catalog (bare package names,
ecosystem tags without an explicit host, ambiguous refs) and
`enumerate_shelved_sources` is the only code path that produces a
manifest-validated view of the catalog to filter.

Wall-clock for that single-shelf `info --brief` call: **97s under profiling
overhead, 39.2s unprofiled** (page cache warm from the profiling run
immediately before it). A second, fully independent `search --corpus`
invocation (must:identifier, no filters) measured **81.5s cold** and **40.3s
with a warm OS page cache** — i.e., in this corpus, a single-shelf `info`
call and a full-corpus `search --corpus` call cost about the same, because
both pay the same full-catalog verification pass; `search --corpus` merely
also uses (a subset of) the same shelves for actual predicate evaluation
afterward.

**Correction to the issue's framing:** the issue states "`search --corpus`
fans out across every eligible shelf." That is true, but it undersells the
problem — the same full-catalog re-verification happens on *any* command
that resolves a spec (`info`, `get`, `api`, `examples`, `trust`, `diff`, ...),
including ones that only touch a single shelf's output. The cost is not
proportional to what the command reads; it is proportional to **corpus size**,
because spec resolution scans the whole catalog before selecting.

This has a direct implication for warm-mode design (see ADR-0035): caching
verified state per-scope-touched-by-search is not sufficient — the
catalog-wide `enumerate_shelved_sources` result itself is the thing that must
become a re-verify-on-demand, invalidation-tracked structure, or every
single-shelf command pays full-corpus cost regardless of what warm mode does
for search specifically.

This finding is bigger than #272 on its own and is filed separately as
**[issue #279](https://github.com/anthonykewl20/leitir/issues/279)**: doing
O(catalog) verification work to resolve a single-shelf spec is a cold-path
performance defect today, independent of any warm process. It directly
contradicts ADR-0031's advisory-lane premise and #266 A2's `info --brief`
recommendation, both of which sell `info`/`search`/`ask`/`examples`/`api` as
cheap, frequently-callable verbs — the token cost of `info --brief` was
measured and reduced (56%, #266 A2), but its latency was never measured
until this report, and it turns out to scale with corpus size, not with
work actually done. Fixing #279 is a prerequisite for the advisory lane's
premise being true; it is not a substitute for the warm-mode session cache
ADR-0035 decides, since even a corrected single-call resolution still repeats
per-call verification of the *same* shelf across a multi-call session.

## Finding 3 — hot-function breakdown of verification cost

By self time (`tottime`) across the same profile, verification cost is
dominated by pure-Python `pathlib` overhead layered on top of the actual
hashing:

```
6,843,364 calls  pathlib.PurePath.__init__          6.7s
1,406,124 calls  hashlib HASH.update                4.7s   <- the actual crypto work
8,227,394 calls  pathlib._str_normcase                4.1s
  866,558 calls  posix.lstat                          3.5s
2,100,265 calls  posixpath.join                       3.5s
```

The SHA-256 hashing itself (`HASH.update`, the unavoidable work of reading
every byte) is a real but *minority* contributor (~4.7s of ~97s, under 5%).
The rest is `pathlib`-heavy directory-walking and path-normalization
overhead in `treehash.py`'s `_scan_entries` / `_sorted_regular_files` /
`_posix_relative`, repeated per shelf per call. This means a warm-mode cache
that skips re-verification saves not just I/O and hashing but a large
constant-factor Python-level overhead that scales with file count × shelf
count — this is worth flagging to whoever implements #272's cache layer,
since a `pathlib`-free rewrite of the scan (independent of #272) would also
help but is out of scope here.

## Finding 4 — `search --corpus` re-verifies every eligible shelf per invocation: CONFIRMED

Directly confirmed by code inspection and the profile: `engine.py`'s
`ScopedSearcher.search()` iterates `spec.scopes` and for each one enters
`_local_shelf()`, which calls `read_valid_manifest()` under the per-target
advisory lock (`engine.py:643-668`). `read_valid_manifest` unconditionally
calls `verify_materialized_integrity` (`materialize.py:717-723`) for every
manifest carrying `materialized_tree_hash` or a file-digest map — i.e. every
shelf produced by current materialization. There is no cache; every
invocation redoes the full scan for every scope in play, and (per Finding 2)
`CorpusSearcher`'s eligibility pass does a second, corpus-wide pass through
`enumerate_shelved_sources` before that. The issue's claim is correct: this
is a genuine, repeated cost, not a hypothesis.

## Finding 5 — what `mcp/bridge.py` pays per tool call: CONFIRMED, full cost

`src/leitir/mcp/bridge.py:96-111` (`run_leitir_json`) shells out to
`[sys.executable, "-m", "leitir.cli", *argv]` via `subprocess.run` for
**every** MCP tool call — `search`, `info`, `api`, `examples`, `diff`. No
in-process call exists (the module docstring says so explicitly: "no
resolution, search, or verification logic is reimplemented here"). Each tool
call therefore pays the full cost measured above: ~100ms interpreter+import
overhead plus the full corpus-scan verification cost for whatever command was
invoked (single-digit seconds for a small corpus, tens of seconds for a
~120-160 shelf corpus like the one measured here, and worse for the
131-shelf corpus the dogfood report describes, or the larger corpora a real
agent session accumulates). An agent doing ten to twenty consultations in
one task, as the issue describes, currently pays this **once per call**,
serially, with no reuse across calls even when the same shelves are touched
repeatedly.

## Summary table

| Cost component | Measured | Dominant? |
|---|---|---|
| Python interpreter startup | ~0.01s | No |
| `import leitir.cli` | ~0.07-0.11s | No |
| Corpus-wide manifest re-verification (`enumerate_shelved_sources`, 163 entries) | ~94.8-96.7s (cumulative, profiled run) | **Yes — ~97% of wall time** |
| Actual SHA-256 hashing within that scan | ~4.7s (~5% of the scan) | No (minority of the dominant cost) |
| `search --corpus` end-to-end, cold page cache | 81.5s | (same mechanism as above) |
| `search --corpus` end-to-end, warm page cache | 40.3s | (same mechanism as above) |
| Single-shelf `info --brief`, warm page cache | 39.2s | Pays the *same* full-catalog cost as `search --corpus` |
| MCP `bridge.py` per tool call | subprocess spawn (~ms) + full cost above | Subprocess overhead is negligible next to verification |

**Bottom line for design:** the issue's framing ("cold Python start... full
shelf re-verification") correctly identifies re-verification as the target,
but understates its scope — it is not confined to `search --corpus`'s
fan-out, it is inherent to spec resolution against a growing catalog. Any
warm-mode cache that only memoizes per-search-scope state, and not the
catalog-enumeration path, will still leave every single-shelf command paying
full-corpus cost. See ADR-0035 for what this means for what is cached and
how it is invalidated, and see issue #279 for the cold-path defect (O(catalog)
work per call, independent of warm mode) this same measurement surfaced.
