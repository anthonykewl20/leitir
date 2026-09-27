# Reliability audit — concurrency, scale, idempotency, dead code (2026-09-27)

Repository-wide engineering audit of leitir @ `a32fca9` (Linux, Python 3.14.7, 16 cores).
Code and real runs were the only source of truth. Four independent scans traced code paths
and reproduced findings with real concurrent processes, repeated runs, injected SIGKILLs and
measurements; the lead auditor re-checked the highest-impact claims in code. No repository
file was modified by the scans. Every finding is filed as an issue in
[milestone 7](https://github.com/anthonykewl20/leitir/milestone/7) (epic
[#410](https://github.com/anthonykewl20/leitir/issues/410), "Phase R"), each with a decided
fix, explicit blockers and acceptance tests. Where this report says "forced", the harness
only added sleeps to widen a window that exists in the real code.

## Executive summary

| Category | Findings | Confirmed (reproduced/measured) | High (code-confirmed, not run) |
|---|---|---|---|
| Race conditions | 5 | 3 | 2 |
| Concurrency and scale | 8 | 7 | 1 |
| Idempotency | 11 | 10 | 1 |
| Dead / unreachable code | 11 (+5 corrections to #406) | 8 | 3 |
| **Total** | **35** | **28** | **7** |

Duplicates were merged: the unlocked `remove` was found independently by the race and
idempotency scans (one finding, #415); the deadlock and the corpus-wide serialization share
a root cause (POINTERS.md regeneration under locks) but have different impacts, so they are
two linked findings (#414, #419).

**Highest-impact issues**

1. **#413 (Critical, confirmed)** — `bts-compute`/`bts-run` lock the shelf's parent instead
   of the corpus root; a concurrent BTS call deletes an in-flight `get`'s staging and the
   registry-artifact path publishes a **partial shelf marked `verified: True`** (8 of 16
   files), which re-`get` does not repair.
2. **#414 (High, confirmed without instrumentation)** — inconsistent lock ordering
   deadlocks concurrent agents: `sbom` + `api` hung in 42 of 150 plain runs; `flock` has no
   timeout, so agents hang forever.
3. **#418 (Critical, measured)** — `info`/`examples` run one regex per API symbol over every
   snippet under the shelf's exclusive lock: next.js `info` ≈ 2 hours (extrapolated from
   21.5 s per 20 snippets; observed >830 s), stalling every other command on the corpus.
4. **#419 / #420 (High, measured)** — every cached call rewrites the catalog and takes every
   shelf lock to rebuild POINTERS.md, and read commands re-hash the whole corpus: 20 agents on
   1,000 shelves → p50 53 s per `info`.
5. **#437 (Medium, confirmed)** — the `usage` admission gate that modules claim is wired is
   never called.

**Systemic patterns**

- *Lock discipline is by convention*: the global order exists only as a comment
  (`corpus.py:925`); several paths hold one lock while acquiring others, and two paths take
  no lock at all (#413, #414, #415, #417).
- *Derived artefacts are rebuilt eagerly under writer locks* (POINTERS.md, API/examples,
  index bindings), so read-mostly agent workloads serialize (#418, #419, #420, #432).
- *Directory outputs are not staged atomically* even where single files are (#428, #429,
  #434).
- *Fail-open on "unknown"* in tooling and flags: dedupe search failure → create
  (#430); `--require-index` partial → exit 0 (#432); `lock` unsupported input → exit 0
  (#368, earlier audit).
- *Test-only production code*: ~2,360 lines reachable only from tests, including two
  integrity gates (#437, #438).

## Findings

### [RACE] — BTS locks the wrong root and publishes partial verified shelves (#413)
**Severity:** Critical **Confidence:** Confirmed (forced interleaving, real processes)
**Location:** `src/leitir/bts_cli.py:177` `load_donor_snapshot`, `:211` `load_donor_materialization`; `bts_cli.py:847,884`; `bts.py:1144`; `materialize.py:221` `_sweep_target_debris`; `materialize.py:2005-2049`.
**Evidence:** `with _target_lock(target.parent, target, commit_sha):` → lock file under `repos/<host>/<owner>/<repo>/.locks/` instead of `<root>/.locks/`.
**How It Happens:** `get pypi:six` extracts under the real lock; `bts-compute` holds a different lock, its sweep `rmtree`s the live staging; extraction recreates parents; the partial tree is hashed and published.
**Impact:** Shelf with 8/16 files, `verified: True`, accepted by `list`/`info`; not repaired by re-`get`.
**Root Cause:** Shelf parent passed as corpus root; no extracted-set vs archive-member check.
**Recommended Fix:** Carry corpus root in `DonorSnapshot`; `_target_lock` rejects non-corpus roots; compare staged files to archive members before hashing.
**Verification:** Blocked-writer + concurrent `load_donor_snapshot` test; tamper test for a deleted member.

### [RACE] — Lock-order deadlocks between sbom/get/api/examples/info (#414)
**Severity:** High **Confidence:** Confirmed (42/150 natural hangs; wait-for graphs from `/proc/locks`)
**Location:** `cli_corpus.py:1320-1323`; `corpus.py:616-644`; `docpointers.py:142`; `cli_corpus.py:1533-1544,1801,1814`; `info.py:354`.
**Evidence:** `sbom`: shelves → `.sources.lock`; `_upsert`: `.sources.lock` → every shelf; `api`: own shelf → every other shelf.
**How It Happens:** Three captured cycles (api↔sbom, get↔sbom, api↔api on different shelves).
**Impact:** Agents hang indefinitely; MCP calls until the 600 s bridge timeout; same for threads via `leitir.api.call_json`.
**Root Cause:** No enforced global lock order; POINTERS regeneration under held locks.
**Recommended Fix:** One lock-acquisition helper with the order `.sources.lock` → sorted shelves → index manifest lock; never regenerate POINTERS while holding a shelf lock.
**Verification:** Subprocess pair tests with timeouts; 150-iteration stress loop with 0 hangs.

### [RACE] — `remove`/`clean` modify the catalog and delete shelves unlocked (#415)
**Severity:** Medium **Confidence:** Confirmed (reproduced by two scans)
**Location:** `corpus.py:1023-1073` `remove_source`; `cli_corpus.py:1223-1228`.
**Evidence:** `load_sources` → `rmtree` → `write_sources(kept)` with no `.sources.lock` or shelf lock.
**How It Happens:** A concurrent `get` upserts between remove's read and write.
**Impact:** Fetched shelf invisible to list/sbom/export/search; both commands exit 0.
**Root Cause:** Unlocked read-modify-write and deletion.
**Recommended Fix:** Lock helper from #414; rename-then-delete under the shelf lock.
**Verification:** Paused-remove + concurrent upsert test; kill-during-remove test.

### [RACE] — Windows blocking lock fails after ~10 s (#416)
**Severity:** Medium **Confidence:** High (code + documented `msvcrt` semantics; not run on Windows)
**Location:** `materialize.py:172-193` `_file_lock`.
**Evidence:** `msvcrt.locking(fd, msvcrt.LK_LOCK, 1)`; re-raised when blocking.
**How It Happens:** A holder keeps a lock >10 s; the waiter raises `OSError`.
**Impact:** Spurious failures for concurrent agents on Windows.
**Root Cause:** `LK_LOCK` treated as indefinite.
**Recommended Fix:** Loop on `LK_NBLCK` with a short sleep.
**Verification:** Windows CI test with a 15 s holder.

### [RACE] — `upgrade-cache` stale write and trust-on-first-hash backfills (#417)
**Severity:** Medium **Confidence:** High (code; lost update needs a legacy corpus)
**Location:** `cli_corpus.py:621-669`; `corpus.py:980-992`; `materialize.py:535-547`.
**Evidence:** Manifest read and tree hash computed outside `_target_lock`, written inside; anchor backfilled for a digest-map-without-anchor manifest that `update_manifest` rejects; `lock_project` anchors unverified bytes.
**How It Happens:** Concurrent `trust`/`info`/re-materialize between read and write.
**Impact:** Lost manifest fields; tampered bytes anchored.
**Root Cause:** Work outside the lock; backfills not gated on verification.
**Recommended Fix:** Read/hash/write under the lock via `update_manifest`; refuse anchorless digest maps; `lock` re-materializes instead of backfilling.
**Verification:** Slow-hash + concurrent trust test; reject tests.

### [SCALE] — Quadratic example matching under an exclusive lock (#418)
**Severity:** Critical **Confidence:** Confirmed (measured; py-spy 72% in `extract_examples`)
**Location:** `examples.py:485-506`; `info.py:300-330`.
**Workload Scenario:** `info`/`examples` on a monorepo. **Scaling dimension:** snippets × symbols per shelf.
**Evidence:** 23,130 symbols × 6,948 snippets; 21.51 s per 20 snippets; unrelated `info` blocked >60 s.
**Why It Scales Poorly:** One regex per symbol per snippet; recompilation past the 512-pattern cache; no reuse across calls.
**Estimated Failure Mode:** Hours-long lock hold; corpus-wide stall; MCP timeout cascades.
**Recommended Fix:** Tokenize once and intersect with a symbol set; stop at `limit`; derive outside the writer lock; cache by tree hash.
**Verification:** next.js `info` < 60 s; concurrent `info` on another shelf completes.

### [SCALE] — No-op calls rebuild the catalog and POINTERS.md across every shelf lock (#419)
**Severity:** High **Confidence:** Confirmed (measured)
**Location:** `corpus.py:616-644,928`; `docpointers.py:142`; `materialize.py:313-375`; `cli_corpus.py:1801,1814`.
**Workload Scenario:** Many agents looping `info`. **Scaling dimension:** shelves × agents.
**Evidence:** 1,003 epoch bumps and 2.41 s per cached `info` at 1,000 shelves; 20 agents → p50 53.2 s, max 130.6 s; one held lock delayed an unrelated `info` 14.23 s.
**Why It Scales Poorly:** O(catalog) locks and fsyncs per call under the global catalog lock.
**Estimated Failure Mode:** Latency growth, worker starvation, timeout amplification.
**Recommended Fix:** Skip byte-identical upserts; render POINTERS without shelf locks, incrementally; shared locks for verifying readers.
**Verification:** ≤ 3 epoch bumps per repeat `info`; concurrent `info` < 2× single-call time.

### [SCALE] — Read commands re-hash the whole corpus per call (#420)
**Severity:** High **Confidence:** Confirmed (measured)
**Location:** `corpus.py:172-219`; `engine.py:671`; `cli_search.py:267-298,644-647`.
**Workload Scenario:** `list`/`search` loops. **Scaling dimension:** corpus bytes per call.
**Evidence:** `search --corpus` 2,000 verifications at 1,000 shelves (8.2 s); scoped search 0.068 s → 2.305 s with one monorepo present.
**Why It Scales Poorly:** Duplicate verification; routings for the whole catalog.
**Estimated Failure Mode:** CPU/IO growth per call proportional to corpus size.
**Recommended Fix:** Verify once per served shelf; routings only for results; keep tree-hash verification.
**Verification:** Counting tests; tamper test on every path.

### [SCALE] — Verification cap excludes monorepos from search and indexing (#421)
**Severity:** Medium **Confidence:** Confirmed (measured)
**Location:** `materialize.py:77-78,1247-1250,1351-1355`.
**Workload Scenario:** Any repo > 1,000 files. **Scaling dimension:** files per repo.
**Evidence:** next.js `sampled`/`unknown`, excluded from `--corpus` and `index`; full local check of 33,215 files: 0.46 s, 0 mismatches, tree not truncated.
**Why It Scales Poorly:** API-cost cap applied to local comparison.
**Estimated Failure Mode:** Empty corpus results for the largest repos.
**Recommended Fix:** Full comparison when the tree listing is complete.
**Verification:** >1,000-file fixture verified and indexable; tamper test.

### [SCALE] — Unpinned registry specs repeat 5 network calls and unbounded metadata (#422)
**Severity:** Medium **Confidence:** Confirmed (measured)
**Location:** `resolver.py:455-458,2546-2580`.
**Workload Scenario:** Agent loops on `info npm:<name>`. **Scaling dimension:** API calls, payload.
**Evidence:** 5 requests per call; `next` metadata 31.3 MB fetched twice.
**Why It Scales Poorly:** No memo, no size bound, no tag→SHA cache.
**Estimated Failure Mode:** Rate-limit exhaustion (~1,666 unpinned calls/hour/token), bandwidth and memory pressure.
**Recommended Fix:** Memo; abbreviated metadata with bounded reads; on-disk tag→SHA hints re-verified.
**Verification:** HTTP-count test.

### [SCALE] — Registry `get` downloads whole monorepos for a discarded parity check (#423)
**Severity:** Medium **Confidence:** Confirmed (measured)
**Location:** `corpus.py:843-866`.
**Workload Scenario:** Cold registry `get` of monorepo packages. **Scaling dimension:** payload, lock time.
**Evidence:** `npm:next@15.0.0`: +41.4 MB codeload download; parity `unknown`, `files_compared: 0`.
**Why It Scales Poorly:** Unbounded side materialization inside the writer lock; exceptions swallowed.
**Estimated Failure Mode:** Bandwidth/temp-disk/lock-time amplification.
**Recommended Fix:** Subpath-bounded parity outside the lock; record `parity_error`.
**Verification:** No full download; lock hold < 5 s.

### [SCALE] — Global search: sequential fetches, no shared cache (#424)
**Severity:** Medium **Confidence:** High (partially measured)
**Location:** `cli_search.py:533-534`; `discovery_search.py:835-873`; `_http.py:419`.
**Workload Scenario:** 50 agents sharing one token. **Scaling dimension:** API calls × agents.
**Evidence:** 1 search call + 30 sequential raw fetches (17.56 s); code-search limit 10/min.
**Why It Scales Poorly:** Shared per-token budget, synchronized retries.
**Estimated Failure Mode:** Rate limiting and thundering herd; exact concurrent failure rate not quantified by the available evidence.
**Recommended Fix:** TTL result cache, immutable blob cache, bounded parallel fetch, jitter.
**Verification:** HTTP-count and wall-time tests.

### [SCALE] — Whole archives buffered in memory (#425)
**Severity:** Low **Confidence:** Confirmed for one process
**Location:** `materialize.py:1020-1031,1499-1502`.
**Workload Scenario:** Concurrent large `get`s. **Scaling dimension:** payload × processes.
**Evidence:** next.js `get` peak RSS 247 MB; concurrent totals not quantified by the available evidence.
**Why It Scales Poorly:** Full-response buffering.
**Estimated Failure Mode:** Memory pressure.
**Recommended Fix:** Spooled temp file with the same cap.
**Verification:** RSS < 100 MB.

### [IDEMPOTENCY] — Verified `get` never upgrades a `--no-verify` shelf (#426)
**Severity:** Medium **Confidence:** Confirmed
**Location:** `materialize.py:1613-1636,1722-1728,1033-1051`.
**Evidence / behaviour:** First: `verified: false`. Every retry: re-download, `tree verification outcome=True`, staging discarded, still `verified: false`.
**Why not idempotent:** Retries never converge on the requested state.
**Recommended Fix:** Replace when staged verification is stronger.
**Verification:** no-verify → verify → `verified: True`; third call offline.

### [IDEMPOTENCY] — `lock` writes project closures into shared manifests (#427)
**Severity:** Medium **Confidence:** Confirmed
**Location:** `corpus.py:993`; `sbom.py:439-451`.
**Evidence / behaviour:** Same `lock --cwd P2` rerun gives `sbom` deps `['ms']` or `['is','ms']` depending on whether P1 ran.
**Why not idempotent:** Output depends on corpus history, not inputs.
**Recommended Fix:** Project-keyed closure files; sbom reads only the project's closure.
**Verification:** Byte-identical sbom regardless of other projects.

### [IDEMPOTENCY] — `bts-run --out` mixes stale and new artefacts (#428)
**Severity:** Medium **Confidence:** Confirmed
**Location:** `cli_bts.py:525-529`; `pipeline_cli.py:1591-1629`.
**Evidence / behaviour:** Seeded stale result/summary/packet survived a rerun that wrote a fresh receipt.
**Why not idempotent:** No emptiness check; no directory staging.
**Recommended Fix:** Refuse non-empty `--out`; stage and `os.replace`; summary last.
**Verification:** Seeded-dir rejection; kill-before-summary leaves nothing.

### [IDEMPOTENCY] — `exit-gate-run` output directory not atomic (#429)
**Severity:** Medium **Confidence:** Confirmed (in-process SIGKILL)
**Location:** `pipeline_cli.py:1935,2008,2061,2065`.
**Evidence / behaviour:** Stale case dirs survive; kill between report and summary left mismatched digests accepted on rerun.
**Recommended Fix:** Stage the directory; refuse non-empty; readers check `summary.report_digest`.
**Verification:** Kill tests; reject test.

### [IDEMPOTENCY] — Calibration creates duplicate issues when dedupe search fails (#430)
**Severity:** Medium **Confidence:** Confirmed (stub `gh`)
**Location:** `tools/calibration/issues.py:72-81,111-128`; `.github/workflows/calibration.yml`.
**Evidence / behaviour:** Search error → `None` → second issue created; ledger never persisted in CI.
**Recommended Fix:** Raise on unknown; workflow concurrency group; save ledger per action.
**Verification:** Stub-`gh` tests.

### [IDEMPOTENCY] — Mutation probe leaves `src/` mutated after a kill (#431)
**Severity:** Medium **Confidence:** Confirmed (pattern reproduced)
**Location:** `tools/calibration/mutation.py:519-533`; `tools/calibration/cli.py:58`.
**Evidence / behaviour:** SIGTERM skipped `finally`; file stayed mutated; later probes ran against it.
**Recommended Fix:** Mutate a copy on `PYTHONPATH`; abort all probes on dirty `src/`.
**Verification:** Kill test; dirty-tree test.

### [IDEMPOTENCY] — Metadata writes invalidate indexes; `--require-index` partial exits 0 (#432)
**Severity:** Medium **Confidence:** Confirmed
**Location:** `corpus.py:420,993`; `info.py:347`; `index/builder.py:118`.
**Evidence / behaviour:** `index` → `trust` → `--require-index` search: `rc=0`, `shelves_searched=0`, `unindexed`.
**Recommended Fix:** Bind index to tree hash + identity; non-zero exit on required-index partial.
**Verification:** index→trust→search COMPLETE; exit-code test.

### [IDEMPOTENCY] — `gc` misses non-GitHub layouts and manifest temp files (#433)
**Severity:** Low **Confidence:** Confirmed
**Location:** `cli_corpus.py:697-840`.
**Evidence / behaviour:** Killed Go-module `get` debris survives two `gc` runs reporting `removed: 0`.
**Recommended Fix:** Pattern-match debris at any depth, incl. files.
**Verification:** Per-layout gc tests.

### [IDEMPOTENCY] — `import` rerun errors and leaks `$TMPDIR` staging (#434)
**Severity:** Low **Confidence:** Confirmed
**Location:** `snapshot.py:302`; `corpus.py:554-555`.
**Evidence / behaviour:** Second import of an identical snapshot → rc=1; killed import leaves `leitir-snapshot-import-*`.
**Recommended Fix:** No-op success when destination matches the lock; stage beside the root.
**Verification:** Double-import and crash tests.

### [IDEMPOTENCY] — Retried `remove` needs the network (#435)
**Severity:** Low **Confidence:** Confirmed
**Location:** `cli_corpus.py:1198-1222`.
**Evidence / behaviour:** Offline second `remove` fails with a registry connection error (rc=1).
**Recommended Fix:** Exact-version specs absent from the catalog → `not found`, rc 0, offline.
**Verification:** Offline double-remove test.

### [IDEMPOTENCY] — Release/containment tooling not retry-safe; nsjail installed before verification (#436)
**Severity:** Medium **Confidence:** High (code)
**Location:** `.github/workflows/release.yml:200`; `.github/workflows/bts-containment.yml:547-552`; `tools/build-nsjail.sh:64-72`.
**Evidence / behaviour:** Re-run fails on existing release; `upload --clobber` replaces the pinned asset unchecked; `install` precedes the sha256 check.
**Recommended Fix:** Resume-by-digest; skip/fail on asset digest; verify before install; concurrency groups.
**Verification:** Stub-`gh` dry runs; script test.

### [DEAD CODE] — `usage` admission gate never called (#437)
**Severity:** Medium **Confidence:** Confirmed **Class:** Potentially Intended but Unwired
**Location:** `usage/admission.py` (302 lines).
**Evidence:** No importer; module never loaded; docstrings claim it is wired.
**Recommendation:** Wire into `usage` assembly; tamper/reject test.

### [DEAD CODE] — `require_full_provenance` guard unused (#438)
**Severity:** Medium **Confidence:** Confirmed **Class:** Potentially Intended but Unwired
**Location:** `resolver.py:267,340`.
**Evidence:** No production caller; consumers check `degraded_provenance` ad hoc.
**Recommendation:** Route commit-SHA consumers through it.

### [DEAD CODE] — Runtime import recorder test-only (#439)
**Severity:** Medium **Confidence:** Confirmed **Class:** Potentially Intended but Unwired
**Location:** `graph/runtime.py:187-927`.
**Evidence:** Only two enums imported in production; recorder used by tests only.
**Recommendation:** Retire with an ADR-0009 note; keep the enums.

### [DEAD CODE] — `duplicates.py` test-only; enums defined three times (#440)
**Severity:** Low **Confidence:** Confirmed **Class:** Likely Dead
**Location:** `duplicates.py`; `architecture.py:29/35`; `composition.py:36/48`.
**Recommendation:** Single enum definition; wire detector via `compare` (#383).

### [DEAD CODE] — `lineage.check_drift` test-only (→ #396)
**Severity:** Low **Confidence:** Confirmed **Class:** Potentially Intended but Unwired
**Location:** `lineage.py:373`.
**Recommendation:** Build `adopted status` on it (recorded in #396).

### [DEAD CODE] — Confirmed-dead helpers and exports (#441)
**Severity:** Low **Confidence:** Confirmed **Class:** Confirmed Dead
**Location:** `check.py:295,427`; `cli_support.py:133-143`; `engine.py:263`; `warm.py:473`; `examples.py:373`; `license_policy.py:1213`; `cost.py:344`.
**Recommendation:** Remove.

### [DEAD CODE] — Test-only wrappers mask production-path coverage (#442)
**Severity:** Low **Confidence:** High **Class:** Likely Dead
**Location:** 12 symbols (e.g. `engine.py:294 score_content`, `discovery_search.py:698 build_query`, `pipeline_cli.py:1632`).
**Recommendation:** Retarget tests to production functions; delete wrappers.

### [DEAD CODE] — `clean --repos` parsed but never read (#443)
**Severity:** Medium **Confidence:** Confirmed **Class:** Likely Dead
**Location:** `cli_corpus.py:176,1223-1230`.
**Recommendation:** Remove the flag; update ADR-0004.

### [DEAD CODE] — Tests set an env var no code reads (#444)
**Severity:** Low **Confidence:** Confirmed **Class:** Confirmed Dead
**Location:** six test files; `_update_check.py:70`.
**Recommendation:** Use `LEITIR_NO_UPDATE_CHECK=1` via an autouse fixture.

### [DEAD CODE] — Operator tools and benchmarks without an invoker (#445)
**Severity:** Low **Confidence:** High **Class:** Potentially Intended but Unwired
**Location:** `tools/export_asv_evidence.py`, `tools/loadtest_corpus.py`, `benchmarks/bench_hot_paths.py`.
**Recommendation:** CI smoke import.

### [DEAD CODE] — Test-only reference implementations and hooks (not filed)
**Severity:** Low **Confidence:** High **Class:** Potentially Intended but Unwired
**Location:** `manifest_auth.py:302,416`; `exec_sandbox.py:1158,1220`; `exit_corpus.py:479`; `funnel_cli.py:148,360`; `graph/model.py:616`; `apisurface.py:603 register_extractor`.
**Recommendation:** Keep — test oracles, ceremony helpers and ADR-documented extension points; not a defect.

Corrections to #406 (recorded in the issue): `resolve_source_license` is reachable;
`build_reuse_packet_v2` has no tests; all of `cost.py` is unimported; more `occupied` types
are test-only; `compose` helpers confirmed test-only.

## Remediation priorities

| Priority | Finding | Category | Severity | Confidence | Main Risk | Recommended Action |
|---|---|---|---|---|---|---|
| 1 | #413 BTS wrong lock root | Race | Critical | Confirmed | Partial shelf published as verified | Corpus-root lock + member-set check |
| 2 | #414 Lock-order deadlocks | Race | High | Confirmed | Agents hang forever | Single ordered lock helper |
| 3 | #418 Quadratic examples under lock | Scale | Critical | Confirmed | Hours-long corpus stall | Token-set matching, derive outside lock, cache |
| 4 | #419 No-op upsert/POINTERS rebuild | Scale | High | Confirmed | Serialized agents, minute latencies | Skip no-op writes; lock-free POINTERS |
| 5 | #420 Per-call full re-hash | Scale | High | Confirmed | CPU/IO grows with corpus | Verify once per served shelf |
| 6 | #415 Unlocked remove/clean | Race | Medium | Confirmed | Lost catalog entries | Catalog + shelf locks |
| 7 | #437 Admission gate unwired | Dead code | Medium | Confirmed | Integrity claim not enforced | Wire gate |
| 8 | #438 Provenance guard unused | Dead code | Medium | Confirmed | Degraded provenance slips through | Route consumers through guard |
| 9 | #417 upgrade-cache / trust-on-first-hash | Race | Medium | High | Anchoring tampered bytes | Lock + refuse unsafe backfills |
| 10 | #426 no-verify sticky | Idempotency | Medium | Confirmed | Never-verified shelves | Replace on stronger verification |
| 11 | #432 Index invalidation / exit 0 | Idempotency | Medium | Confirmed | Silent empty results | Bind to tree hash; non-zero exit |
| 12 | #428 bts-run --out | Idempotency | Medium | Confirmed | Mixed audit evidence | Refuse non-empty; stage |
| 13 | #429 exit-gate-run out | Idempotency | Medium | Confirmed | Inconsistent phase evidence | Stage directory |
| 14 | #427 lock deps in shared manifests | Idempotency | Medium | Confirmed | Wrong SBOMs | Project-keyed closures |
| 15 | #421 Verification cap | Scale | Medium | Confirmed | Monorepos unsearchable | Full local check |
| 16 | #436 Release/containment tooling | Idempotency | Medium | High | Unverified nsjail; asset replaced | Verify before install; resume by digest |
| 17 | #430 Calibration duplicate issues | Idempotency | Medium | Confirmed | Duplicate public issues | Fail-closed dedupe |
| 18 | #431 Mutation probe leaves src mutated | Idempotency | Medium | Confirmed | False findings | Mutate a copy |
| 19 | #422 Registry metadata calls | Scale | Medium | Confirmed | Rate limits, bandwidth | Memo, bound, cache |
| 20 | #423 Parity side download | Scale | Medium | Confirmed | Bandwidth, lock time | Subpath-bounded, outside lock |
| 21 | #424 Global search cache | Scale | Medium | High | Rate-limit stampede | TTL cache, parallel fetch |
| 22 | #416 Windows lock timeout | Race | Medium | High | Spurious failures | LK_NBLCK loop |
| 23 | #443 `clean --repos` ignored | Dead code | Medium | Confirmed | Unexpected cache loss | Remove flag |
| 24 | #439 Runtime recorder | Dead code | Medium | Confirmed | Misleading control | Retire |
| 25 | #425 Archive buffering | Scale | Low | Confirmed | Memory pressure | Spool to disk |
| 26 | #433 gc layouts | Idempotency | Low | Confirmed | Disk leaks | Pattern-based sweep |
| 27 | #434 import rerun | Idempotency | Low | Confirmed | Retry errors, tmp leaks | No-op success; stage beside root |
| 28 | #435 remove offline | Idempotency | Low | Confirmed | Offline retry failure | Offline not-found |
| 29 | #440 duplicates/enums | Dead code | Low | Confirmed | Divergent enums | Single definition |
| 30 | #444 env var in tests | Dead code | Low | Confirmed | Network in offline tests | Fix variable |
| 31 | #441 dead helpers | Dead code | Low | Confirmed | Clutter | Remove |
| 32 | #442 test-only wrappers | Dead code | Low | High | Misleading coverage | Retarget tests |
| 33 | #445 tools smoke | Dead code | Low | High | Silent rot | CI smoke import |

## What could not be verified

| Gap | Why | Evidence needed |
|---|---|---|
| Windows lock behaviour (#416) and any Windows-specific paths | Audit ran on Linux | A Windows CI run holding a lock for 15 s |
| Natural frequency of the BTS sweep race (#413) and the api↔api deadlock | Shown with widened windows | A soak test of parallel agent workloads on a shared corpus |
| Thread-level deadlocks through `leitir.api.call_json` | Inferred from `flock` semantics | A threaded reproduction |
| Contained `bts-run`/`exit-gate-run` behaviour | nsjail and the rootfs are not on the audit host | A run on the containment CI runner |
| MCP server concurrency (sync tool functions on the event loop) | `mcp` extra not installed | Concurrent MCP calls against an installed server |
| Truncated-tree walk cost (e.g. microsoft/TypeScript) | Would consume ~40% of the hourly API budget | A dedicated-token measurement |
| Full next.js `info` wall time | Stopped at 830 s | Run to completion on a dedicated host |
| Concurrent memory totals for large `get`s | Single-process only | Concurrent RSS measurement |
| NFS/shared-filesystem corpus roots | Not tested | `flock` semantics on the target filesystem |
| GitHub-side behaviour for partial releases and search-index lag | Simulated with a stub `gh` | A sandbox repository |
| Legacy-manifest `upgrade-cache` lost update | Needs a pre-#194 corpus | A corpus built by an older release |
| Branch-level dead code beyond type-provable cases | mypy `warn_unreachable` clean; runtime invariants not enumerated | Coverage from real CLI journeys |
