# BTS v1 real agent tasks

These six single-task manifests are the non-synthetic #75 evaluation set. Each
seed file was checked out at the exact commit below and its Git blob SHA-1 was
computed from the checked-out bytes. A grade of 2 is the intended seed; grade 1
is a plausible component-level alternative, not an interchangeable answer.

| Task | Grade-2 seed | Contract baseline (pass/fail/skip) | License |
| --- | --- | --- | --- |
| `async-retry-backoff` | `litl/backoff@d82b23c42d7a7e2402903e71e7a7f03014a00076` `backoff._jitter.full_jitter` lines 18-28 | 9/0/0 | MIT |
| `url-normalization-compare` | `niksite/url-normalize@9a9a3214c2b3bdab09ba7b19c8f9d22aa4cfee31` `url_normalize.normalize_fragment.normalize_fragment` lines 1-27 | 9/0/0 | MIT |
| `lru-ttl-decisions` | `lonelyenvoy/python-memoization@9c1a0d13e8fbad1f7f4a05d5b41873a7ca5b6aaa` `memoization.caching.general.values_with_ttl.make_cache_value` lines 4-5 | 6/0/0 | MIT |
| `binary-wire-decode` | `moontreeapp/electrumx-evr@df269a63bcb2fd09bb0fea9142f31f6598c079a0` `electrumx.lib.tx.read_le_uint32` lines 143-145 | 11/0/0 | MIT |
| `worker-shutdown-predicate` | `python/mypy@d6d7295e6721a6d97bd474569820f6ea10e983dd` `mypy.build_worker.worker.should_shutdown` lines 140-147 | 3/0/0 | MIT |
| `three-repo-combine` | `mmcloughlin/luhn@c26e5c61fbc23006f265a71b9f87dac229e6ed99` `luhn.checksum` lines 3-11 | 9/0/0 | MIT |

## Gold and grading rationale

- **Async retry:** `full_jitter` is the exact full-range jitter component. Cognee's
  exponential calculator and Omi's capped millisecond calculator are graded 1:
  useful arithmetic, but not the selected full-jitter operation. The async loop
  and sleep boundary are intentional recipient adaptations.
- **URL normalization:** `normalize_fragment` preserves the percent-decoding and
  re-quoting component boundary. w3lib's file-URI conversion and urltools'
  default-port removal are real, similar URL-component operations and are
  distractors rather than substitutes.
- **LRU + TTL:** python-memoization's TTL value construction is the seed; its
  validity and retrieval functions plus gazu's expiry decision are required
  components. The mutation/eviction wrapper is recipient-authored.
- **Binary wire:** ElectrumX's little-endian uint32 decoder has the intended
  `(value, cursor + width)` shape. Its neighbouring fixed-width readers and the
  vlen/zigzag/CRC primitives are plausible but incomplete alternatives.
- **Worker shutdown:** mypy's predicate recognizes the coordinator's empty SCC
  request and rejects unexpected message tags. It is the sole grade-2 seed.
- **Three-repository combine:** Luhn checksum is the composition entry point;
  full jitter and fragment normalization are required cross-repository helpers.

All source licenses in the selected grade-2 rows are MIT. The supplemental
candidate pool also includes Apache-2.0 (Cognee, freemqtt, Iroha, kafka) and
LGPL-3.0-or-later (gazu); the latter is a component distractor only and is not
the expected license of the task seed.

## Baseline recording

The `expected_outcome_vector` and selected IDs are the sorted, all-pass results
of the supplied pinned-donor contract tests: 47 tests across the six tasks.
The six digests in the manifests are SHA-256 over the canonical
`[[test_id,"pass"], ...]` vector, prefixed with `sha256:`. They bind the
recorded runner-neutral baseline; the integrated pipeline must pin its E2
baseline evidence to the same outcome vector before a live evaluation can pass.

The contained execution substrate is CPython `>=3.12,<3.13`. The url-normalize donor imports `idna==3.18` at runtime. Install runtime pins
only in the contained CI execution environment (or supply its locked runtime
image); they are not Leitir runtime dependencies. Three-repo-combine uses the
honest fallback mode `coexisting-recipient-three-runs`: it runs the three public,
one-donor pipeline validators separately over their disjoint, direct-import
contract-test subsets and reports an aggregate of their three results. A merged relocation is not constructed:
`Relocation.publish` accepts only an empty recipient and there is no public
merged-Relocation/rerun validator. The aggregate consequently has no single-run
baseline digest and cannot be presented as a successful merged-recipient
integration result.

Each task has a reviewed, closed `tasks/<task-id>/policy.json` sidecar. The
driver passes that exact sidecar to the task assembler rather than discovering a
policy: async retry authorizes `random`; binary wire authorizes `struct` and
`zlib`; LRU/TTL authorizes `time`; URL normalization pins
`url_normalize.tools`; the three-repo task is their `random`/URL union; and the
worker predicate has an explicitly empty policy. Their bytes are receipted in
`RECEIPTS.json`.

## CI runner

`tools/run_bts_tasks.py --dry-run` emits a canonical plan without materializing,
validating, or executing donor code. A non-dry run requires `--root`,
`--substrate-nsjail-sha`, `--substrate-rootfs-digest`, `--nsjail-version`,
`--nsjail-build-identity`, `--config-schema-digest`, and `--rootfs-source`.
Before materializing exact Git pins it fail-closes on the committed sidecar
layout `tasks/<task-id>/contract_tests/*.py` and
`tasks/<task-id>/baseline.json`; it then requires the integrated
`leitir.pipeline_cli` task-request assembler. The pipeline remains responsible
for S2/nsjail containment; the driver has no unsandboxed donor-execution
fallback.

Candidate pins are the C3 search space and require structural materialization:
an immutable 40-hex commit, resolvable repository, successful materialization,
and its recorded tree-integrity identity (full or sampled). Exact Git parity
and a full-tree identity are required only when an
observation-plan execution candidate is promoted to BTS/relocation/rerun. If
that promotion fails, the task still records C3 discovery/ranking evidence, but
its canonical run record carries the typed execution failure and marks every
execution-dependent metric not applicable with that same reason. Other tasks
continue; no sampled or drifted candidate is executed.

## Observation chain

The task runner captures candidate identities before grading, builds a minimal
empty-recipient profile, and derives its capability specification only from the
task's `python.callable.sync@v1` behavior identifier. It evaluates the real
materialized candidate/license evidence through C3a suitability and C3b Best-3;
gold qrels remain available only to the benchmark grader.

## Scope notes

The donor corpus deliberately does **not** claim a real pure varint decoder or
an LRU maxsize-eviction operation. Round-1 `REPORT.md` records rejected
accumulator-rebinding varint loops and `memo.pop`/class-method eviction paths.
Round-2 `REPORT2.md` extends the varint search by about twenty implementations
and reports zero recursive production matches, and summarizes the additional
LRU-eviction search (classes, closures, method dispatch, and an AGPL exclusion).
Thus `binary-wire-decode` uses fixed-width/cursor primitives and
`lru-ttl-decisions` uses TTL decisions; their missing mutation steps are honest
recipient adaptations, not asserted donor provenance.

The binary-wire seed calls `unpack_le_uint32_from` at
`electrumx/lib/tx.py:144`, bound by its `from electrumx.lib.util import ...`
at line 36.  The conservative Python graph emits that binding as the declared
external `electrumx.lib.util`; the per-task policy therefore records it as a
`pinned-exact` external requirement.  `struct` and `zlib` remain the only
stdlib allowlist entries; no implicit builtin or module authorization was added.

`worker-shutdown-predicate` is a permanent honest partial: the pinned mypy donor
contains 1,921 files, which exceeds the verification cap, so materialization was
sampled and an exact-parity snapshot is structurally unavailable. Its discovery
and ranking metrics are real; execution-dependent metrics are
NA-with-reason `bts_cli_parity_v1` rather than claimed as an execution result.
