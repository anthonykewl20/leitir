# Exit corpus v1 review record

This record is the content-bound review receipt for the substrate-independent
five-donor corpus assembled for issue #73. Its SHA-256 digest is copied into
every manifest case. A digest binds this record's content; it is not a claim of
self-ratification.

## Selection

The five highest-ranked candidates from `/tmp/opencode/donors/candidates.json`
were selected without substitution: they are five distinct GitHub repositories,
their recorded licenses are permissive, and their seed extraction verdicts are
complete at both the generous and mandated 4000-bps donor-source budgets. The
search record is `/tmp/opencode/donors/REPORT.md`; its machine-readable final
verification is `/tmp/opencode/donors/final_verification.json`.

Each pinned commit was fetched afresh with `git fetch --depth 1 origin <sha>`
and checked out detached during assembly on 2026-08-15. The resulting detached
HEADs exactly matched the pins. `git ls-remote <repo> <sha>` is not used as a
commit-existence proof because GitHub advertises refs rather than arbitrary
object IDs.

## Extractor outputs for selected seeds

The following are the selected-seed outputs from
`final_verification.json` (the source generator is
`leitir.graph.python.extract_static_edges` plus `leitir.bts.compute_bts`, as
recorded in `candidates.json`).

### mmcloughlin/luhn — `luhn.checksum`

```json
{"blockers":[],"counters":{"edges":0,"files":1,"nodes":1,"source_lines":9},"externals":[],"file":"luhn.py","members":["luhn.checksum"],"repo":"mmcloughlin/luhn","scope":"full-tree (3 py files)","seed":"luhn.checksum","sha":"c26e5c61fbc23006f265a71b9f87dac229e6ed99","status_bps4000":"complete","status_generous":"complete"}
```

### litl/backoff — `backoff._jitter.full_jitter`

```json
{"blockers":[],"counters":{"edges":1,"files":1,"nodes":1,"source_lines":11},"externals":["declared_external:function:random.uniform","declared_external:module:random"],"file":"backoff/_jitter.py","members":["backoff._jitter.full_jitter"],"repo":"litl/backoff","scope":"full-tree (18 py files)","seed":"backoff._jitter.full_jitter","sha":"d82b23c42d7a7e2402903e71e7a7f03014a00076","status_bps4000":"complete","status_generous":"complete"}
```

### niksite/url-normalize — `url_normalize.normalize_fragment.normalize_fragment`

```json
{"blockers":[],"counters":{"edges":2,"files":1,"nodes":1,"source_lines":20},"externals":["declared_external:function:url_normalize.tools.quote","declared_external:function:url_normalize.tools.unquote","declared_external:module:url_normalize.tools"],"file":"url_normalize/normalize_fragment.py","members":["url_normalize.normalize_fragment.normalize_fragment"],"repo":"niksite/url-normalize","scope":"full-tree (33 py files)","seed":"url_normalize.normalize_fragment.normalize_fragment","sha":"9a9a3214c2b3bdab09ba7b19c8f9d22aa4cfee31","status_bps4000":"complete","status_generous":"complete"}
```

### ubernostrum/webcolors — `src.webcolors._conversion.rgb_to_hex`

```json
{"blockers":[],"counters":{"edges":1,"files":1,"nodes":1,"source_lines":19},"externals":["declared_external:function:src.webcolors._normalization.normalize_integer_triplet","declared_external:module:src.webcolors._normalization"],"file":"src/webcolors/_conversion.py","members":["src.webcolors._conversion.rgb_to_hex"],"repo":"ubernostrum/webcolors","scope":"full-tree (15 py files)","seed":"src.webcolors._conversion.rgb_to_hex","sha":"ed4bad8daf26a0ad606d38732375b2f7cf72e57a","status_bps4000":"complete","status_generous":"complete"}
```

### topoteretes/cognee — `cognee.infrastructure.utils.calculate_backoff.calculate_backoff`

```json
{"blockers":[],"counters":{"edges":1,"files":1,"nodes":1,"source_lines":21},"externals":["declared_external:function:random.uniform","declared_external:module:random"],"file":"cognee/infrastructure/utils/calculate_backoff.py","members":["cognee.infrastructure.utils.calculate_backoff.calculate_backoff"],"repo":"topoteretes/cognee","scope":"package-dir (cognee/infrastructure/utils, 3 files)","seed":"cognee.infrastructure.utils.calculate_backoff.calculate_backoff","sha":"4b9dd362625dfd3621c344e571a86f5bc7a55ee8","status_bps4000":"complete","status_generous":"complete"}
```

## License findings

Freshly materialized `LICENSE` files were hashed and the digest was saved in
each `donor-meta.json`: luhn, backoff, and url-normalize are MIT; webcolors is
BSD-3-Clause; cognee is Apache-2.0. Donor source is deliberately not committed.

## Contract-test rationale and recorded baseline

The committed tests are Leitir-authored, import the relevant donor module, and
use only bare `test_*` functions with assertions. They exercise two stable
observations per seed: known-good/known-bad Luhn checksums, zero and bounded
full jitter, fragment Unicode and percent-escape normalization, canonical RGB
hex conversion, and zero-jitter exponential plus bounded-jitter backoff. They
do not rely on a fixed random sequence.

Each test file was run with pytest against a fresh detached checkout at its
pin. `PYTHONPATH` was the donor root except webcolors (`src`) and cognee
(`cognee/infrastructure/utils`); the latter avoids importing cognee's unrelated
dependency-heavy package initializer while importing the pinned donor module
itself. url-normalize was run after installing its pinned project's declared
runtime requirement, `idna>=3.3`. Recorded results: every case has 2 collected,
2 passed, 0 failed, and 0 skipped.

## Review trail and ratification boundary

The donor-search agent produced the evidence at the paths named above; this
assembly re-fetched every pin, authored the reduced contract tests, and
recorded their baseline. Independent review of this corpus occurs at PR time.
Per ADR-0017 corpus-non-self-ratification, final ratification is recorded
out-of-band in the issue tracker rather than in this self-authored record. The
manifest therefore leaves `ratified_manifest_digest` null until issue #73's
closure record binds its manifest content digest.
