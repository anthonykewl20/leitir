# Single-shelf spec resolution (#279): before/after measurement

**Date:** 2026-08-30 · **Scope:** measurement of the two-phase resolution fix
to `corpus.find_materialized_sources` (issue #279), plus output-equivalence
verification. Companion to the fix itself; framing in
[ADR-0035](../adr/0035-warm-process-invalidation-contract.md) (Findings 2/3 of
`docs/evidence/warm-mode-premise-2026-08-27.md` are the defect's discovery
measurements).

## Method

Same real corpus as the premise report: `~/.leitir`, now 178 entries in
`sources.json` (128 distinct repos), shelves under `repos/github.com/**`.
`PYTHONPATH=src`, `python3`, page cache warm from an immediately preceding
identical run (both variants measured in the warm state; the dominant cost is
CPU-side path/hash work, so cold-cache runs only add noise). Timing via
`/usr/bin/time`; each variant run twice, second run reported.

- **Before** = `main` at `4ce19e7` with only `src/leitir/corpus.py` reverted
  (`git stash push src/leitir/corpus.py`), i.e. the
  verify-everything-then-filter `find_materialized_sources`.
- **After** = the same worktree with the two-phase fix applied
  (identity-resolve against catalog entries, then verify only candidates).
- Everything else identical between the two runs (the #281 logging changes
  were present in both; they do not touch this path).

## Results

`leitir info <spec> --brief`, one shelf per spec:

| Spec | Before | After | Output |
|---|---|---|---|
| `Chocobozzz/PeerTube@30eb3cc4…` | 107.74s | 1.98s | byte-identical (`cmp`) |
| `DavidAnson/markdownlint@3f1f4793…` | 102.26s | 0.64s | byte-identical (`cmp`) |

The remaining ~2s / ~0.6s is the single shelf's own ADR-0006 verification
plus the verb's work — the part the contract requires keeping.

`cProfile` on the before-path (premise report, Finding 2) attributed ~99% of
`read_valid_manifest` time to `verify_materialized_integrity`; the fix removes
all but the matched shelf's instance of that call (asserted by test:
`tests/test_corpus_cli.py::test_find_materialized_sources_verifies_only_the_matching_shelf`
counts `read_valid_manifest` invocations — exactly one for a six-shelf corpus
and an exact `owner/repo@sha` spec).

## Equivalence checks

- Byte-identical `--brief` stdout on the real corpus for both specs above
  (before vs. after).
- The full `tests/test_corpus_cli.py` + `tests/test_info.py` suites pass
  unchanged, including the existing tag-, version-, bare-name-, and
  ambiguity-matching tests that pin `record_trust`/`info._source` semantics
  on top of `find_materialized_sources`.
- Fail-closed preserved on the served shelf: a tampered matching shelf still
  raises (`test_find_materialized_sources_still_rejects_tampered_match`);
  ADR-0006 load-time verification of what a command serves is not weakened.

## Documented deltas (shelves the command does not serve)

1. A manifest that is invalid on a *non-candidate* shelf no longer fails the
   whole lookup — it never affected the served result. Pinned by
   `test_find_materialized_sources_skips_unrelated_invalid_shelf`.
2. A hand-written `ecosystem` manifest override contradicting the entry's
   registry host no longer matches; no producer writes such an override, and
   a catalog/manifest disagreement of that shape is itself corruption (it
   also can no longer turn an otherwise-unambiguous lookup ambiguous). The
   entry-only prefilter is a conservative superset of the full predicate:
   it excludes an entry only on fields the full predicate reads from the
   entry itself (name, host, owner/repo slug, `ref_kind == "sha"` against the
   entry's `commit_sha`). Version, tag, branch, and manifest-level ecosystem
   decisions always keep the entry as a candidate.
