# Deterministic assembly of bounded, explainable usage evidence

- Status: accepted
- Deciders: leitir usage-evidence-pipeline contributors
- Date: 2026-08-25
- Technical Story: issue #258 (blocked by #255-#257, blocks #259)

## Context and Problem Statement

`#257`'s resolver, `#256`'s admission/import-catalog gates, and `#255`'s
frozen contract each produce their own typed evidence in isolation. Nothing
yet combines them into one final, presentable report: ranking usage sites
by relevance, collapsing evidence that describes the same logical usage
without losing any of it, bounding the output, and attaching advisory
per-snippet license information. That combination step needs its own
deterministic rules, because a downstream consumer (`#259`'s CLI) needs a
report that is byte-stable across runs, never silently drops evidence, and
never asserts more certainty (about ranking, dedup, or license) than the
inputs actually support.

## Decision Drivers

- Ranking must be explainable: a caller must be able to see *why* one
  usage site outranked another, not just a bare number.
- Two pieces of evidence about the same usage site (the same distribution
  at the same source span) must collapse into one result, but every
  originating provenance record must survive -- including when two pieces
  of evidence disagree (conflicting provenance), which must never be
  silently merged or picked-one.
- Every bound (result count, provenance-per-result, license-snippets-per-
  result, total payload bytes) must be enforced without exceeding it and
  without silently truncating evidence that the "never drop provenance"
  rule protects.
- License evidence is advisory only, per the frozen contract's
  `LicenseSnippetEvidence.advisory` invariant (`#255`): never claim a
  definite SPDX id for content with no explicit marker.
- The frozen contract (`contract.py`, `_canonical.py`, `errors.py`) and the
  upstream modules (`admission.py`, `import_catalog.py`, `resolver.py`) are
  out of scope for this issue; the assembler must compose them through
  their existing public surface only.

## Considered Options

- Extend the frozen `UsageReport` schema directly with ranking/provenance
  fields (rejected -- `contract.py` is explicitly out of scope for #258).
- Silently truncate or de-duplicate to whichever cap constant applies,
  keeping only one representative of a duplicate/conflicting group
  (rejected -- SP-1 explicitly forbids dropping duplicate provenance).
- Wrap the frozen `UsageReport` in a new, purely additive
  `AssembledEvidenceReport` that carries ranking, provenance, and capping
  as its own typed, versioned dataclasses, and represents genuinely
  cap-exceeded or conflicting identities via the frozen contract's
  existing extension points (`CoverageRecord`/`CoverageSummary.exclusions`
  strings, and the already-closed `UnresolvedState.CAP_EXCEEDED` /
  `AMBIGUOUS_BINDING` members) (chosen).

## Decision Outcome

Chosen option: `src/leitir/usage/assemble.py`'s `assemble_usage_evidence`
takes one or more `ReferenceBatch`es (typed resolver output tagged with a
human-readable origin), the upstream `ImportMapping`s and
`UnresolvedDistribution`s, and produces an `AssembledEvidenceReport`
wrapping a normal, frozen-contract `UsageReport` plus:

- **Explainable ranking.** Every `UsageResult` carries a `ScoreExplanation`
  with one named `ScoreComponent` per signal (`conflicting_penalty`,
  `license_confidence`, `provenance_count`, `span_width`), each with its
  weight, raw value, and contribution, evaluated in a fixed alphabetical
  order. Ties break on a `tie_break_key` derived only from the result's own
  identity fields (distribution, file, zero-padded line/col), never
  insertion or hash order.
- **Provenance-preserving, identity-keyed dedup.** The dedup identity is
  `(distribution, span.file, span.start_line, span.start_col, span.end_line,
  span.end_col)` -- the same distribution at the same source span is the
  same logical usage regardless of which `ReferenceBatch` reported it.
  Every occurrence becomes one `ProvenanceRecord` (origin + `code_digest`);
  none are ever dropped. `conflicting` is derived, not asserted
  independently: `True` exactly when the retained provenance disagrees on
  `code_digest`. A conflicting identity is excluded from the underlying
  `UsageReport.references` (no single digest could honestly represent it)
  but is fully retained, and surfaced, in `results` plus an
  `AMBIGUOUS_BINDING` coverage record.
- **Bounded results without dropping provenance.** `MAX_RESULTS`,
  `MAX_PROVENANCE_PER_RESULT` are enforced by *exclusion*, never
  truncation: an identity whose provenance exceeds its cap, or that ranks
  outside the top `MAX_RESULTS`, moves -- with its full, untruncated
  provenance -- into `capped_results` and gets a `CAP_EXCEEDED` coverage
  record, rather than a truncated entry inside `results`.
  `MAX_LICENSE_SNIPPETS_PER_RESULT` is different: license snippets are
  genuinely optional/advisory extras, so exceeding that cap clips them to
  an empty tuple for that result plus a `CAP_EXCEEDED` record, which is
  acceptable because no provenance is lost. `MAX_TOTAL_OUTPUT_BYTES` is the
  one bound enforced by outright rejection
  (`UsageUnsupportedError`) rather than partial output, since there is no
  non-arbitrary way to keep "some" of an oversized payload.
- **Advisory, non-authoritative licensing.** A best-effort scan of a
  file's leading `MAX_LICENSE_SCAN_LINES` lines looks for an explicit
  `SPDX-License-Identifier: <id>` marker (`confidence="high"`); a weaker
  "license"-keyword hit without an explicit id is `confidence="medium"`
  with `license_guess="unknown"`; anything else -- including an unreadable
  or absent file -- is `confidence="low"`, `license_guess="unknown"`.
  Every emitted record has `advisory=True`, matching the frozen
  contract's `LicenseSnippetEvidence` invariant that this is never
  authoritative regardless of confidence level.
- **Explicit coverage.** `ReferenceBatch.coverage` records are merged
  (contradictory per-file states raise `UsageMalformedError` rather than
  picking one); `UnresolvedDistribution`s from `#256`'s `ImportCatalog` are
  folded into `CoverageSummary.exclusions` as
  `"unresolved-distribution:<name>:<state>"` strings -- the frozen
  contract has no dedicated field for this, so the existing, already-typed
  `exclusions` bag is the extension point used, per the wiring note left
  by `#256`. Every capped/conflicting identity also gets its own coverage
  record, so nothing about *why* the assembled report is incomplete is
  silently dropped.

### Positive Consequences

- No change to `contract.py`/`_canonical.py`/`errors.py`/`admission.py`/
  `import_catalog.py`/`resolver.py`: every extension point used
  (`CoverageSummary.exclusions`, the already-closed `CAP_EXCEEDED` /
  `AMBIGUOUS_BINDING` `UnresolvedState` members) already existed.
- `#259`'s CLI layer gets both a normal, replay-compatible `UsageReport`
  (`AssembledEvidenceReport.report`) and the richer ranking/provenance
  detail (`results`/`capped_results`) without needing to choose between
  them.
- Determinism is structural, not incidental: every grouping step sorts on
  content-derived keys before finalizing output, so behavior does not
  depend on `PYTHONHASHSEED`, dict/set iteration, or batch input order.

### Negative Consequences

- `AssembledEvidenceReport` is a second top-level shape alongside
  `UsageReport`, with its own schema-version literals to track; a future
  consumer must know to read `results`/`capped_results` for full
  provenance detail rather than assuming `report.references` alone is
  complete (a conflicting identity is deliberately absent from
  `report.references`).
- Folding `UnresolvedDistribution` into `CoverageSummary.exclusions` as a
  formatted string is a pragmatic reuse of an existing bag-of-strings
  field, not a structured type; a future issue that needs to parse it back
  out must agree on the `"unresolved-distribution:<name>:<state>"` format
  rather than getting a typed field.

## Links

- `docs/adr/0025-usage-evidence-and-replay-contract.md` -- the frozen
  contract this module builds `UsageReport`s against.
- `docs/adr/0026-conservative-admission-and-import-catalog.md` -- source of
  `ImportMapping`s and `UnresolvedDistribution`s.
- `docs/adr/0027-static-python-usage-resolver.md` -- source of the
  `CodeReference`/`CoverageSummary` evidence wrapped into `ReferenceBatch`es.
- Issue #258.
