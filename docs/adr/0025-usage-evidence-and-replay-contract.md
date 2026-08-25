# ADR-0025: Usage evidence and offline replay contract

- Status: Accepted
- Date: 2026-08-25
- Issue: [#255](https://github.com/anthonykewl20/leitir/issues/255)

## Context and Problem Statement

Leitir has no dedicated contract for describing *how a consumer project uses
a provider dependency*: which distribution maps to which import roots, which
source spans exercise it, whether resolution was clean or ambiguous, and
whether a license claim about a snippet is authoritative. Four upcoming
issues (#256 admission and the import catalog, #257 the static resolver,
#258 the evidence assembler, #259 the CLI, replay, and E2E) all need to
produce and consume this evidence, so the shape must be frozen before any of
them starts, or each will invent an incompatible ad hoc structure.

The evidence also has to survive being handed to a third party, or stored
and re-checked later, without re-trusting the tool that produced it: a
report must be replayable byte-for-byte from nothing but itself and the
original inputs, entirely offline, and any tampering with either the report
or the underlying corpus bytes must be caught before replay does anything
else with the input.

## Decision Drivers

- Downstream issues must be able to build against a stable data shape
  without waiting for admission, resolution, or assembly logic to exist.
- The schema must be closed (unknown/extra fields rejected, not ignored) so
  a malformed or forged payload cannot silently pass as valid.
- Coverage gaps (dynamic imports, star imports, ambiguous bindings,
  re-exports, unsupported syntax, cap overruns) must be typed and
  enumerable, not free-text, so a resolver can be written against an
  exhaustive switch.
- License evidence attached to a snippet must never be presented as
  authoritative; it is a hint for a human, not a legal determination.
- Replay must be safe to run against untrusted corpora: no network, no
  execution or import of consumer code, no writes outside test scratch
  space.

## Considered Options

- A single loosely-typed JSON blob validated with a generic schema library.
- Per-consumer bespoke report shapes, unified later by #258's assembler.
- A closed, versioned set of frozen dataclasses with an explicit
  parse/validate/replay API, defined once in `leitir.usage` and imported by
  every downstream issue. (Chosen.)

## Decision Outcome

Chosen option: **a closed, versioned dataclass contract in
`src/leitir/usage/`**, because it gives every downstream issue a stable,
type-checked surface immediately, and lets validation and replay share one
fail-closed implementation instead of five drifting reimplementations.

`src/leitir/usage/contract.py` defines:

- **Identities.** `Identity` (schema `leitir-usage-identity-v1`) is
  SHA-pinned via a `digest` field and carries an explicit `role` of either
  `"provider"` or `"consumer"`; a `UsageReport` requires exactly one of
  each, and the parser rejects a report where the roles are swapped or
  duplicated.
- **Dependency evidence.** `DependencyEvidence` carries the *exact*
  `requirements.txt` text, its raw-bytes digest, and the parser identity
  and version that produced it. The digest is checked against the text at
  three points: dataclass construction (`__post_init__`), closed-schema
  parsing (`report_from_dict`), and, most importantly, replay against the
  real on-disk file (`replay_report`) -- so an internally self-consistent
  but forged report is still caught once real bytes are available.
- **Distribution -> import roots.** `ImportMapping` is a closed,
  capped, deduplicated mapping from one distribution name to its import
  roots.
- **References.** `CodeReference` binds a `SourceSpan` (file, 1-indexed
  line, 0-indexed column ranges) to a `code_digest` computed over the exact
  span text, per distribution.
- **Coverage.** `CoverageSummary` holds `CoverageRecord`s (one per file),
  explicit `exclusions`, a bounded `cap`, and a `capped` flag. Each
  record's `state` is an `UnresolvedState` -- a closed `str, Enum` with
  members `resolved`, `dynamic-import`, `star-import`,
  `ambiguous-binding`, `re-export`, `unsupported-syntax`, and
  `cap-exceeded`. No other value is ever produced or accepted, so #257's
  resolver can switch on it exhaustively.
- **Licensing.** `LicenseSnippetEvidence.advisory` is a boolean that must
  be `True`; `advisory: false` is rejected as malformed, so the schema
  itself makes "this is a guess, not a determination" structurally
  impossible to violate.
- **Report digest.** `UsageReport.report_digest` is a `sha256:` digest over
  the canonical JSON of every other field (`recompute_digest`). It is
  checked at parse time, before any file is touched.
- **Versions.** Every structure embeds a `schema_version` literal
  (`leitir-usage-<name>-v1`); an unrecognized-but-well-typed version raises
  `UsageUnsupportedError` rather than being silently accepted or treated as
  a structural defect.

Errors are three disjoint, purpose-built classes in
`src/leitir/usage/errors.py`, each with `.to_json()` returning a
machine-readable dict: `UsageMalformedError` (structurally broken input),
`UsageUnsupportedError` (well-formed but an unsupported version/bound), and
`UsageTamperError` (a digest or byte sequence does not match what it must
match). `report_from_dict`/`report_from_json_bytes` never reach digest
comparisons before every structural check has passed, and `replay_report`
never touches a code span's bytes before the dependency evidence itself has
been confirmed to match the real `requirements.txt` on disk -- fail-closed
at every stage, not just at the end.

Replay (`replay_report`) takes the parsed report plus a `corpus_root` (for
source spans, read through `leitir.safeio.confined_path` +
`read_regular_file`) and an explicit `dependency_path` (for the pinned
`requirements.txt`, read the same way). It never imports or executes
anything from the corpus, performs no network access, and writes nothing;
on success it returns the same report object unchanged, proving the replay
was a verification and never a substitution.

## Fixture corpus

`tests/fixtures/usage/<case>/` holds one directory per required case --
`positive`, `alias`, `shadowing`, `ambiguous`, `unsupported`, `tamper`, and
`determinism` -- each with a self-describing `manifest.json`
(`leitir-usage-fixture-manifest-v1`), a `requirements.txt`, a `consumer/`
source tree, and a `report.json`. `tamper` is deliberately internally
self-consistent (its own `report_digest` validates) but its on-disk
`consumer/app.py` was altered *after* the report was produced, so only
offline replay against the real bytes -- not schema validation alone --
catches it; the manifest records `tamper_stage: "replay"` and
`expected_error: "UsageTamperError"` so the intent is discoverable, not
just asserted in test code. `tests/fixtures/usage/generate.py` is the
maintenance script that produced the corpus deterministically from the
`leitir.usage` package itself (same precedent as
`tests/fixtures/occupied_validate/generate.py`); tests discover cases from
disk rather than hardcoding the list, so #256-#258 can append cases without
touching this issue's test files.

## Consequences

### Positive Consequences

- #256-#259 have an immediately importable, type-checked, fully tested
  contract to build against; none of them need to define their own report
  shape.
- The closed-schema + typed-error split makes it possible to distinguish,
  from an error alone, whether a caller sent garbage, sent something this
  build does not yet support, or sent something that was tampered with --
  three different remediations.
- Fully offline replay means a report can be archived and re-verified years
  later without re-trusting the tool version that produced it, as long as
  the original corpus bytes are still available.

### Negative Consequences

- The schema is deliberately strict (closed dicts, capped collections, a
  fixed `UnresolvedState` enum); extending it for a new coverage state or
  evidence field is a schema-version bump, not a quiet field addition.
- `replay_report` re-reads every referenced source file from disk on every
  call (no cross-call caching beyond a single invocation's `source_cache`),
  which is the right trade-off for an offline verifier but is not free for
  reports with very large reference counts (bounded by `MAX_REFERENCES`).

## Links

- Issue [#255](https://github.com/anthonykewl20/leitir/issues/255)
- `src/leitir/usage/contract.py`, `src/leitir/usage/errors.py`,
  `src/leitir/usage/_canonical.py`
- `tests/test_usage_contract.py`, `tests/test_usage_fixtures.py`,
  `tests/fixtures/usage/`
