# Conservative consumer admission and distribution-to-import-root cataloging

- Status: Accepted
- Deciders: leitir usage-evidence pipeline (issue #256)
- Date: 2026-08-25
- Technical Story: #256 (builds on #255's frozen contract, ADR-0025)

## Context and Problem Statement

The usage evidence pipeline (#255-#259) must never fabricate a claim about
what a consumer depends on, or which import roots a distribution provides.
Before any usage report can be assembled, two gates need to run ahead of it:
(1) admitting only consumers whose source is SHA-pinned and whose declared
dependencies are exact, verifiable pins, and (2) mapping each admitted
dependency's distribution name to the import root(s) it actually provides,
using only local, static evidence. How should these two gates be built so
that every rejection is typed and fail-closed, and every acceptance is
independently verifiable, without extending the frozen #255 contract?

## Decision Drivers

- Fail-closed: any doubt about a consumer's pin, a dependency's exact
  version, a digest, or a distribution's import root must reject or
  typed-unresolve, never guess.
- The frozen `leitir.usage` contract (dataclasses, error hierarchy, the
  closed `UnresolvedState` enum) must not be modified or extended.
- Admitted evidence must be retained byte-for-byte, not re-derived, so
  downstream stages (#257-#259) can trust it without re-verification.
- No network, no package installation, no `import`/`exec` of consumer or
  provider code, stdlib only.

## Considered Options

- Extend `UnresolvedState` with new members for "missing mapping" and
  "unsupported packaging shape".
- Reuse only the existing closed `UnresolvedState` members, repurposing
  `AMBIGUOUS_BINDING` and `UNSUPPORTED_SYNTAX` for the import-catalog's own
  ambiguity/unsupported-shape outcomes.
- Represent admission rejections as plain exceptions with ad hoc messages
  instead of the contract's typed error hierarchy.

## Decision Outcome

Chosen option: reuse the existing closed `UnresolvedState` members and the
existing typed error hierarchy (`UsageUnsupportedError`, `UsageTamperError`),
because the enum was deliberately frozen in #255 for exhaustive switching by
every downstream stage, and the error hierarchy already expresses exactly
the three failure shapes admission needs (structurally invalid input,
unsupported/out-of-policy shape, digest/byte mismatch).

`admission.py` admits a consumer only when: its ref is a full 40-hex SHA
pin (not a floating branch/tag/`HEAD`) and matches the ref recorded for it
out-of-band; its `requirements.txt` contains only exact `name==version`
lines (no ranges, wildcards, bare names, markers, extras, or VCS/URL
requirements); and the actual on-disk `requirements.txt` bytes match the
digest recorded for them out-of-band. A SHA/digest mismatch is
`UsageTamperError`; every other rejection is `UsageUnsupportedError`. An
admitted consumer's `AdmittedConsumer` retains the exact
`leitir.usage.DependencyEvidence` built from the verified bytes -- never a
re-derived copy -- plus a recorded parser identity/version.

`import_catalog.py` catalogs a batch of local `DistributionRecord` evidence
(declared roots + a source-kind tag, PEP 503-normalized for grouping) into
either a resolved `leitir.usage.ImportMapping` or a typed-unresolved
`UnresolvedDistribution`. Missing evidence and evidence from an unsupported
source kind both resolve to `UnresolvedState.UNSUPPORTED_SYNTAX`; two
distinct distribution names colliding after normalization, disagreeing
evidence sources for one distribution, or two distributions claiming the
same import root all resolve to `UnresolvedState.AMBIGUOUS_BINDING`. A
single coherent source declaring more than one root is still resolved (a
legitimate multi-root distribution) -- multi-root is not itself ambiguous.

### Positive Consequences

- No changes to the frozen contract; #257-#259 can rely on it unchanged.
- Every rejection carries a machine-readable `.to_json()` payload consistent
  with the rest of the pipeline.
- The `UnresolvedState` enum stays exhaustively switchable by the resolver
  (#257) without a new, catalog-only member to special-case.

### Negative Consequences

- `UNSUPPORTED_SYNTAX` is now overloaded across two different domains
  (resolver code-parsing shapes, and catalog evidence shapes); the
  `UnresolvedDistribution.reason` field carries the human-readable
  distinction since the enum value alone cannot.
- "Missing mapping" and "genuinely unsupported packaging" are not
  distinguishable by `state` alone, only by `reason` text.

## Known limitation

`UnresolvedState.UNSUPPORTED_SYNTAX` has exactly one other producer in the
whole `leitir.usage` package: the static resolver (`resolver.py`), where it
means "the Python source did not parse" (a `SyntaxError`/cap-exceeded
condition). `import_catalog.py` reuses the same enum member (see the
`# NOTE (known limitation, ...)` comment at its two producer sites) for a
completely different condition -- "no usable local packaging evidence was
found for this distribution" (either an unsupported evidence-source kind,
or no evidence declaring any import root). A consumer branching on
`UnresolvedDistribution.state`/`CoverageRecord.state` alone cannot tell
these two apart; only `reason` (free text, always present) distinguishes
them.

This was a forced choice, not an oversight: the `UnresolvedState` enum was
frozen by #255 before #256 (this issue) existed, so no dedicated
"missing packaging evidence" member was available, and the enum is
explicitly closed for exhaustive switching downstream (#257-#259) --
extending it was out of this issue's file scope (see "Considered Options"
above). The nearest alternative, `AMBIGUOUS_BINDING`, would have been a
worse fit: it already has its own distinct, unrelated meaning here
(disagreeing evidence sources / colliding roots), and reusing it for
"missing evidence" too would conflate three conditions under one member
instead of two.

**Consumers of catalog-sourced unresolved entries must read `.reason`
before acting on `.state` alone.** A future contract revision (updating the
frozen #255 enum, which would need coordinated changes across #256-#259)
should add a dedicated member -- e.g. something like
`MISSING_PACKAGING_EVIDENCE` -- so this overload can be retired.

## Pros and Cons of the Options

### Extend `UnresolvedState`

- Good, because each catalog outcome would get an exact, self-describing
  enum member.
- Bad, because it modifies a contract explicitly frozen in #255 and out of
  this issue's file scope; every downstream exhaustive `match`/`if` over the
  enum would need updating in lockstep.

### Reuse the closed enum (chosen)

- Good, because it requires no contract changes and keeps the enum's
  closure guarantee intact for #257's exhaustive switch.
- Bad, because two states must each cover more than one conceptual case,
  pushed into the `reason` field instead of the type.

### Ad hoc exceptions

- Good, because it would be the least code.
- Bad, because it would abandon the pipeline's single typed-error
  convention, breaking uniform `.to_json()` handling in the eventual CLI
  (#259).

## Links

- [ADR-0025](0025-usage-evidence-and-replay-contract.md) -- the frozen
  contract this ADR builds on.
- Issue #256.
