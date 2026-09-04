# Self-calibration loop: bounded blind-spot hunting with a convergence ledger

- Status: accepted
- Deciders: owner
- Date: 2026-09-04
- Technical Story: production-readiness calibration before public release
- Implementation: complete (v1 probes); the evolve step is the existing AGENTS.md loop

## Context and Problem Statement

All tracked issues are closed and the ADR-0002 scorecard decides `pass`, yet the
project has no automated way to find what it does not know: faults the suite
would not notice, inputs the kernels crash on, environment-dependent output,
untested fail-closed paths, or performance drift. Coverage percentages and a
green suite are necessary but say nothing about *sensitivity*. Before public
use the project needs a repeatable, self-driving calibration that surfaces
its own weak spots with quantified bounds and tracks whether they are shrinking.

## Decision Drivers

- Stdlib-only, deterministic, fail-closed conventions must apply to the tool itself.
- Claims must be bounded, not asserted: "no bugs found" is not a statement.
- The loop must feed the existing agent workflow (probe → red test → fix → PR) rather than replace it.
- Findings must have stable identities so convergence and regression are visible across runs.
- The existing scorecard consumes a mutmut evidence slot that covers a single module; broad mutation evidence was missing.

## Considered Options

- Extend `tools/score_engine.py` with more collectors.
- Adopt third-party tooling (mutmut, hypothesis, atheris) as dev dependencies.
- A separate stdlib harness (`tools/calibrate.py`) with pluggable probes and a tracked ledger.

## Decision Outcome

Chosen option: a separate stdlib harness with pluggable probes and a tracked
ledger, because the scorecard is an *assessment* (fixed policy, pinned tools,
canonical envelope) while calibration is *exploration* (fresh seeds, sampled
mutants, generators that evolve). Mixing them would either destabilise the
scorecard's provenance or freeze the calibration's search. Third-party
mutation/fuzz tools would add dependencies and hide the oracles the project
cares about (tamper detection, permutation invariance, error taxonomy).

Contracts:

- Probes observe; they never fix. The mutation probe is the only one that
  touches `src/`, transiently, with byte-exact restore and a dirty-tree guard.
- Every finding has a stable identity; the ledger transitions
  `open → fixed → regressed` only on evidence from a run that executed the
  same probe.
- Every quantitative claim carries a bound: Wilson interval on mutation kill
  rate, rule-of-three and Good-Turing estimates on fuzz targets, median+3·MAD
  band on timing.
- The blind-spot index (weighted open findings) is the objective; the
  convergence criterion for a budget is `K` consecutive fresh-seed runs
  observing nothing new.
- `run` fails CI only on *new or regressed* findings at or above a chosen
  severity, never on the known backlog.

### Positive Consequences

- Real defects were surfaced on the first smoke run (trust scoring crashes on
  non-hashable manifest fields; a regex shape that evades the ReDoS guard and
  hangs; fail-closed rejections in the spec parser that no test asserts).
- Test adequacy gains an actual sensitivity measure rather than a coverage proxy.
- The report and ledger are tracked, so the convergence history is public evidence.

### Negative Consequences

- Sampled mutation testing is statistical; the interval, not the point, is the claim.
- Generators can be shallow; the per-target "rejected by design" ratio and Good-Turing mass are reported precisely so generator weakness is itself visible.
- A full run is long (suite + coverage + mutation budget); the nightly workflow carries it, not the PR lane.

## Links

- [docs/calibration.md](../calibration.md) — operation and how to read findings
- [ADR-0002](0002-deterministic-evidence-scoring-engine.md) — the assessment half
- [AGENTS.md](../../AGENTS.md) — the fix half of the loop
- Hermes Agent self-evolution (GEPA-style constraint-gated evolution with human review) — the shape borrowed for proposal → gate → review
