# Differential evaluation harness (issue #266 E2/E3)

Leitir can currently prove it returns correct, pinned, deterministically
ordered, verifiable source. It cannot yet prove that an agent using leitir
*writes more correct code* than one using raw GitHub search. This directory
is the harness for that second claim -- the actual product claim -- and the
PRD section 6.2 metrics (SER, DRI, FPCR, SCCR, 0% hallucinated params) that
currently exist only as targets, implemented nowhere.

**No evaluation has been run with this harness.** It has only ever been
exercised with the offline deterministic stub runner
(`stub_runner.DeterministicStubRunner`), whose outputs are canned strings,
not model output. Do not treat any number this harness has ever printed
during development as a real score.

## Architecture

```
tasks.py          -- reads benchmarks/exit-corpus/ (read-only); splits every
                      task into PublicTask (safe for prompts) and
                      EvaluatorAssets (contract-test path/bytes, hidden)
runner.py          -- Arm enum (A/B/C) + the Runner protocol every backend
                      (stub or real) implements
prompt.py          -- builds prompts from PublicTask only; runtime leak scan
stub_runner.py     -- deterministic, offline, no-network runner for tests
contract_exec.py   -- shells out to `pytest` against a candidate, parses
                      JUnit XML (stdlib only)
check_bridge.py     -- shells out to `leitir check` for hallucinated-symbol
                      counts; never reimplements its API-surface logic
harness.py          -- orchestrates generate -> test -> repair-loop -> check
                      for every (task, arm)
report.py           -- assembles the structured JSON report and the
                      arms_compared (C - B) delta
```

## The three arms

Every task runs through three arms with the same model, prompt scaffold,
and repair budget:

- **A** -- no retrieval
- **B** -- raw web/GitHub search
- **C** -- leitir (`info`, `search`, `examples`, `api`, `check`)

The deliverable metric is `arms_compared` in the report: **C minus B**, not
either arm's absolute score.

## Task source

Tasks come from `benchmarks/exit-corpus/corpus-v1.1.json` and its five
donors' authored contract tests. This harness only *reads* that directory --
it never writes to it, and `tests/test_differential_eval.py` asserts the
manifest's content digest is unchanged after a run. See
`benchmarks/exit-corpus/README.md` for that corpus's own schema and
ratification protocol, which this harness does not touch or depend on.

## The evaluator seam

Contract tests are evaluator assets: their path, source, assertions,
output, and any source-derived diagnostics must never reach a generation
prompt, a repair prompt, a trace, a replay artifact, or the candidate
workspace. This is enforced structurally, not just documented:

1. `tasks.load_tasks` splits every task into `PublicTask` (provenance
   metadata only -- case id, seed module/qualified name, donor pin) and
   `EvaluatorAssets` (contract-test path + bytes). Every function in
   `prompt.py` that builds prompt text takes a `PublicTask`, never an
   `EvaluatorAssets` -- there is no parameter through which contract-test
   bytes could reach a prompt.
2. The repair loop's feedback (`runner.RepairSignal`) carries only
   pass/fail/error *counts*, not pytest stdout, assertion text, or any
   other source-derived diagnostic -- there is no string field to leak
   through.
3. `prompt.assert_no_evaluator_leak` is a runtime backstop: `harness.py`
   calls it on every rendered prompt payload before use, scanning for the
   literal bytes of every task's contract test. A leak raises
   `EvaluatorLeakError` and aborts the run rather than silently scoring it.
   `tests/test_differential_eval.py` pins this directly.

## Runner protocol and the offline stub

`runner.Runner` is a `Protocol` with `generate`/`repair` methods. The whole
harness is exercisable offline, with no network, no model credential, and
no paid call, via `stub_runner.DeterministicStubRunner`: it returns fixed
candidate source keyed only by `(case_id, arm, attempt)`, so results are
byte-identical across `PYTHONHASHSEED` values.

To plug in a real model runner, implement the same protocol against your
client of choice and pass an instance to `harness.run_all` in place of the
stub -- see the docstring in `runner.py` for a worked example. Nothing in
`GenerationRequest`/`RepairSignal` can carry evaluator-asset bytes, so a
real runner cannot leak hidden-test content even by accident.

## Metrics

Every metric is one of `Measured(value)` or `Unavailable(reason)`
(`metrics.py`) -- per ADR-0002, unknown is neither zero nor pass. The
report (`report.py`) includes, per task per arm:

- `first_pass_correct` / `post_repair_correct` (PRD FPCR/SCCR inputs) from
  the contract tests, via `contract_exec.py`
- `tokens_used` / `steps_used` (PRD SER's cost input)
- `hallucinated_symbol_count` / `check_status`, from shelling out to
  `leitir check` (`check_bridge.py`) -- **never reimplemented**. `check`
  exits 4 when it examined zero sites; this harness always records that as
  `Unavailable`, never as a clean 0.
- an `infrastructure_invalid` status (with reason) when the contract-test
  subprocess itself could not be run

Aggregated per arm: `fpcr` and `sccr`, each with numerator, denominator,
and excluded-run count (per PRD 6.3's verification requirement -- a bare
percentage is not evidence). `arms_compared` reports the C-minus-B delta
for FPCR, SCCR, mean token cost, and mean hallucinated-symbol count, each
`Unavailable` rather than fabricated when either side lacks enough measured
data.

## What is and is not measurable yet

**Computable by this harness today** (with a real runner plugged in):
FPCR, SCCR, token/step cost (the input to SER), hallucinated-symbol counts
via `leitir check`, and the C-minus-B `arms_compared` delta for all of
those.

**Not yet computable**:

- **SER** (Search Efficiency Ratio) needs the retained-vs-total *retrieval
  evidence token* accounting from Step 3/4 of a real orchestrator run. The
  stub runner's `tokens_used` is a prompt-length stand-in for a real
  provider `usage` value, not evidence-chunk accounting; a real runner must
  report that split for SER to be computed.
- **DRI** (Door Resolution Index) needs the four-tier evidence provenance
  a real leitir-backed arm C run would record (which tier resolved the
  task). The stub runner has no tiers; nothing here fabricates a
  distribution.
- The **0%-hallucinated-parameters** target is approximated by the
  `hallucinated_symbol_count` metric above but is not identical to the PRD
  wording (it is `leitir check`'s site-level verification, not a
  per-parameter audit).

## Running

```console
PYTHONPATH=src uv run --no-project --with-requirements requirements.txt \
    python -m pytest -q tests/test_differential_eval.py
```

There is no CLI entry point in this directory yet; `tests/test_differential_eval.py`
is the only current caller of `harness.run_all`, using
`stub_runner.DeterministicStubRunner`. A real evaluation run (with a real
model runner, real network access for `leitir check`, and a real spend
budget) is out of scope for this change and has not been performed.
