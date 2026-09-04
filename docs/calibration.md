# Self-calibration loop

`tools/calibrate.py` is Leitir's automated dogfood: it hunts for the
project's *own* blind spots and keeps a convergence ledger so every iteration
can be compared to the last. It is the operational half of ADR-0037; the
ADR-0002 scorecard remains the *evidence* half. The tool is stdlib-only,
imports no `leitir` code at module level, and never edits production source
except transiently inside the mutation probe (which restores bytes in a
`finally`).

## What "blind spot" means here

A blind spot is any behaviour the project cannot currently *see*: a fault the
tests would not notice, an input the kernels crash on, an output that depends
on the environment, a fail-closed path no test ever reaches, or a slowdown no
gate would catch. Each probe observes one class:

| probe | question it answers | evidence it produces |
|---|---|---|
| `static` | Do lint, types, and docs-truth hold? Where does output order or wall-clock leak in? | ruff/mypy results; `json.dumps` calls without `sort_keys`; clock reads outside time-owning modules |
| `suite` | Does the full offline suite pass? | JUnit report; each failure is a `critical` finding |
| `coverage` | Which fail-closed `raise` statements in integrity modules has no test ever executed? Did any module fall below its recorded floor? | branch coverage with per-test *contexts*, persisted for the mutation probe |
| `fuzz` | Do the pure kernels (spec parser, path confinement, tree hash, regex budget, search, ranking, trust, SPDX, lockfiles, license inference) crash, hang, misbehave, or violate their metamorphic contracts on seeded random inputs? | one finding per distinct failure signature, with a three-value reproducer |
| `determinism` | Are outputs byte-identical under different `PYTHONHASHSEED`, `TZ`, and locale? | digests of the same fuzz inputs from three subprocess environments |
| `mutation` | If a single semantic fault is planted, do the tests notice? | sampled mutants with the exact test set that failed to notice |
| `perf` | Did any hot path slow down relative to a stored baseline on this host? | median/MAD per benchmark against `calibration/perf-baseline.json` |
| `scorecard` (opt-in) | Does the ADR-0002 offline self-assessment still decide `pass`? | failed/unresolved checks |

## The mathematics of "almost zero"

The loop never claims "no bugs". It reports bounds:

- **Mutation kill rate with a Wilson 95% interval.** With `k` killed out of
  `n` sampled mutants the lower bound is the defensible test-adequacy claim.
  Sampling is weighted 3× toward integrity modules and 3× toward `raise-drop`
  mutants (a deleted fail-closed rejection is the fault class that matters most).
- **Rule of three.** A fuzz target with zero failures after `n` inputs has a
  true per-input failure rate below `3/n` at 95% confidence. Reported per target.
- **Good-Turing unseen mass.** `singletons / n` estimates the probability
  that the *next* input reveals a failure class nobody has seen. When this is
  near zero for every target, more random fuzzing at that distribution is no
  longer the best use of time; change the generator or the target instead.
- **Robust performance regression.** A regression needs both a median ratio
  above 1.25 *and* the candidate median outside the baseline's median + 3·MAD
  band, so one noisy run cannot flag anything.
- **Blind-spot index.** Weighted count of open, undispositioned findings
  (critical 20, high 8, medium 3, low 1, info 0). The loop's objective is to
  drive it to zero and keep it there; the report shows the index per run so
  convergence (or regression) is visible.

## The loop

```
observe  ->  ledger  ->  next  ->  fix (probe / red test / green)  ->  gates  ->  observe
```

1. **Observe.** `run` executes probes with a fresh seed (defaults to the run
   number, so each iteration explores new fuzz inputs and a new mutant sample
   while staying reproducible).
2. **Ledger.** Every finding has a stable identity. It is `open` while
   observed, `fixed` once a run that executed the same probe *re-tested* it
   and no longer observes it, `regressed` if it returns. Exhaustive probes
   (suite, static, coverage, determinism, perf) re-test everything by
   construction; the sampled probes (fuzz, mutation) first re-run every open
   finding's recorded reproducer and only then spend their budget exploring
   new seeds, so an unlucky sample can never retire a finding. Human dispositions (`accepted`,
   `equivalent`) silence noise without deleting evidence.
3. **Next.** `next` prints the highest-weight open findings as agent tasks,
   each with a reproducer. This is the hand-off to the AGENTS.md loop: probe
   with the reproducer, write the failing user-level intent test, make the
   smallest honest fix.
4. **Gates.** The full suite, `ruff`, `mypy`, and the determinism matrix are
   the constraint gates a fix must pass (the same "constraint gates, then human
   review" shape as reflective prompt-evolution systems such as GEPA: the
   loop proposes, evidence filters, a person merges).
5. **Observe again.** The ledger marks the finding fixed and reports the new
   index. `loop --until-stable K` repeats with fresh seeds until `K`
   consecutive runs observe nothing new at the current budget.

Fixes are pull requests, never automatic commits.

## Running on GitHub

`.github/workflows/calibration.yml` runs nightly (and on demand with a
probe/mutant override). No model, credentials, or network beyond GitHub are
involved: the observer is deterministic Python. After each run it calls
`calibrate.py issues`, which files one issue per **new** open finding at or
above `high` (capped at 10 per run), labeled `calibration`, `ready-for-agent`,
and `priority:<severity>`. The body carries the reproducer, evidence, and
acceptance criteria; a hidden `calibration-id:<id>` marker plus the number
written back into the ledger keep filing idempotent, so re-runs never
duplicate. When a later run re-tests a finding and marks it fixed, the tool
comments on the issue; it never closes issues (the fixing PR's `Closes #N` does).
Agents then work the `ready-for-agent` queue exactly as AGENTS.md describes.

Lower-severity findings stay in the ledger and `REPORT.md`; raise the bar
deliberately with `--min-severity medium` once the high backlog is empty.
The ledger and report changes made by the Actions run are uploaded as
artifacts rather than committed; commit them from a local run (or add a
bot-commit step) when you want the convergence history in git.

## Running it

Full run (needs the test lock plus the optional coverage/lint/type tools):

```bash
PYTHONPATH=src uv run --no-project --with-requirements requirements.txt \
  --with coverage==7.15.2 --with pytest-cov==7.1.0 --with ruff --with mypy \
  python tools/calibrate.py run
```

Smoke run in a few minutes:

```bash
PYTHONPATH=src uv run --no-project --with-requirements requirements.txt \
  python tools/calibrate.py run --quick --probes static,fuzz,determinism,perf
```

Useful variants:

```bash
python tools/calibrate.py run --probes mutation --modules treehash,safeio --mutants 150
python tools/calibrate.py run --probes fuzz --fuzz-targets trust,spec --fuzz-count 5000
python tools/calibrate.py loop --iterations 6 --until-stable 2
python tools/calibrate.py status
python tools/calibrate.py next --count 5
python tools/calibrate.py fuzz-repro --target trust --seed 1 --index 3
python tools/calibrate.py mutant <id> --path src/leitir/spec.py --run
python tools/calibrate.py disposition <id> equivalent --note "same observable behaviour"
```

`run` exits 1 when a **new or regressed** finding of severity ≥ `--fail-on`
(default `high`) appears, so CI fails on regressions but not on the known
backlog. The mutation probe refuses to run on a dirty `src/` unless
`--allow-dirty` is passed.

## Outputs

- `calibration/ledger.json` — tracked. The memory of the loop; history of runs
  and every finding's status.
- `calibration/REPORT.md` — tracked. Regenerated each run: convergence table,
  measurements with their bounds, open findings with reproducers.
- `calibration/perf-baseline.json` — tracked. Host-fingerprinted timing
  baseline; refresh with `--update-perf-baseline` on the reference host.
- `.leitir-calibration/runs/<id>/` — ignored. Full run JSON, JUnit, coverage
  contexts, mutant outcomes, fuzz details, logs.

## Reading a finding

Every ledger entry carries `probe/category`, severity, location, evidence,
and a reproducer command. Some categories and how to act:

- `surviving-mutant` — the listed tests ran against the mutated line and
  passed. Either add the assertion that would have failed, or mark the mutant
  `equivalent` if the change is genuinely unobservable.
- `uncovered-raise` — a fail-closed rejection in an integrity module that no
  test executes. Add the tamper/reject test AGENTS.md already requires.
- `fuzz-crash` — an exception outside the documented taxonomy escaped. Fail
  closed with the documented error instead (e.g. a manifest field of the
  wrong type must become `unknown`, not a `TypeError`).
- `fuzz-property` / `fuzz-nondeterministic` / `env-nondeterminism` — a
  contract (permutation invariance, tamper detection, idempotence, byte
  determinism) was violated. These are product bugs by definition.
- `fuzz-slow` with signature `:hang` — an input exceeded the hard deadline;
  for regex targets this is a ReDoS shape the guard did not recognise.
- `perf-regression` — confirm on the baseline host, then profile or refresh the baseline with justification.

## Extending

Add a fuzz target by appending a `Target` to `TARGETS` in
`tools/calibration/fuzz.py`: a seeded generator, a runner, the exception
types that are by design, and any metamorphic properties. Add a probe by
adding a module under `tools/calibration/probes/` and registering it in
`registry()`. Both are covered by `tests/test_calibration.py`.
