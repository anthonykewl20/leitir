# Smoke evaluation (`smoke-v1`)

The shipped v1 benchmark is a **four-task Python smoke sample**. The loader
accepts 3–5 tasks; this is not the planned 50-task benchmark and cannot
establish the PRD performance targets.

## Run it

The default command is deliberately gated because it uses the live
orchestrator, Docker, network services, and paid OpenRouter calls:

```bash
LEITIR_ENABLE_LIVE_EVAL=1 leitir eval
```

The value must be exactly `1`. Without it, the command fails with exit 3 before
the driver runs. There is no dry-run CLI flag. For a safe offline check, use:

```bash
leitir eval --help
python -m pytest tests/test_evaluation.py
```

The evaluation tests inject a fake run operation and need no Docker, network,
model credential, or paid call. The repository's full test suite separately
contains Docker sandbox integration tests.

Each valid task still runs through `FiveStepOrchestrator.run`; the evaluation
module does not reimplement workflow steps or model requests. Each task emits
its own normal trace. After all tasks, stdout includes a JSON report and a
driver-managed completion line. CLI exit 0 means the evaluation driver
completed, not that all four tasks passed.

## Versioned bundles and hidden boundary

The manifest version is `smoke-v1`. Every task records:

- dependency and version;
- evidence date and intended evidence Tiers 1–3;
- Python/Docker/pytest policy;
- validity; and
- an evaluator-only hidden-test identity.

`prompt.md` is the only generation-visible task text. The sibling
`hidden/eval_test.py` is mounted read-only into Step 5 through the evaluator
seam. Its path, source, assertions, output, and source-derived diagnostics are
not copied into the workflow request, synthesis/repair prompts, replay
artifacts, or candidate workspace. Hidden tests are evaluator assets; do not
publish or paste them into traces or reports.

The four bundled tasks vary evidence dates and tier needs. All are Python and
run only Docker `pytest`; there are no Cargo, Go, or headless-browser tasks.

## Outcomes

The report separates:

- `first_pass_pass`;
- `repaired_pass`;
- `valid_failure`;
- `spend_cap_termination`; and
- `infrastructure_invalid`.

Infrastructure error/cancellation or any invalid sandbox span makes the run
infrastructure-invalid. A spend-cap run is counted separately only when it is
otherwise valid. Invalid manifest tasks are not run and count as metric
exclusions.

## Metrics and exclusions

Every metric contains its raw numerator, denominator, excluded-run count,
`benchmark_version`, and percentage. Percentage is JSON `null` when the
denominator is zero.

- **SER (Search Efficiency Ratio):** retained first-synthesis evidence tokens
  divided by total cleaned first-synthesis evidence tokens, aggregated across
  valid runs. Infrastructure-invalid runs and runs with absent/zero accounting
  are excluded.
- **DRI (Door Resolution Index):** accepted runs whose highest cited evidence
  tier is Tier 1 or 2, divided by accepted runs with resolvable cited-tier
  data. The distribution separately reports Tier 1 alone, Tiers 1–2, and
  Tiers 1–3. All other tasks are excluded.
- **FPCR (First-Pass Compilation Rate):** valid started runs whose first Step 5
  sandbox span passed, divided by all valid started runs.
- **SCCR (Self-Correction Convergence Rate):** runs accepted on attempts 2–4,
  divided by valid runs whose first Step 5 span failed. Runs outside that
  correction population are excluded.

Provider usage reports a known sum, reported-run count, and missing-run count
for cost, prompt tokens, completion tokens, and reasoning tokens. Missing
provider values are not converted to zero. The policy section reports model
call count, review call count (expected: zero), and reasoning-policy
violations.

The report includes a small-sample notice. Results are diagnostic only and
must not be presented as validation of the full 50-task suite or production
quality.

See [operations.md](operations.md) for service prerequisites, spend-cap
semantics, the exact Hy3 policy, trace inspection, and Docker isolation.
