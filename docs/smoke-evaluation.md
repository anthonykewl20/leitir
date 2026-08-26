# Smoke evaluation (`smoke-v1`) — Historical (Removed)

> **ARCHIVED — This feature has been permanently removed.** The `leitir eval` 
> command and the `smoke-v1` benchmark (`benchmarks/smoke-v1/`) were deleted in 
> ADR-001 slice P0r, along with the orchestrator, Docker sandbox, and OpenRouter 
> call infrastructure they required. **Do not attempt to run the commands below — 
> they will fail.** This document is retained only for historical reference.
> 
> **Current evaluation approach:** The pinned retrieval benchmark is now 
> implemented as `leitir bench`, scored by 
> [ADR-0002 S4](adr/0002-deterministic-evidence-scoring-engine.md). See that 
> document for the current benchmark design.
> 
> **Planned evaluation system:** The evidence-scoring engine described in 
> ADR-0002 S4 provides the foundation for the full evaluation system tracked in 
> issue #266, items E2 and E3.

## What existed (no longer operational)

The `smoke-v1` benchmark was a **four-task Python smoke sample**. It used the 
live orchestrator, Docker sandbox, and paid OpenRouter calls to run tasks through 
the `FiveStepOrchestrator.run` workflow. The loader accepted 3–5 tasks and did 
not establish the PRD performance targets.

### Removed commands (archived for reference only)

The following commands **no longer exist** in the codebase and cannot be run:

```bash
# ARCHIVED — DO NOT RUN
LEITIR_ENABLE_LIVE_EVAL=1 leitir eval
```

The `leitir eval` command has been removed. The gating environment variable 
`LEITIR_ENABLE_LIVE_EVAL` no longer has any effect.

### Removed testing approach

Offline testing previously used:

```bash
# ARCHIVED — eval tests are removed
python -m pytest tests/test_evaluation.py
```

These tests, which injected fake run operations, have been removed with the 
broader evaluation infrastructure. The repository's test suite remains.

## Historical reference — Task and outcome design (archived)

This section documents the design of the `smoke-v1` benchmark for reference only.

### Task structure

The manifest version was `smoke-v1`. Every task recorded:

- dependency and version;
- evidence date and intended evidence Tiers 1–3;
- Python/Docker/pytest policy;
- validity; and
- an evaluator-only hidden-test identity.

`prompt.md` was the only generation-visible task text. The sibling
`hidden/eval_test.py` was mounted read-only into Step 5 through the evaluator
seam. Its path, source, assertions, output, and source-derived diagnostics were
not copied into the workflow request, synthesis/repair prompts, replay
artifacts, or candidate workspace.

The four bundled tasks varied evidence dates and tier needs. All were Python and
ran only Docker `pytest`; there were no Cargo, Go, or headless-browser tasks.

### Report structure

The report separated:

- `first_pass_pass`;
- `repaired_pass`;
- `valid_failure`;
- `spend_cap_termination`; and
- `infrastructure_invalid`.

Infrastructure error/cancellation or any invalid sandbox span made the run
infrastructure-invalid. A spend-cap run was counted separately only when
otherwise valid. Invalid manifest tasks were not run and counted as metric
exclusions.

### Metrics (archived reference)

Each metric contained its raw numerator, denominator, excluded-run count,
`benchmark_version`, and percentage. Percentage was `null` when the
denominator was zero.

- **SER (Search Efficiency Ratio):** retained first-synthesis evidence tokens
  divided by total cleaned first-synthesis evidence tokens, aggregated across
  valid runs. Infrastructure-invalid runs and runs with absent/zero accounting
  were excluded.
- **DRI (Door Resolution Index):** accepted runs whose highest cited evidence
  tier was Tier 1 or 2, divided by accepted runs with resolvable cited-tier
  data. The distribution separately reported Tier 1 alone, Tiers 1–2, and
  Tiers 1–3. All other tasks were excluded.
- **FPCR (First-Pass Compilation Rate):** valid started runs whose first Step 5
  sandbox span passed, divided by all valid started runs.
- **SCCR (Self-Correction Convergence Rate):** runs accepted on attempts 2–4,
  divided by valid runs whose first Step 5 span failed. Runs outside that
  correction population were excluded.

Provider usage reported a known sum, reported-run count, and missing-run count
for cost, prompt tokens, completion tokens, and reasoning tokens. Missing
provider values were not converted to zero. The policy section reported model
call count, review call count (expected: zero), and reasoning-policy
violations.

The report included a small-sample notice. Results were diagnostic only and
must not be presented as validation of the full 50-task suite or production
quality.

Historical service prerequisites, spend-cap semantics, and Docker isolation 
details were previously documented in [operations.md](operations.md).
