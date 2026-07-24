# Smoke evaluation (`smoke-v1`)

The v1 smoke benchmark contains four Python tasks. Each bundle records its
dependency/version, evidence date, intended Tiers 1–3, Docker pytest policy,
validity, and an evaluator identity. `prompt.md` is the only generation-visible
task input. The sibling `hidden/eval_test.py` is passed through the evaluator
seam and mounted read-only by Step 5; it is not copied into a request,
synthesis prompt, repair prompt, replay artifact, or candidate workspace.

The default CLI path is deliberately gated because it uses the live
orchestrator, Docker, network services, and paid model calls:

```bash
LEITIR_ENABLE_LIVE_EVAL=1 leitir eval
```

Normal `pytest` runs use a fake run operation and require none of those
services. Every live task still runs through `FiveStepOrchestrator.run`; the
evaluation module does not reproduce any workflow step or model request.

The emitted report includes SER, DRI, FPCR, and SCCR. Each metric has its raw
numerator, denominator, excluded-run count, benchmark version, and percentage
(or `null` when its denominator is zero). Provider usage reports known sums and
missing-run counts rather than changing missing values to zero. Outcome counts
separate first-pass passes, repaired passes, valid failures, spend-cap
terminations, and infrastructure-invalid runs. This four-task smoke sample is
diagnostic and cannot establish success on the full benchmark.
