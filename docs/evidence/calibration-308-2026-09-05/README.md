# Rejection diagnostic calibration #308

Observed on 2026-09-05 at source pin 73f57b6. The production rejection already existed; the previous assertion accepted any downstream rejection and missed deletion of the intended diagnostic. The strengthened caller-level assertion preserves the specific actionable rejection. No runtime behavior or dependency changed.

Actual mutation `5f2b304416c41125` survived before and was killed after. `ledger.json` was seeded with the original finding from Actions run 33941983549, then rechecked with the production mutation probe (zero new samples; the open finding is mandatory). Its status is fixed. This mutation check measures regression sensitivity, not real-provider E2E correctness. The separate live audit covers real provider behavior.
