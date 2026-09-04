"""Seeded fuzzing with Good-Turing residual-mass and rule-of-three bounds per target."""

from __future__ import annotations

import json

from ..fuzz import TARGETS, FuzzFailure, check_input, fuzz_target
from ..ledger import Finding
from ..stats import good_turing_unseen_mass, rule_of_three
from . import ProbeContext, ProbeResult

_INTEGRITY_TARGETS = frozenset({"spec", "confined_path", "treehash", "trust", "spdx", "lockfiles", "regex_budget"})
_SEVERITY = {"crash": ("high", "medium"), "property": ("high", "high"), "nondeterministic": ("high", "high"), "slow": ("medium", "medium")}


def probe(context: ProbeContext) -> ProbeResult:
    result = ProbeResult("fuzz", "ok")
    seed = int(context.option("seed", 0))
    count = int(context.option("fuzz_count", 400))
    per_target_budget = float(context.option("fuzz_budget", 120))
    wanted = context.option("fuzz_targets")
    summary: dict[str, dict[str, object]] = {}
    total_inputs = 0
    total_failures = 0
    retested: set[str] = set()
    rechecks: dict[str, list[FuzzFailure]] = {}
    # Re-examine every open finding at its recorded (seed, index) before exploring new inputs.
    for entry in context.open_for("fuzz"):
        evidence = entry.get("evidence", {})
        name = str(entry.get("location", "")).split(":", 1)[0]
        if name not in TARGETS or not isinstance(evidence.get("seed"), int) or not isinstance(evidence.get("index"), int):
            continue
        if wanted and name not in wanted:
            continue
        identity = str(evidence.get("identity"))
        retested.add(identity)
        for failure in check_input(TARGETS[name], evidence["seed"], evidence["index"]):
            rechecks.setdefault(name, []).append(failure)
    result.metrics["rechecked"] = len(retested)
    for name, target in TARGETS.items():
        if wanted and name not in wanted:
            continue
        outcome = fuzz_target(target, seed=seed, count=count, budget_seconds=per_target_budget)
        outcome.failures.extend(rechecks.get(name, []))
        total_inputs += outcome.executed
        total_failures += len(outcome.failures)
        signatures = outcome.signature_counts()
        first_by_signature: dict[str, FuzzFailure] = {}
        for failure in outcome.failures:
            first_by_signature.setdefault(failure.signature, failure)
        for signature, failure in sorted(first_by_signature.items()):
            integrity_severity, other_severity = _SEVERITY[failure.kind]
            severity = integrity_severity if name in _INTEGRITY_TARGETS else other_severity
            result.findings.append(
                Finding(
                    "fuzz",
                    f"fuzz-{failure.kind}",
                    severity,
                    f"{failure.kind} in {name}: {failure.detail[:120]}",
                    signature,
                    {
                        "identity": signature,
                        "occurrences": signatures[signature],
                        "seed": failure.seed,
                        "index": failure.index,
                        "input": failure.input_repr,
                        "detail": failure.detail,
                    },
                    f"python tools/calibrate.py fuzz-repro --target {name} --seed {failure.seed} --index {failure.index}",
                )
            )
        by_design_ratio = round(outcome.by_design / outcome.executed, 3) if outcome.executed else None
        summary[name] = {
            "executed": outcome.executed,
            "by_design": outcome.by_design,
            "by_design_ratio": by_design_ratio,
            "failures": len(outcome.failures),
            "distinct_signatures": len(signatures),
            "unseen_mass_good_turing": round(good_turing_unseen_mass(list(signatures.values()), outcome.executed), 4),
            "failure_rate_upper95_if_clean": round(rule_of_three(outcome.executed), 4) if not outcome.failures else None,
            "elapsed": round(outcome.elapsed, 2),
        }
        if by_design_ratio is not None and by_design_ratio > 0.95:
            result.notes.append(f"{name}: {by_design_ratio:.0%} of inputs rejected by design; generator explores little of the accepted space")
    result.metrics.update({"inputs": total_inputs, "failures": total_failures, "targets": summary})
    result.retested = retested
    (context.run_dir / "fuzz.json").write_text(json.dumps(result.metrics, indent=1, sort_keys=True), encoding="utf-8")
    return result
