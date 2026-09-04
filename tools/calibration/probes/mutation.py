"""Sampled mutation testing with a confidence interval on the kill rate."""

from __future__ import annotations

import json
import random
import time
from collections import defaultdict

from ..ledger import Finding
from ..mutation import (
    ERROR,
    INTEGRITY_MODULES,
    KILLED,
    SURVIVED,
    TIMEOUT,
    Mutant,
    MutantOutcome,
    TestSelector,
    enumerate_mutants,
    run_mutant,
    run_pytest,
    severity_for,
    target_files,
)
from ..stats import wilson_interval
from . import ProbeContext, ProbeResult


def _sample(mutants: list[Mutant], size: int, rng: random.Random) -> list[Mutant]:
    """Weighted sample without replacement: integrity modules and raise-drop mutants count triple."""
    if size >= len(mutants):
        return list(mutants)
    pool = list(mutants)
    weights = [(3.0 if mutant.module in INTEGRITY_MODULES else 1.0) * (3.0 if mutant.operator == "raise-drop" else 1.0) for mutant in pool]
    chosen: list[Mutant] = []
    while pool and len(chosen) < size:
        index = rng.choices(range(len(pool)), weights=weights, k=1)[0]
        chosen.append(pool.pop(index))
        weights.pop(index)
    return chosen


def probe(context: ProbeContext) -> ProbeResult:
    result = ProbeResult("mutation", "ok")
    repo_root = context.repo_root
    rng = random.Random(context.option("seed", 0))
    sample_size = int(context.option("mutants", 200))
    budget = float(context.option("mutation_budget", 3600))
    modules = context.option("modules")

    files = target_files(repo_root, modules)
    all_mutants: list[Mutant] = []
    for path in files:
        all_mutants.extend(enumerate_mutants(repo_root, path))
    result.metrics["enumerated"] = len(all_mutants)
    result.metrics["files"] = len(files)
    if not all_mutants:
        result.status = "skipped"
        result.notes.append("no mutants enumerated")
        return result

    contexts_path = context.state_dir / "coverage-contexts.json"
    selector = TestSelector.build(repo_root, contexts_path)
    result.metrics["selection_mode"] = "contexts" if selector.precise else "static"
    if not selector.precise:
        result.notes.append("no coverage contexts available; using static import mapping (run the coverage probe first for precise selection). Survivors in static mode may be reachable by CLI-level tests the mapping did not select; confirm with `calibrate.py mutant <id> --run` after a coverage run.")

    by_id = {mutant.id: mutant for mutant in all_mutants}
    retested: set[str] = set()
    recheck: list[Mutant] = []
    for entry in context.open_for("mutation"):
        if entry.get("category") != "surviving-mutant":
            continue
        identity = str(entry.get("evidence", {}).get("identity"))
        retested.add(identity)  # drifted source (id no longer enumerable) retires the finding honestly
        mutant = by_id.get(identity)
        if mutant is not None:
            recheck.append(mutant)
    result.metrics["rechecked"] = len(retested)
    result.retested = retested
    sample = recheck + [mutant for mutant in _sample(all_mutants, sample_size, rng) if mutant.id not in retested]
    # Group by selected test set so one control run validates many mutants.
    groups: dict[tuple[str, ...], list[tuple[Mutant, str]]] = defaultdict(list)
    uncovered: list[Mutant] = []
    for mutant in sample:
        tests, mode = selector.select(mutant)
        if not tests:
            uncovered.append(mutant)
        else:
            groups[tests].append((mutant, mode))

    outcomes: list[MutantOutcome] = []
    started = time.monotonic()
    control_failures = 0
    exhausted = False
    for tests in sorted(groups, key=lambda key: (len(groups[key]), key), reverse=True):
        if time.monotonic() - started > budget:
            exhausted = True
            break
        exit_code, control_duration, tail = run_pytest(repo_root, tests, timeout=max(900.0, budget / 3))
        if exit_code is None:
            control_failures += 1
            result.notes.append(f"control run timed out for {len(tests)} tests starting {tests[0]}; {len(groups[tests])} mutants skipped (raise --mutation-budget)")
            continue
        if exit_code != 0:
            control_failures += 1
            result.notes.append(f"control run failed (exit {exit_code}) for {len(tests)} tests starting {tests[0]}; {len(groups[tests])} mutants skipped")
            result.findings.append(
                Finding(
                    "mutation",
                    "control-failure",
                    "high",
                    "selected tests do not pass on unmutated source (flaky or order-dependent)",
                    tests[0],
                    {"identity": ",".join(tests)[:200], "exit_code": exit_code, "tail": tail[-800:]},
                    "PYTHONPATH=src python -m pytest -q -x " + " ".join(tests[:5]),
                )
            )
            continue
        timeout = max(30.0, 3.0 * control_duration + 5.0)
        for mutant, mode in groups[tests]:
            if time.monotonic() - started > budget:
                exhausted = True
                break
            outcome = run_mutant(repo_root, mutant, tests, mode, timeout=timeout)
            outcomes.append(outcome)
            context.log(f"  {outcome.outcome:8s} {mutant.describe()[:110]}")
        if exhausted:
            break
    if exhausted:
        result.notes.append(f"budget of {budget:.0f}s exhausted after {len(outcomes)} mutants")

    counts = {KILLED: 0, SURVIVED: 0, TIMEOUT: 0, ERROR: 0}
    per_operator: dict[str, dict[str, int]] = defaultdict(lambda: {"killed": 0, "survived": 0})
    per_module: dict[str, dict[str, int]] = defaultdict(lambda: {"killed": 0, "survived": 0})
    for outcome in outcomes:
        counts[outcome.outcome] += 1
        if outcome.outcome in (KILLED, TIMEOUT):
            per_operator[outcome.mutant.operator]["killed"] += 1
            per_module[outcome.mutant.module]["killed"] += 1
        elif outcome.outcome == SURVIVED:
            per_operator[outcome.mutant.operator]["survived"] += 1
            per_module[outcome.mutant.module]["survived"] += 1
            result.findings.append(
                Finding(
                    "mutation",
                    "surviving-mutant",
                    severity_for(outcome.mutant),
                    f"tests blind to {outcome.mutant.operator}: `{' '.join(outcome.mutant.original.split())[:60]}` -> `{' '.join(outcome.mutant.mutated.split())[:60]}`",
                    f"{outcome.mutant.path}:{outcome.mutant.lineno}",
                    {"identity": outcome.mutant.id, "mutant": outcome.mutant.to_dict(), "tests": list(outcome.tests)[:20], "selection_mode": outcome.selection_mode},
                    f"python tools/calibrate.py mutant {outcome.mutant.id} --path {outcome.mutant.path}",
                )
            )
    tested = counts[KILLED] + counts[SURVIVED] + counts[TIMEOUT]
    killed = counts[KILLED] + counts[TIMEOUT]
    lower, upper = wilson_interval(killed, tested)
    result.metrics.update(
        {
            "sampled": len(sample),
            "executed": len(outcomes),
            "uncovered_in_sample": len(uncovered),
            "control_failures": control_failures,
            "killed": counts[KILLED],
            "timeout": counts[TIMEOUT],
            "survived": counts[SURVIVED],
            "error": counts[ERROR],
            "kill_rate": round(killed / tested, 4) if tested else None,
            "kill_rate_wilson95": [round(lower, 4), round(upper, 4)] if tested else None,
            "per_operator": dict(sorted(per_operator.items())),
            "per_module": dict(sorted(per_module.items())),
        }
    )
    (context.run_dir / "mutants.json").write_text(
        json.dumps({"outcomes": [outcome.to_dict() for outcome in outcomes], "uncovered": [mutant.to_dict() for mutant in uncovered]}, indent=1, sort_keys=True),
        encoding="utf-8",
    )
    return result
