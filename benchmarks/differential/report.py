"""Assembles the structured JSON report for one differential-eval run.

Every reported rate carries its numerator, denominator, and excluded-run
count (per PRD section 6.3's verification requirement), and every metric is
tagged measured/unavailable (see ``metrics.py``) -- never defaulted to a
number when it could not be computed.

The deliverable metric, ``arms_compared``, is the delta of arm C (leitir)
minus arm B (raw web/GitHub search); it is ``Unavailable`` wherever either
side lacks enough measured data, never silently computed from a partial set.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import TypedDict

from .harness import ArmRunResult, DifferentialRunResult
from .metrics import Measured, Metric, Unavailable, metric_to_json
from .runner import Arm


class RateAggregate(TypedDict):
    numerator: int
    denominator: int
    excluded_count: int
    percentage: float | None


class MeanAggregate(TypedDict):
    sum: int
    count: int
    excluded_count: int
    mean: float | None


class ArmAggregate(TypedDict):
    run_count: int
    scored_count: int
    infrastructure_invalid_count: int
    fpcr: RateAggregate
    sccr: RateAggregate
    tokens_used: MeanAggregate
    steps_used: MeanAggregate
    hallucinated_symbol_count: MeanAggregate


def _rate(
    results: list[ArmRunResult], selector: Callable[[ArmRunResult], bool | None]
) -> RateAggregate:
    """A pass-rate style aggregate: numerator / denominator over scored runs.

    ``selector`` returns ``None`` for a run that is scored but out of the
    metric's population (e.g. SCCR only counts first-pass *failures*).
    """

    numerator = 0
    denominator = 0
    excluded = 0
    for r in results:
        if r.status != "scored":
            excluded += 1
            continue
        included = selector(r)
        if included is None:
            excluded += 1
            continue
        denominator += 1
        if included:
            numerator += 1
    percentage = numerator / denominator if denominator > 0 else None
    return {
        "numerator": numerator,
        "denominator": denominator,
        "excluded_count": excluded,
        "percentage": percentage,
    }


def _mean_int(
    results: list[ArmRunResult], selector: Callable[[ArmRunResult], Metric[int]]
) -> MeanAggregate:
    values: list[int] = []
    excluded = 0
    for r in results:
        if r.status != "scored":
            excluded += 1
            continue
        metric = selector(r)
        if isinstance(metric, Unavailable):
            excluded += 1
            continue
        values.append(metric.value)
    mean = sum(values) / len(values) if values else None
    return {"sum": sum(values), "count": len(values), "excluded_count": excluded, "mean": mean}


def _fpcr(results: list[ArmRunResult]) -> RateAggregate:
    def selector(r: ArmRunResult) -> bool | None:
        assert isinstance(r.first_pass_correct, Measured)
        return r.first_pass_correct.value

    return _rate(results, selector)


def _sccr(results: list[ArmRunResult]) -> RateAggregate:
    def selector(r: ArmRunResult) -> bool | None:
        assert isinstance(r.first_pass_correct, Measured)
        if r.first_pass_correct.value:
            return None  # not a first-pass failure; outside the SCCR population
        assert isinstance(r.post_repair_correct, Measured)
        return r.post_repair_correct.value

    return _rate(results, selector)


def _aggregate_for_arm(run: DifferentialRunResult, arm: Arm) -> ArmAggregate:
    results = [t.arms[arm] for t in run.tasks]
    return {
        "run_count": len(results),
        "scored_count": sum(1 for r in results if r.status == "scored"),
        "infrastructure_invalid_count": sum(1 for r in results if r.status == "infrastructure_invalid"),
        # PRD 6.2 FPCR: first Step 5 attempt passes the complete contract suite.
        "fpcr": _fpcr(results),
        # PRD 6.2 SCCR: fails first valid attempt but passes within the repair budget.
        "sccr": _sccr(results),
        "tokens_used": _mean_int(results, lambda r: r.tokens_used),
        "steps_used": _mean_int(results, lambda r: r.steps_used),
        "hallucinated_symbol_count": _mean_int(results, lambda r: r.hallucinated_symbol_count),
    }


def _delta(c_value: float | None, b_value: float | None, *, unavailable_reason: str) -> dict[str, object]:
    metric: Metric[float]
    if c_value is None or b_value is None:
        metric = Unavailable(unavailable_reason)
    else:
        metric = Measured(c_value - b_value)
    return metric_to_json(metric)


def _arms_compared(run: DifferentialRunResult) -> dict[str, object]:
    b_agg = _aggregate_for_arm(run, Arm.RAW_SEARCH)
    c_agg = _aggregate_for_arm(run, Arm.LEITIR)
    return {
        "note": "C (leitir) minus B (raw web/GitHub search); the deliverable metric.",
        "fpcr_delta": _delta(
            c_agg["fpcr"]["percentage"], b_agg["fpcr"]["percentage"],
            unavailable_reason="fpcr percentage unavailable for arm B or C (zero-denominator population)",
        ),
        "sccr_delta": _delta(
            c_agg["sccr"]["percentage"], b_agg["sccr"]["percentage"],
            unavailable_reason="sccr percentage unavailable for arm B or C (zero-denominator population)",
        ),
        "mean_tokens_used_delta": _delta(
            c_agg["tokens_used"]["mean"], b_agg["tokens_used"]["mean"],
            unavailable_reason="mean token cost unavailable for arm B or C",
        ),
        "mean_hallucinated_symbol_count_delta": _delta(
            c_agg["hallucinated_symbol_count"]["mean"],
            b_agg["hallucinated_symbol_count"]["mean"],
            unavailable_reason="mean hallucinated-symbol count unavailable for arm B or C",
        ),
    }


def build_report(
    run: DifferentialRunResult,
    *,
    manifest_digest_before: str,
    manifest_digest_after: str,
    runner_name: str,
) -> dict[str, object]:
    """Assemble the full structured JSON report. Emits no fabricated numbers.

    ``manifest_digest_before``/``after`` let a caller assert the exit-corpus
    manifest was not mutated by this run (see ``tasks.manifest_digest``).
    """

    tasks_json = []
    for task in run.tasks:
        arms_json = {}
        for arm, result in task.arms.items():
            arms_json[arm.value] = {
                "status": result.status,
                "infra_reason": result.infra_reason,
                "first_pass_correct": metric_to_json(result.first_pass_correct),
                "post_repair_correct": metric_to_json(result.post_repair_correct),
                "repair_attempts_used": metric_to_json(result.repair_attempts_used),
                "tokens_used": metric_to_json(result.tokens_used),
                "steps_used": metric_to_json(result.steps_used),
                "hallucinated_symbol_count": metric_to_json(result.hallucinated_symbol_count),
                "check_status": metric_to_json(result.check_status),
            }
        tasks_json.append({"task_id": task.task_id, "arms": arms_json})

    return {
        "differential_eval_version": "v1",
        "runner": runner_name,
        "manifest_digest_before": manifest_digest_before,
        "manifest_digest_after": manifest_digest_after,
        "manifest_unchanged": manifest_digest_before == manifest_digest_after,
        "tasks": tasks_json,
        "aggregate_metrics": {arm.value: _aggregate_for_arm(run, arm) for arm in Arm},
        "arms_compared": _arms_compared(run),
    }


__all__ = ["build_report"]
