"""Orchestrates one differential-eval run across all three arms.

For each task, for each arm: build a generation prompt from the task's
``PublicTask`` view only, call the runner, run the contract tests (an
evaluator-only asset, read but never exposed to the runner), and -- on
failure -- run a bounded repair loop whose feedback is a count-only
``RepairSignal``. Every prompt payload built along the way is scanned by
``prompt.assert_no_evaluator_leak`` before use; a leak raises immediately
and aborts the run rather than silently producing a score.

This module never fabricates a metric. A task/arm whose contract-test
subprocess could not run at all is recorded ``infrastructure_invalid`` (all
its metrics ``Unavailable``), matching the archived smoke-eval convention
described in ``docs/smoke-evaluation.md``.
"""

from __future__ import annotations

import tempfile
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path

from .check_bridge import HallucinationMeasurement, run_leitir_check
from .contract_exec import ContractExecutionError, ContractRunOutcome, run_contract_tests
from .metrics import Measured, Metric, Unavailable
from .prompt import (
    PromptRecord,
    assert_no_evaluator_leak,
    build_generation_request,
    build_repair_request,
    render_payload,
)
from .runner import Arm, GenerationResult, RepairSignal, Runner
from .tasks import DifferentialTask, EvaluatorAssets, PublicTask

DEFAULT_REPAIR_BUDGET = 3


@dataclass(frozen=True)
class ArmRunResult:
    arm: Arm
    status: str  # "scored" | "infrastructure_invalid"
    infra_reason: str | None
    first_pass_correct: Metric[bool]
    post_repair_correct: Metric[bool]
    repair_attempts_used: Metric[int]
    tokens_used: Metric[int]
    steps_used: Metric[int]
    hallucinated_symbol_count: Metric[int]
    check_status: Metric[str]
    final_code: str | None


@dataclass(frozen=True)
class TaskRunResult:
    task_id: str
    arms: dict[Arm, ArmRunResult]


@dataclass(frozen=True)
class DifferentialRunResult:
    tasks: tuple[TaskRunResult, ...]
    prompt_trace: tuple[PromptRecord, ...]


def _sum_metric_int(values: list[Metric[int]]) -> Metric[int]:
    total = 0
    for v in values:
        if isinstance(v, Unavailable):
            return Unavailable("at least one attempt's cost accounting was unavailable")
        total += v.value
    return Measured(total)


def _run_one_arm(
    *,
    task: DifferentialTask,
    arm: Arm,
    runner: Runner,
    all_evaluator_assets: tuple[EvaluatorAssets, ...],
    repair_budget: int,
    check_corpus_root: Path,
    check_env_overrides: Mapping[str, str] | None,
    trace: list[PromptRecord],
) -> ArmRunResult:
    public = task.public
    evaluator = task.evaluator

    request = build_generation_request(public, arm, attempt=1)
    payload = render_payload(request)
    assert_no_evaluator_leak(payload, all_evaluator_assets)
    trace.append(PromptRecord(task.public.case_id, arm, "generate", 1, payload))

    result: GenerationResult = runner.generate(request)
    token_costs = [result.tokens_used]
    step_costs = [result.steps_used]

    try:
        outcome = run_contract_tests(
            candidate_code=result.code,
            seed_module=public.seed_module,
            import_roots=public.import_roots,
            evaluator=evaluator,
        )
    except ContractExecutionError as exc:
        return _infra_invalid(arm, str(exc))

    first_pass_correct = outcome.all_passed
    final_code = result.code
    final_outcome: ContractRunOutcome = outcome
    repair_attempts = 0

    attempt = 1
    while not final_outcome.all_passed and repair_attempts < repair_budget:
        attempt += 1
        repair_attempts += 1
        passed, failed, errored = final_outcome.to_repair_signal_counts()
        signal = RepairSignal(passed=passed, failed=failed, errored=errored)
        repair_request = build_repair_request(public, arm, signal=signal, attempt=attempt)
        repair_payload = render_payload(repair_request)
        assert_no_evaluator_leak(repair_payload, all_evaluator_assets)
        trace.append(PromptRecord(public.case_id, arm, "repair", attempt, repair_payload))

        repair_result = runner.repair(repair_request, final_code, signal)
        token_costs.append(repair_result.tokens_used)
        step_costs.append(repair_result.steps_used)
        try:
            final_outcome = run_contract_tests(
                candidate_code=repair_result.code,
                seed_module=public.seed_module,
                import_roots=public.import_roots,
                evaluator=evaluator,
            )
        except ContractExecutionError as exc:
            return _infra_invalid(arm, str(exc))
        final_code = repair_result.code

    hallucination = _measure_hallucination(
        public=public,
        final_code=final_code,
        check_corpus_root=check_corpus_root,
        check_env_overrides=check_env_overrides,
    )

    return ArmRunResult(
        arm=arm,
        status="scored",
        infra_reason=None,
        first_pass_correct=Measured(first_pass_correct),
        post_repair_correct=Measured(final_outcome.all_passed),
        repair_attempts_used=Measured(repair_attempts),
        tokens_used=_sum_metric_int(token_costs),
        steps_used=_sum_metric_int(step_costs),
        hallucinated_symbol_count=hallucination.hallucinated_symbol_count,
        check_status=hallucination.check_status,
        final_code=final_code,
    )


def _infra_invalid(arm: Arm, reason: str) -> ArmRunResult:
    return ArmRunResult(
        arm=arm,
        status="infrastructure_invalid",
        infra_reason=reason,
        first_pass_correct=Unavailable(reason),
        post_repair_correct=Unavailable(reason),
        repair_attempts_used=Unavailable(reason),
        tokens_used=Unavailable(reason),
        steps_used=Unavailable(reason),
        hallucinated_symbol_count=Unavailable(reason),
        check_status=Unavailable(reason),
        final_code=None,
    )


def _measure_hallucination(
    *,
    public: PublicTask,
    final_code: str,
    check_corpus_root: Path,
    check_env_overrides: Mapping[str, str] | None,
) -> HallucinationMeasurement:
    with tempfile.TemporaryDirectory(prefix="leitir-differential-check-") as workdir_str:
        workdir = Path(workdir_str)
        candidate_path = workdir / "candidate.py"
        candidate_path.write_text(final_code, encoding="utf-8")
        return run_leitir_check(
            candidate_path=candidate_path,
            against_spec=public.source_provenance,
            corpus_root=check_corpus_root,
            cwd=workdir,
            extra_env=check_env_overrides,
        )


def run_all(
    tasks: tuple[DifferentialTask, ...],
    runner: Runner,
    *,
    check_corpus_root: Path,
    repair_budget: int = DEFAULT_REPAIR_BUDGET,
    check_env_overrides: Mapping[str, str] | None = None,
) -> DifferentialRunResult:
    """Run every task through all three arms and return the full result set.

    ``check_env_overrides`` is forwarded to every ``leitir check`` subprocess
    call (see ``check_bridge.run_leitir_check``). Tests use it to redirect
    the network calls ``check`` would otherwise make to an unreachable
    address, so the harness is deterministic offline regardless of whether
    the host running it happens to have network access.
    """

    all_evaluator_assets = tuple(t.evaluator for t in tasks)
    trace: list[PromptRecord] = []
    task_results: list[TaskRunResult] = []

    for task in tasks:
        arms: dict[Arm, ArmRunResult] = {}
        for arm in (Arm.NO_RETRIEVAL, Arm.RAW_SEARCH, Arm.LEITIR):
            arms[arm] = _run_one_arm(
                task=task,
                arm=arm,
                runner=runner,
                all_evaluator_assets=all_evaluator_assets,
                repair_budget=repair_budget,
                check_corpus_root=check_corpus_root,
                check_env_overrides=check_env_overrides,
                trace=trace,
            )
        task_results.append(TaskRunResult(task_id=task.public.case_id, arms=arms))

    return DifferentialRunResult(tasks=tuple(task_results), prompt_trace=tuple(trace))


__all__ = [
    "DEFAULT_REPAIR_BUDGET",
    "ArmRunResult",
    "DifferentialRunResult",
    "TaskRunResult",
    "run_all",
]
