"""Prompt construction and the evaluator-seam leak check.

Structural enforcement of the seam has two layers:

1. **Type-level**: every function in this module that builds prompt text
   takes a ``tasks.PublicTask`` (and, for repair, a ``runner.RepairSignal``)
   -- never a ``tasks.EvaluatorAssets``, a ``Path`` pointing at a contract
   test, or raw contract-test bytes. There is no parameter here through
   which those bytes could be threaded into a prompt; adding one would be a
   visible, reviewable change to this file's signatures.
2. **Runtime backstop**: :func:`assert_no_evaluator_leak` scans a rendered
   payload's bytes for the *exact* bytes of every task's contract test and
   raises ``EvaluatorLeakError`` if found. ``harness.py`` calls this on
   every prompt payload it builds, and
   ``tests/test_differential_eval.py`` pins it directly.
"""

from __future__ import annotations

from dataclasses import dataclass

from .runner import Arm, GenerationRequest, RepairSignal, RetrievalChunk
from .tasks import EvaluatorAssets, PublicTask

_SCAFFOLD = (
    "You are implementing a small, self-contained Python function.\n"
    "Task: {case_id}\n"
    "Target behavior: reimplement the semantics of "
    "{seed_qualified_name!r} from module {seed_module!r} "
    "(language: {language}), independently -- do not assume you can "
    "import the original package.\n"
    "Provenance (for context only, not a dependency you may import): "
    "{source_provenance}\n"
)

_ARM_PREAMBLE = {
    Arm.NO_RETRIEVAL: "Retrieval: none. Answer from your own knowledge only.\n",
    Arm.RAW_SEARCH: "Retrieval: raw web/GitHub search results are provided below.\n",
    Arm.LEITIR: "Retrieval: leitir verb output (info/search/examples/api/check) is provided below.\n",
}


class EvaluatorLeakError(Exception):
    """Raised when contract-test bytes are found in a payload the harness built."""


@dataclass(frozen=True)
class PromptRecord:
    """One rendered prompt payload, kept for the seam-leak trace and tests."""

    task_id: str
    arm: Arm
    phase: str  # "generate" | "repair"
    attempt: int
    text: str


def build_generation_request(
    public_task: PublicTask,
    arm: Arm,
    *,
    context: tuple[RetrievalChunk, ...] = (),
    attempt: int = 1,
) -> GenerationRequest:
    """Build a first-pass (or later-attempt) generation request.

    Takes only ``PublicTask`` -- see the module docstring for why that is
    the seam's type-level enforcement.
    """

    prompt = _SCAFFOLD.format(
        case_id=public_task.case_id,
        seed_qualified_name=public_task.seed_qualified_name,
        seed_module=public_task.seed_module,
        language=public_task.language,
        source_provenance=public_task.source_provenance,
    ) + _ARM_PREAMBLE[arm]
    return GenerationRequest(
        task_id=public_task.case_id,
        arm=arm,
        prompt=prompt,
        context=context,
        attempt=attempt,
    )


def build_repair_request(
    public_task: PublicTask,
    arm: Arm,
    *,
    signal: RepairSignal,
    context: tuple[RetrievalChunk, ...] = (),
    attempt: int,
) -> GenerationRequest:
    """Build a repair-loop request from a non-leaking :class:`RepairSignal`.

    ``signal`` carries only pass/fail/error counts (see ``runner.py``);
    there is nothing here that could carry pytest output or assertion text.
    """

    base = build_generation_request(public_task, arm, context=context, attempt=attempt)
    repair_note = (
        f"\nYour previous attempt (attempt {attempt - 1}) was checked against "
        f"a hidden contract test suite you cannot see: "
        f"{signal.passed} passed, {signal.failed} failed, {signal.errored} errored. "
        "Revise your implementation to address likely correctness gaps.\n"
    )
    return GenerationRequest(
        task_id=base.task_id,
        arm=base.arm,
        prompt=base.prompt + repair_note,
        context=base.context,
        attempt=attempt,
    )


def render_payload(request: GenerationRequest) -> str:
    """Render the full text payload a runner would receive, for leak-scanning."""

    context_text = "\n".join(f"[{chunk.source}]\n{chunk.text}" for chunk in request.context)
    return request.prompt + "\n" + context_text


def assert_no_evaluator_leak(payload: str, evaluator_assets: tuple[EvaluatorAssets, ...]) -> None:
    """Raise :class:`EvaluatorLeakError` if any contract-test bytes appear in ``payload``.

    Checks both the raw contract-test bytes (decoded permissively) and its
    file path, since either leaking into a prompt is a seam violation.
    """

    payload_bytes = payload.encode("utf-8", errors="surrogateescape")
    for asset in evaluator_assets:
        if asset.contract_test_bytes and asset.contract_test_bytes in payload_bytes:
            raise EvaluatorLeakError(
                f"contract-test bytes for {asset.case_id!r} appeared in a generated payload"
            )
        if str(asset.contract_test_path) in payload:
            raise EvaluatorLeakError(
                f"contract-test path for {asset.case_id!r} appeared in a generated payload"
            )


__all__ = [
    "EvaluatorLeakError",
    "PromptRecord",
    "assert_no_evaluator_leak",
    "build_generation_request",
    "build_repair_request",
    "render_payload",
]
