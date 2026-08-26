"""Pluggable runner protocol for the differential eval harness.

A real model runner (paid, networked) and the offline deterministic stub
runner in ``stub_runner.py`` both implement :class:`Runner`. The harness
(``harness.py``) only ever calls through this protocol, so swapping in a
real model is a matter of writing a class with ``generate``/``repair``
methods of this shape and passing an instance to ``harness.run_all``.

Plugging in a real model runner
--------------------------------
Implement :class:`Runner` against whatever client you use (OpenRouter,
Anthropic, a raw GitHub-search agent, etc.)::

    @dataclass
    class MyModelRunner:
        def generate(self, request: GenerationRequest) -> GenerationResult:
            response = my_client.complete(request.prompt, context=request.context)
            return GenerationResult(
                code=response.code,
                tokens_used=Measured(response.usage.total_tokens),
                steps_used=Measured(1),
            )

        def repair(
            self, request: GenerationRequest, prior_code: str, signal: RepairSignal
        ) -> GenerationResult:
            ...

Nothing in ``GenerationRequest`` or ``RepairSignal`` can carry contract-test
bytes -- see the module docstrings on ``tasks.py`` and ``prompt.py`` for the
evaluator seam this enforces structurally. A real runner therefore cannot
leak hidden-test content even by accident: it is simply never given a
reference to it.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Protocol

from .metrics import Metric


class Arm(StrEnum):
    """The three experimental arms. The deliverable metric is C minus B."""

    NO_RETRIEVAL = "A"
    RAW_SEARCH = "B"
    LEITIR = "C"


@dataclass(frozen=True)
class RetrievalChunk:
    """One piece of retrieval context surfaced to the model for a given arm.

    ``text`` must never be built from evaluator assets (contract-test path,
    source, assertions, output, or source-derived diagnostics).
    """

    source: str
    text: str


@dataclass(frozen=True)
class GenerationRequest:
    """Everything a runner sees for one generation or repair attempt.

    ``prompt`` and ``context`` are built exclusively from
    ``tasks.PublicTask`` fields plus arm-appropriate retrieval chunks --
    never from ``tasks.EvaluatorAssets``. ``prompt.py`` is the only place
    that constructs this object; its function signatures make it
    impossible to pass evaluator assets in.
    """

    task_id: str
    arm: Arm
    prompt: str
    context: tuple[RetrievalChunk, ...] = field(default_factory=tuple)
    attempt: int = 1


@dataclass(frozen=True)
class RepairSignal:
    """A non-leaking summary of a prior failed attempt.

    Deliberately just three counts. There is no string field here for
    pytest stdout, an assertion message, or any other source-derived
    diagnostic to hide in -- that is the structural enforcement of the
    evaluator seam for the repair loop.
    """

    passed: int
    failed: int
    errored: int


@dataclass(frozen=True)
class GenerationResult:
    """A runner's output for one generation or repair attempt."""

    code: str
    tokens_used: Metric[int]
    steps_used: Metric[int]


class Runner(Protocol):
    """Abstract generation backend. Implemented by a stub and, eventually, a real model."""

    def generate(self, request: GenerationRequest) -> GenerationResult:
        """Produce a first-pass candidate for ``request``."""
        ...

    def repair(
        self, request: GenerationRequest, prior_code: str, signal: RepairSignal
    ) -> GenerationResult:
        """Produce a repaired candidate given the prior code and a non-leaking failure signal."""
        ...


__all__ = [
    "Arm",
    "GenerationRequest",
    "GenerationResult",
    "RepairSignal",
    "RetrievalChunk",
    "Runner",
]
