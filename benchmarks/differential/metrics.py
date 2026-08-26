"""Measured/Unavailable metric wrapper.

Per ADR-0002, unknown is neither zero nor pass. Every metric this harness
emits is one of these two shapes, never a bare number that could silently
default to zero on failure.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Generic, TypeVar

T = TypeVar("T")


@dataclass(frozen=True)
class Measured(Generic[T]):
    """A metric that was actually computed."""

    value: T


@dataclass(frozen=True)
class Unavailable:
    """A metric that could not be computed, and why.

    Never coerce this to 0, False, or an empty collection -- callers must
    branch on the type, not on a fallback value.
    """

    reason: str


Metric = Measured[T] | Unavailable


def is_measured(metric: Metric[T]) -> bool:
    return isinstance(metric, Measured)


def metric_to_json(metric: Metric[T]) -> dict[str, object]:
    if isinstance(metric, Measured):
        return {"status": "measured", "value": metric.value}
    return {"status": "unavailable", "reason": metric.reason}


__all__ = ["Measured", "Metric", "Unavailable", "is_measured", "metric_to_json"]
