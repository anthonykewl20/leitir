"""Probe registry.  A probe observes one class of blind spot and never fixes anything."""

from __future__ import annotations

import time
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ..ledger import Finding


@dataclass
class ProbeContext:
    repo_root: Path
    run_dir: Path
    state_dir: Path
    options: dict[str, Any]
    log: Callable[[str], None]
    open_findings: list[dict[str, Any]] = field(default_factory=list)

    def open_for(self, probe: str) -> list[dict[str, Any]]:
        return [entry for entry in self.open_findings if entry.get("probe") == probe]

    def option(self, name: str, default: Any = None) -> Any:
        value = self.options.get(name)
        return default if value is None else value


@dataclass
class ProbeResult:
    name: str
    status: str  # ok | skipped | error
    findings: list[Finding] = field(default_factory=list)
    metrics: dict[str, Any] = field(default_factory=dict)
    notes: list[str] = field(default_factory=list)
    elapsed: float = 0.0
    # Identities this run actually re-examined.  ``None`` means the probe is
    # exhaustive: anything it did not observe is gone.  A sampled probe must
    # list what it re-tested so an unlucky sample never marks a finding fixed.
    retested: set[str] | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "status": self.status,
            "findings": [finding.to_dict() for finding in self.findings],
            "metrics": self.metrics,
            "notes": self.notes,
            "elapsed": round(self.elapsed, 3),
        }


ProbeFunction = Callable[[ProbeContext], ProbeResult]


def run_probe(name: str, function: ProbeFunction, context: ProbeContext) -> ProbeResult:
    started = time.monotonic()
    context.log(f"[{name}] start")
    try:
        result = function(context)
    except Exception as exc:  # a broken probe is itself a finding, never a silent skip
        result = ProbeResult(name, "error", notes=[f"probe crashed: {type(exc).__name__}: {exc}"])
    result.elapsed = time.monotonic() - started
    context.log(f"[{name}] {result.status} findings={len(result.findings)} elapsed={result.elapsed:.1f}s")
    return result


def registry() -> dict[str, ProbeFunction]:
    from . import coverage, determinism, fuzz, mutation, perf, scorecard, static, suite

    return {
        "static": static.probe,
        "suite": suite.probe,
        "coverage": coverage.probe,
        "fuzz": fuzz.probe,
        "determinism": determinism.probe,
        "mutation": mutation.probe,
        "perf": perf.probe,
        "scorecard": scorecard.probe,
    }


DEFAULT_PROBES = ("static", "suite", "coverage", "fuzz", "determinism", "mutation", "perf")
