"""Deterministic trust scoring from cached corpus evidence."""

from __future__ import annotations

import logging
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import cast

_WEIGHTS = {
    "age": 15,
    "artifact_checksum": 15,
    "documentation": 10,
    "license": 15,
    "parity": 15,
    "tests": 10,
    "verification": 20,
}
_DATE_FIELDS = ("published_at",)
logger = logging.getLogger(__name__)


@dataclass(frozen=True, slots=True)
class TrustScore:
    """A bounded score and its ordered, auditable factor breakdown."""

    score: int
    breakdown: tuple[dict[str, object], ...]

    def as_dict(self) -> dict[str, object]:
        return {"trust_score": self.score, "trust_breakdown": [dict(item) for item in self.breakdown]}


def _factor(name: str, score: int, evidence: Mapping[str, object]) -> dict[str, object]:
    """Build one factor, accepting only integer scores and bounding them to 0..100.

    Booleans, floats (including NaN and infinities), and all other non-integer
    values are invalid rather than evidence that can be promoted by clamping.
    """

    if not isinstance(score, int) or isinstance(score, bool):
        raise ValueError("factor score must be an integer")
    return {
        "factor": name,
        "score": max(0, min(100, score)),
        "weight": _WEIGHTS[name],
        "evidence": dict(evidence),
    }


def _verification(manifest: Mapping[str, object]) -> dict[str, object]:
    if "verified" not in manifest:
        return _factor("verification", 50, {"state": "unknown", "reason": "verification state is not cached"})
    state = manifest.get("verified")
    if state is True:
        score = 100
    elif state == "sampled":
        score = 70
    elif state == "archive-only":
        score = 40
    elif state is False:
        score = 0
    else:
        return _factor("verification", 50, {"state": "unknown", "reason": "cached verification state is invalid"})
    return _factor("verification", score, {"state": state, "reason": f"cached verification state is {state!r}"})


def _parity(manifest: Mapping[str, object]) -> dict[str, object]:
    state = manifest.get("parity", "unknown")
    scores = {"exact": 100, "drift": 0, "unknown": 50}
    if not isinstance(state, str) or state not in scores:
        state = "unknown"
    reason = "cached parity result" if state != "unknown" else "parity result is unknown"
    return _factor("parity", scores[state], {"state": state, "reason": reason})


def _license(manifest: Mapping[str, object], target_path: Path) -> dict[str, object]:
    confidence = manifest.get("license_confidence")
    method: object = manifest.get("license_method")
    if not isinstance(confidence, str) or confidence not in {"high", "medium", "low"}:
        from leitir.sbom import infer_license

        result = infer_license(dict(manifest), target_path)
        confidence = result.confidence
        method = result.method
        if result.identifier is None and result.method == "unknown":
            return _factor(
                "license",
                50,
                {"state": "unknown", "reason": "license evidence is unavailable"},
            )
    scores = {"high": 100, "medium": 65, "low": 25}
    if confidence not in scores:
        return _factor("license", 50, {"state": "unknown", "reason": "license confidence is unavailable"})
    return _factor(
        "license",
        scores[confidence],
        {"state": confidence, "method": method, "reason": f"license confidence is {confidence}"},
    )


def _documentation(manifest: Mapping[str, object]) -> dict[str, object]:
    known = "docs_urls" in manifest or "entry_points" in manifest
    if not known:
        return _factor("documentation", 50, {"state": "unknown", "reason": "documentation evidence is not cached"})
    docs = manifest.get("docs_urls")
    entries = manifest.get("entry_points")
    has_docs = isinstance(docs, list) and bool(docs)
    has_entries = isinstance(entries, list) and bool(entries)
    score = 100 if has_docs and has_entries else 60 if has_docs or has_entries else 0
    state = "docs-and-entry-points" if score == 100 else "partial" if score else "absent"
    return _factor(
        "documentation",
        score,
        {"state": state, "docs_urls": has_docs, "entry_points": has_entries, "reason": "cached docs and entry-point presence"},
    )


def _tests(manifest: Mapping[str, object], target_path: Path) -> dict[str, object]:
    del target_path  # Test-tree inspection is represented by the cached field.
    cached = manifest.get("has_tests")
    if isinstance(cached, bool):
        return _factor(
            "tests",
            100 if cached else 0,
            {"state": "present" if cached else "absent", "reason": "cached Git tree tests/ presence"},
        )
    return _factor(
        "tests",
        50,
        {"state": "unknown", "reason": "Git tree tests/ presence is not cached"},
    )


def _checksum(manifest: Mapping[str, object]) -> dict[str, object]:
    checksum = manifest.get("artifact_checksum")
    kind = manifest.get("artifact_kind")
    if isinstance(checksum, str) and checksum and isinstance(kind, str) and kind:
        return _factor("artifact_checksum", 100, {"state": "present", "artifact_kind": kind, "reason": "cached artifact checksum and kind are present"})
    if checksum is None and kind is None and manifest.get("source") == "git-commit":
        return _factor(
            "artifact_checksum",
            0,
            {"state": "absent", "reason": "cached source mode confirms there is no registry artifact"},
        )
    if "artifact_checksum" not in manifest and "artifact_kind" not in manifest:
        return _factor(
            "artifact_checksum",
            50,
            {"state": "unknown", "reason": "artifact checksum evidence is not cached"},
        )
    return _factor("artifact_checksum", 50, {"state": "unknown", "reason": "artifact checksum metadata is incomplete"})


def _parse_timestamp(value: object) -> datetime | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return None
    return parsed.astimezone(UTC)


def _age(manifest: Mapping[str, object]) -> dict[str, object]:
    field = next((name for name in _DATE_FIELDS if name in manifest), None)
    released = _parse_timestamp(manifest.get(field)) if field else None
    observed = _parse_timestamp(manifest.get("fetched_at"))
    if released is None or observed is None or released > observed:
        return _factor("age", 50, {"state": "unknown", "reason": "cached release/commit and fetch timestamps are unavailable or invalid"})
    days = (observed - released).days
    score = 100 if days <= 365 else 75 if days <= 1095 else 50 if days <= 1825 else 25
    return _factor("age", score, {"state": "known", "source": field, "days_at_fetch": days, "reason": "age measured at cached fetch time"})


def compute_trust(manifest: Mapping[str, object], target_path: str | Path) -> TrustScore:
    """Compute a weighted trust score without network or wall-clock inputs.

    Factor weights are verification 20, parity 15, license 15,
    documentation 10, tests 10, artifact checksum 15, and age 15.
    """

    target = Path(target_path)
    factors = [
        _verification(manifest),
        _parity(manifest),
        _license(manifest, target),
        _documentation(manifest),
        _tests(manifest, target),
        _checksum(manifest),
        _age(manifest),
    ]
    factors.sort(key=lambda item: str(item["factor"]))
    weighted = sum(
        cast(int, item["score"]) * cast(int, item["weight"]) for item in factors
    )
    score = max(0, min(100, (weighted + 50) // 100))
    logger.debug("trust score=%d factors=%s", score, factors)
    return TrustScore(score, tuple(factors))


__all__ = ["TrustScore", "compute_trust"]
