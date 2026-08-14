"""Typed, deterministic failure surface for Behavioral Transplant Sets."""

from __future__ import annotations

import json
from dataclasses import dataclass, replace
from enum import Enum


class BTSRejectReason(str, Enum):  # noqa: UP042 - shared contract requires str, Enum
    """Stable machine-readable reasons for rejecting a BTS operation."""

    REJECT_UNRESOLVED_EDGE = "reject_unresolved_edge"
    REJECT_UNSUPPORTED_CONSTRUCT = "reject_unsupported_construct"
    REJECT_UNSUPPORTED_EXTRA = "reject_unsupported_extra"
    REJECT_PROVENANCE_MISMATCH = "reject_provenance_mismatch"
    REJECT_MOVING_REFERENCE = "reject_moving_reference"
    REJECT_DONOR_IMPORT_OBSERVED = "reject_donor_import_observed"
    REJECT_BUDGET_EXCEEDED = "reject_budget_exceeded"
    REJECT_EXTRACTION_BUDGET = "reject_extraction_budget"
    REJECT_LICENSE_INCOMPATIBLE = "reject_license_incompatible"
    REJECT_LICENSE_UNKNOWN = "reject_license_unknown"
    REJECT_LICENSE_OBLIGATION_MISSING = "reject_license_obligation_missing"
    REJECT_BUNDLE_INVALID = "reject_bundle_invalid"
    REJECT_HARD_GATE_FAILED = "reject_hard_gate_failed"
    REJECT_EXECUTION_THREAT = "reject_execution_threat"
    REJECT_FETCH_FAILED = "reject_fetch_failed"
    REJECT_DUPLICATE_RESULT = "reject_duplicate_result"
    REJECT_COVERAGE_MISCOUNT = "reject_coverage_miscount"
    REJECT_SEMANTIC_DEGRADATION = "reject_semantic_degradation"
    REJECT_UNDER_COLLECTION = "reject_under_collection"


@dataclass(frozen=True, slots=True)
class BTSEvidence:
    """Human-readable failure evidence with an optional donor source span."""

    message: str
    slug: str | None = None
    commit_sha: str | None = None
    path: str | None = None
    blob_sha: str | None = None
    start_line: int | None = None
    start_col: int | None = None
    end_line: int | None = None
    end_col: int | None = None
    detail_code: str | None = None


_EVIDENCE_FIELDS = (
    "message",
    "slug",
    "commit_sha",
    "path",
    "blob_sha",
    "start_line",
    "start_col",
    "end_line",
    "end_col",
    "detail_code",
)


def _reject_duplicate_json_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _optional_str(evidence: dict[str, object], field: str) -> str | None:
    value = evidence[field]
    if value is None:
        return None
    if isinstance(value, str):
        return value
    raise ValueError(f"evidence.{field} has an invalid type")


def _optional_int(evidence: dict[str, object], field: str) -> int | None:
    value = evidence[field]
    if value is None:
        return None
    if type(value) is int:
        return value
    raise ValueError(f"evidence.{field} has an invalid type")


class BTSError(Exception):
    """Base error for a rejected BTS operation."""

    reason: BTSRejectReason
    evidence: BTSEvidence

    def __init__(
        self,
        reason: BTSRejectReason,
        evidence: BTSEvidence | str,
        *,
        detail_code: str | None = None,
        cause: BaseException | None = None,
    ) -> None:
        if not isinstance(reason, BTSRejectReason):
            raise TypeError("reason must be a BTSRejectReason")
        if isinstance(evidence, str):
            evidence = BTSEvidence(message=evidence, detail_code=detail_code)
        elif isinstance(evidence, BTSEvidence):
            if detail_code is not None:
                evidence = replace(evidence, detail_code=detail_code)
        else:
            raise TypeError("evidence must be BTSEvidence or str")
        super().__init__(evidence.message)
        self.reason = reason
        self.evidence = evidence
        if cause is not None:
            self.__cause__ = cause

    def to_json(self) -> str:
        """Return the canonical JSON representation, terminated by one LF."""

        payload = {
            "evidence": {
                "blob_sha": self.evidence.blob_sha,
                "commit_sha": self.evidence.commit_sha,
                "detail_code": self.evidence.detail_code,
                "end_col": self.evidence.end_col,
                "end_line": self.evidence.end_line,
                "message": self.evidence.message,
                "path": self.evidence.path,
                "slug": self.evidence.slug,
                "start_col": self.evidence.start_col,
                "start_line": self.evidence.start_line,
            },
            "reason": self.reason.value,
        }
        return json.dumps(
            payload,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ) + "\n"

    @staticmethod
    def from_json(data: str) -> BTSError:
        """Reconstruct an error from canonical JSON, rejecting malformed data."""

        try:
            decoded = json.loads(data, object_pairs_hook=_reject_duplicate_json_keys)
        except (json.JSONDecodeError, TypeError) as exc:
            raise ValueError("invalid BTS error JSON") from exc
        if not isinstance(decoded, dict) or set(decoded) != {"evidence", "reason"}:
            raise ValueError("invalid BTS error fields")
        reason_value = decoded["reason"]
        if not isinstance(reason_value, str):
            raise ValueError("reason must be a string")
        try:
            reason = BTSRejectReason(reason_value)
        except ValueError as exc:
            raise ValueError("unknown BTS reject reason") from exc

        raw_evidence = decoded["evidence"]
        if not isinstance(raw_evidence, dict) or set(raw_evidence) != set(
            _EVIDENCE_FIELDS
        ):
            raise ValueError("invalid BTS evidence fields")
        message = raw_evidence["message"]
        if not isinstance(message, str):
            raise ValueError("evidence.message must be a string")
        evidence = BTSEvidence(
            message=message,
            slug=_optional_str(raw_evidence, "slug"),
            commit_sha=_optional_str(raw_evidence, "commit_sha"),
            path=_optional_str(raw_evidence, "path"),
            blob_sha=_optional_str(raw_evidence, "blob_sha"),
            start_line=_optional_int(raw_evidence, "start_line"),
            start_col=_optional_int(raw_evidence, "start_col"),
            end_line=_optional_int(raw_evidence, "end_line"),
            end_col=_optional_int(raw_evidence, "end_col"),
            detail_code=_optional_str(raw_evidence, "detail_code"),
        )
        return BTSError(reason, evidence)

    def __eq__(self, other: object) -> bool:
        if type(other) is not type(self):
            return False
        assert isinstance(other, BTSError)
        return self.reason == other.reason and self.evidence == other.evidence


class TransplantError(BTSError):
    """A BTS could not be relocated or rerun successfully."""
