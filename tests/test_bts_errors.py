from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

from leitir.bts_errors import (
    BTSError,
    BTSEvidence,
    BTSRejectReason,
    TransplantError,
)

EXPECTED_REASONS = frozenset(
    {
        "REJECT_UNRESOLVED_EDGE",
        "REJECT_UNSUPPORTED_CONSTRUCT",
        "REJECT_PROVENANCE_MISMATCH",
        "REJECT_MOVING_REFERENCE",
        "REJECT_DONOR_IMPORT_OBSERVED",
        "REJECT_BUDGET_EXCEEDED",
        "REJECT_EXTRACTION_BUDGET",
        "REJECT_LICENSE_INCOMPATIBLE",
        "REJECT_LICENSE_UNKNOWN",
        "REJECT_LICENSE_OBLIGATION_MISSING",
        "REJECT_BUNDLE_INVALID",
        "REJECT_HARD_GATE_FAILED",
        "REJECT_EXECUTION_THREAT",
        "REJECT_FETCH_FAILED",
        "REJECT_DUPLICATE_RESULT",
        "REJECT_COVERAGE_MISCOUNT",
        "REJECT_SEMANTIC_DEGRADATION",
        "REJECT_UNDER_COLLECTION",
    }
)


def _evidence() -> BTSEvidence:
    return BTSEvidence(
        message="could not fetch café.py",
        slug="owner/repo",
        commit_sha="a" * 40,
        path="src/café.py",
        blob_sha="b" * 40,
        start_line=7,
        start_col=2,
        end_line=8,
        end_col=11,
        detail_code="fetch_failed",
    )


def test_reject_reason_membership_is_pinned() -> None:
    assert frozenset(reason.name for reason in BTSRejectReason) == EXPECTED_REASONS
    assert all(reason.value == reason.name.lower() for reason in BTSRejectReason)


@pytest.mark.parametrize("reason", BTSRejectReason)
def test_every_reject_reason_round_trips_through_json(
    reason: BTSRejectReason,
) -> None:
    restored = BTSError.from_json(BTSError(reason, _evidence()).to_json())

    assert restored.reason is reason
    assert restored.reason.name == reason.name
    assert restored.reason.value == reason.value


def test_bts_error_round_trip_preserves_reason_and_evidence() -> None:
    original = BTSError(BTSRejectReason.REJECT_UNRESOLVED_EDGE, _evidence())

    restored = BTSError.from_json(original.to_json())

    assert restored == original
    assert type(restored) is BTSError
    assert restored.reason is BTSRejectReason.REJECT_UNRESOLVED_EDGE
    assert restored.evidence == _evidence()
    assert restored.evidence.detail_code == "fetch_failed"


def test_string_evidence_convenience_constructs_structured_evidence() -> None:
    error = BTSError(
        BTSRejectReason.REJECT_UNRESOLVED_EDGE,
        "could not resolve edge",
        detail_code="unknown_binding",
    )

    assert error.reason is BTSRejectReason.REJECT_UNRESOLVED_EDGE
    assert error.evidence == BTSEvidence(
        message="could not resolve edge", detail_code="unknown_binding"
    )
    assert str(error) == "could not resolve edge"


def test_detail_code_overrides_structured_evidence() -> None:
    original = BTSEvidence(message="blocked", detail_code="old_code")

    error = TransplantError(
        BTSRejectReason.REJECT_UNSUPPORTED_CONSTRUCT,
        original,
        detail_code="new_code",
    )

    assert error.evidence == BTSEvidence(message="blocked", detail_code="new_code")
    assert original.detail_code == "old_code"


def test_bts_error_requires_a_typed_reason() -> None:
    with pytest.raises(TypeError, match="reason must be a BTSRejectReason"):
        BTSError(None, _evidence())  # type: ignore[arg-type]


def test_bts_error_requires_typed_evidence() -> None:
    with pytest.raises(TypeError, match="evidence must be BTSEvidence or str"):
        BTSError(BTSRejectReason.REJECT_FETCH_FAILED, ())  # type: ignore[arg-type]


def test_fetch_failure_retains_underlying_cause() -> None:
    cause = OSError("network unavailable")
    error = BTSError(
        BTSRejectReason.REJECT_FETCH_FAILED,
        BTSEvidence(message="donor fetch failed"),
        cause=cause,
    )

    assert error.__cause__ is cause


def test_error_json_is_byte_identical_across_pythonhashseed() -> None:
    script = """
from leitir.bts_errors import BTSError, BTSEvidence, BTSRejectReason
evidence = BTSEvidence(
    message="could not fetch café.py", slug="owner/repo", commit_sha="a" * 40,
    path="src/café.py", blob_sha="b" * 40, start_line=7, start_col=2,
    end_line=8, end_col=11, detail_code="fetch_failed",
)
print(BTSError(BTSRejectReason.REJECT_FETCH_FAILED, evidence).to_json(), end="")
"""
    outputs: list[bytes] = []
    for seed in ("0", "1", "42"):
        environment = os.environ.copy()
        environment["PYTHONHASHSEED"] = seed
        environment["PYTHONPATH"] = str(Path(__file__).parents[1] / "src")
        outputs.append(
            subprocess.check_output(
                [sys.executable, "-c", script],
                cwd=Path(__file__).parents[1],
                env=environment,
            )
        )

    assert outputs[0] == outputs[1] == outputs[2]
    assert outputs[0].endswith(b"\n")
