"""Completeness and invariants of the shared domain contracts."""

from __future__ import annotations

import pytest

from leitir.contracts import (
    Artifact,
    ArtifactId,
    Attempt,
    AttemptId,
    AttemptStatus,
    ErrorAttribution,
    ErrorCode,
    EvidenceTier,
    StepResult,
    StepStatus,
    TerminalDisposition,
    WorkflowRequest,
    WorkflowStep,
)


EXPECTED_ERRORS = {
    "ERR_EXPANSION_MALFORMED",
    "ERR_SEARCH_AUTH_REQUIRED",
    "ERR_SEARCH_ENGINES_BLOCKED",
    "ERR_SEARCH_ZERO_RESULTS",
    "ERR_SCRAPE_BOILERPLATE_LEAK",
    "ERR_SECURITY_PROMPT_INJECTION",
    "ERR_SYNTAX_COMPILATION_FAIL",
    "ERR_VERIFICATION_TIMEOUT",
}


def test_all_steps_tiers_errors_statuses_and_dispositions_are_represented():
    assert {step.value for step in WorkflowStep} == {1, 2, 3, 4, 5}
    assert {tier.value for tier in EvidenceTier} == {1, 2, 3}
    assert {item.value for item in ErrorCode} == EXPECTED_ERRORS
    assert {"pending", "running", "succeeded", "failed", "skipped"} == {
        status.value for status in StepStatus
    }
    assert TerminalDisposition.ACCEPTED.value == "accepted"
    assert TerminalDisposition.REPAIR_EXHAUSTED.value == "repair_exhausted"


def test_tier_tagged_artifact_and_attempt_identifiers():
    artifact_id = ArtifactId("artifact-1")
    artifact = Artifact(
        artifact_id=artifact_id,
        tier=EvidenceTier.TIER_1,
        source_uri="https://docs.example.test/api",
        content_reference="sha256:abc",
        metadata={"status": 200},
    )
    attempt = Attempt(
        attempt_id=AttemptId("attempt-1"),
        number=1,
        status=AttemptStatus.PASSED,
        disposition=TerminalDisposition.ACCEPTED,
    )
    assert artifact.artifact_id == artifact_id
    assert artifact.tier is EvidenceTier.TIER_1
    assert attempt.attempt_id.value == "attempt-1"


def test_failed_step_requires_matching_error_attribution():
    error = ErrorAttribution(
        code=ErrorCode.ERR_SEARCH_ZERO_RESULTS,
        owner="tool",
        step=WorkflowStep.DISCOVERY,
    )
    result = StepResult(
        step=WorkflowStep.DISCOVERY, status=StepStatus.FAILED, error=error
    )
    assert result.error is error
    with pytest.raises(ValueError):
        StepResult(step=WorkflowStep.DISCOVERY, status=StepStatus.FAILED)


def test_request_cannot_select_another_language():
    request = WorkflowRequest(request_id="request-1", task="write a parser")
    assert request.target_language.value == "python"
    with pytest.raises(ValueError):
        WorkflowRequest(
            request_id="request-2", task="write a parser", target_language="go"
        )

