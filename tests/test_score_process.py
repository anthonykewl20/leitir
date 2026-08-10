"""ADR-002 S6 OpenSSF process and supply-chain adapter gates."""

from __future__ import annotations

import hashlib
import json
import urllib.error
import urllib.request
from pathlib import Path

import pytest

from tools.score_engine import (
    OPENSSF_SELECTED_CHECKS,
    PINNED_OPENSSF_SCORECARD_COMMIT,
    PINNED_OPENSSF_SCORECARD_VERSION,
    CheckStatus,
    Decision,
    EvidenceArtifact,
    GitHubCapabilities,
    OpenSSFApplicability,
    OpenSSFCollectionState,
    Producer,
    Profile,
    Subject,
    canonical_json_bytes,
    collect_openssf_scorecard,
    evaluate,
    evaluate_process_supply_chain_collection,
    evaluate_process_supply_chain_evidence,
    load_policy,
)

REPO_ROOT = Path(__file__).resolve().parents[1]
FIXTURES = REPO_ROOT / "tests" / "fixtures_score" / "openssf"
POLICY_PATH = REPO_ROOT / "scorecard" / "policy-v1.json"
ANONYMOUS_CAPABILITIES = GitHubCapabilities(
    token_kind="anonymous", granted=("public_api",)
)
FIXTURE_SHA256 = {
    "scorecard-v5.5.0-happy.json": "60b8f2fb70ddefbafc436db2f3967a15c84aee5a65dd15487c991fff08a9e9c8",
    "scorecard-v5.5.0-inconclusive.json": "9de85c31d77aa5580c7fe8432209d83453f1a54cea2517884615f91fea9546f1",
}


def _fixture(name: str) -> EvidenceArtifact:
    content = (FIXTURES / name).read_bytes()
    return EvidenceArtifact(
        id="process.openssf-scorecard",
        path=f"tests/fixtures_score/openssf/{name}",
        sha256=FIXTURE_SHA256[name],
        content=content,
    )


def _artifact(name: str, raw: object) -> EvidenceArtifact:
    content = canonical_json_bytes(raw)
    return EvidenceArtifact(
        id="process.openssf-scorecard",
        path=f"tests/fixtures_score/openssf/{name}.json",
        sha256=hashlib.sha256(content).hexdigest(),
        content=content,
    )


def _raw(name: str = "scorecard-v5.5.0-happy.json") -> dict[str, object]:
    return json.loads((FIXTURES / name).read_text(encoding="utf-8"))


def _evaluation(
    artifact: EvidenceArtifact | None = None,
    *,
    capabilities: GitHubCapabilities = ANONYMOUS_CAPABILITIES,
    applicability: tuple[OpenSSFApplicability, ...] = (),
):
    return evaluate_process_supply_chain_evidence(
        policy=load_policy(POLICY_PATH),
        scorecard_artifact=artifact or _fixture("scorecard-v5.5.0-happy.json"),
        capabilities=capabilities,
        expected_repository="ossf/scorecard",
        applicability=applicability,
    )


def _check(evaluation, check_id: str):
    return next(item for item in evaluation.checks if item.id == check_id)


def _replace_check(raw: dict[str, object], name: str, **changes: object) -> None:
    check = next(item for item in raw["checks"] if item["name"] == name)
    check.update(changes)


def _process_dimension(evaluation, artifact):
    assessment = evaluate(
        load_policy(POLICY_PATH),
        evaluation.checks,
        profile=Profile.RELEASE,
        subject=Subject(
            repository="github.com/ossf/scorecard",
            commit_sha="64febf8c5229a2a65d09c6b543677b28a51abb09",
            worktree="clean",
        ),
        producer=Producer(
            name="leitir-score-engine",
            version="1",
            commit_sha="1" * 40,
        ),
        evidence=(artifact,),
    )
    return next(
        item for item in assessment.dimensions if item.id == "process_supply_chain"
    ), assessment


def test_pinned_real_shape_fixture_normalizes_only_policy_selected_checks():
    evaluation = _evaluation()
    selected_ids = {check_id for check_id, _ in OPENSSF_SELECTED_CHECKS}

    assert {item.id for item in evaluation.checks} == selected_ids | {
        "process.supply_chain_evidence"
    }
    assert all(item.status is CheckStatus.PASS for item in evaluation.checks)
    assert evaluation.aggregate_disposition == "discarded"
    assert "aggregate" not in evaluation.to_dict()
    assert evaluation.provenance.to_dict() == {
        "repository": "github.com/ossf/scorecard",
        "repository_commit": "64febf8c5229a2a65d09c6b543677b28a51abb09",
        "tool_version": PINNED_OPENSSF_SCORECARD_VERSION,
        "tool_commit": PINNED_OPENSSF_SCORECARD_COMMIT,
        "observed_at": "2026-08-01T02:19:41Z",
        "raw_artifact_sha256": _fixture("scorecard-v5.5.0-happy.json").sha256,
        "capabilities": {
            "token_kind": "anonymous",
            "token_present": False,
            "granted": ["public_api"],
            "unavailable": [],
        },
    }


def test_known_failure_is_policy_failure_with_integer_basis_points():
    raw = _raw()
    _replace_check(
        raw,
        "Vulnerabilities",
        score=0,
        reason="59 existing vulnerabilities detected",
    )
    artifact = _artifact("known-vulnerabilities", raw)
    evaluation = _evaluation(artifact)
    vulnerabilities = _check(evaluation, "process.vulnerabilities")
    dimension, assessment = _process_dimension(evaluation, artifact)

    assert (vulnerabilities.status, vulnerabilities.score_bps) == (
        CheckStatus.FAIL,
        0,
    )
    assert vulnerabilities.reason_code == "OPENSSF_CHECK_BELOW_POLICY"
    assert dimension.aggregate.score_bps == 8750
    assert assessment.aggregate.decision is Decision.FAIL


def test_inconclusive_minus_one_is_unknown_and_cannot_inflate_any_score():
    artifact = _fixture("scorecard-v5.5.0-inconclusive.json")
    evaluation = _evaluation(artifact)
    selected = [
        _check(evaluation, check_id) for check_id, _ in OPENSSF_SELECTED_CHECKS
    ]
    dimension, assessment = _process_dimension(evaluation, artifact)

    assert all(item.status is CheckStatus.UNKNOWN for item in selected)
    assert all(item.score_bps is None for item in selected)
    assert all(item.score_bps != 0 for item in selected)
    assert dimension.aggregate.score_bps is None
    assert dimension.aggregate.observed_score_bps is None
    assert dimension.aggregate.included_weight == 0
    assert dimension.aggregate.eligible_weight == len(OPENSSF_SELECTED_CHECKS)
    assert assessment.aggregate.decision is Decision.INDETERMINATE


def test_upstream_aggregate_is_discarded_without_even_interpreting_its_value():
    high = _raw("scorecard-v5.5.0-inconclusive.json")
    low = json.loads(json.dumps(high))
    high["score"] = 10.0
    low["score"] = {"not": "scoring input"}
    high_eval = _evaluation(_artifact("aggregate-high", high))
    low_eval = _evaluation(_artifact("aggregate-low", low))

    def normalized(evaluation):
        return [
            (item.id, item.status, item.score_bps, item.reason_code)
            for item in evaluation.checks
        ]

    assert normalized(high_eval) == normalized(low_eval)
    assert high_eval.aggregate_disposition == low_eval.aggregate_disposition == "discarded"


def test_unselected_check_payloads_are_not_normalized_or_scored():
    raw = _raw()
    maintained = next(item for item in raw["checks"] if item["name"] == "Maintained")
    maintained.clear()
    maintained.update({"name": "Maintained", "upstream_shape_drift": True})
    evaluation = _evaluation(_artifact("unselected-check-drift", raw))

    assert all(item.status is CheckStatus.PASS for item in evaluation.checks)


def test_v53_payload_is_error_not_normalized_as_pinned_v55():
    raw = _raw()
    raw["scorecard"]["version"] = "v5.3.0"
    artifact = _artifact("version-v5.3.0", raw)
    evaluation = _evaluation(artifact)

    assert all(item.status is CheckStatus.ERROR for item in evaluation.checks)
    assert {item.reason_code for item in evaluation.checks} == {
        "OPENSSF_VERSION_MISMATCH"
    }
    assert evaluation.provenance.tool_version == "v5.3.0"
    assert all(item.score_bps is None for item in evaluation.checks)


def test_tool_commit_mismatch_is_a_separate_error():
    raw = _raw()
    raw["scorecard"]["commit"] = "0" * 40
    evaluation = _evaluation(_artifact("tool-commit-mismatch", raw))

    assert {item.reason_code for item in evaluation.checks} == {
        "OPENSSF_TOOL_COMMIT_MISMATCH"
    }
    assert all(item.status is CheckStatus.ERROR for item in evaluation.checks)


def test_api_404_collection_is_typed_unavailable_and_never_passes(monkeypatch):
    def unavailable(*args, **kwargs):
        raise urllib.error.HTTPError(
            "https://api.securityscorecards.dev/projects/github.com/example/missing",
            404,
            "Not Found",
            {},
            None,
        )

    monkeypatch.setattr(urllib.request, "urlopen", unavailable)
    collection = collect_openssf_scorecard(
        "example/missing", collected_at="2026-08-03T00:00:00Z"
    )
    evaluation = evaluate_process_supply_chain_collection(
        policy=load_policy(POLICY_PATH), collection=collection
    )

    assert collection.state is OpenSSFCollectionState.UNAVAILABLE
    assert collection.http_status == 404
    assert collection.artifact is None
    assert all(item.status is CheckStatus.UNKNOWN for item in evaluation.checks)
    assert {item.reason_code for item in evaluation.checks} == {
        "OPENSSF_API_UNAVAILABLE"
    }
    assert all(item.score_bps is None for item in evaluation.checks)


def test_local_collection_clock_does_not_change_unavailable_check_evidence(monkeypatch):
    def unavailable(*args, **kwargs):
        raise urllib.error.HTTPError(
            "https://api.securityscorecards.dev/projects/github.com/example/missing",
            404,
            "Not Found",
            {},
            None,
        )

    monkeypatch.setattr(urllib.request, "urlopen", unavailable)
    policy = load_policy(POLICY_PATH)
    first = evaluate_process_supply_chain_collection(
        policy=policy,
        collection=collect_openssf_scorecard(
            "example/missing", collected_at="2026-08-03T00:00:00Z"
        ),
    )
    second = evaluate_process_supply_chain_collection(
        policy=policy,
        collection=collect_openssf_scorecard(
            "example/missing", collected_at="2030-01-01T12:34:56Z"
        ),
    )

    assert first.checks == second.checks
    assert not any(
        entry["kind"] == "collection_time"
        for check in first.checks
        for entry in check.evidence
    )


def test_unsupported_is_unknown_not_not_applicable():
    raw = _raw()
    _replace_check(
        raw,
        "Code-Review",
        score=-1,
        reason="check is not supported for this repository host",
    )
    check = _check(
        _evaluation(_artifact("unsupported-code-review", raw)),
        "process.code_review",
    )

    assert check.status is CheckStatus.UNKNOWN
    assert check.score_bps is None
    assert check.reason_code == "OPENSSF_CHECK_UNSUPPORTED"


def test_not_applicable_requires_matching_versioned_predicate_and_proof():
    policy = load_policy(POLICY_PATH)
    predicate = next(
        item.applicability.rule
        for item in policy.checks
        if item.id == "process.signed_releases"
    )
    proof = OpenSSFApplicability(
        check_id="process.signed_releases",
        predicate=predicate,
        evidence="release-policy-v1 section 2 declares no published artifacts",
    )
    check = _check(_evaluation(applicability=(proof,)), "process.signed_releases")

    assert check.status is CheckStatus.NOT_APPLICABLE
    assert check.score_bps is None
    assert check.reason_code == "OPENSSF_NOT_APPLICABLE_PROVEN"
    assert {item["kind"] for item in check.evidence} >= {
        "applicability_predicate",
        "applicability_proof",
    }


def test_invalid_not_applicable_claim_is_error_not_na():
    proof = OpenSSFApplicability(
        check_id="process.signed_releases",
        predicate="repository currently has no tags",
        evidence="an empty tag list",
    )
    check = _check(_evaluation(applicability=(proof,)), "process.signed_releases")

    assert check.status is CheckStatus.ERROR
    assert check.reason_code == "OPENSSF_APPLICABILITY_EVIDENCE_INVALID"


def test_missing_selected_check_is_unknown_and_control_is_error():
    raw = _raw()
    raw["checks"] = [item for item in raw["checks"] if item["name"] != "CI-Tests"]
    evaluation = _evaluation(_artifact("missing-ci", raw))

    assert _check(evaluation, "process.ci_tests").status is CheckStatus.UNKNOWN
    assert _check(evaluation, "process.ci_tests").reason_code == (
        "OPENSSF_SELECTED_CHECK_MISSING"
    )
    assert _check(evaluation, "process.supply_chain_evidence").status is CheckStatus.ERROR


def test_changed_selected_check_set_does_not_silently_shrink_denominator():
    raw = _raw()
    renamed = next(item for item in raw["checks"] if item["name"] == "CI-Tests")
    renamed["name"] = "CI-Tests-Renamed"
    artifact = _artifact("changed-check-set", raw)
    evaluation = _evaluation(artifact)
    dimension, assessment = _process_dimension(evaluation, artifact)

    assert _check(evaluation, "process.supply_chain_evidence").reason_code == (
        "OPENSSF_SELECTED_CHECK_SET_CHANGED"
    )
    assert _check(evaluation, "process.ci_tests").status is CheckStatus.UNKNOWN
    assert dimension.aggregate.included_weight == 7
    assert dimension.aggregate.eligible_weight == 8
    assert dimension.aggregate.score_bps is None
    assert assessment.aggregate.decision is Decision.INDETERMINATE


def test_insufficient_auth_is_unknown_and_capability_gap_is_recorded():
    raw = _raw()
    _replace_check(
        raw,
        "Branch-Protection",
        score=-1,
        reason="some github tokens cannot read classic branch protection rules",
    )
    capabilities = GitHubCapabilities(
        token_kind="fine_grained",
        granted=("contents", "repository_metadata"),
        unavailable=("branch_protection",),
    )
    check = _check(
        _evaluation(_artifact("insufficient-auth", raw), capabilities=capabilities),
        "process.branch_protection",
    )

    assert check.status is CheckStatus.UNKNOWN
    assert check.reason_code == "OPENSSF_INSUFFICIENT_AUTH"
    capability_record = next(
        item["value"] for item in check.evidence if item["kind"] == "github_capabilities"
    )
    assert json.loads(capability_record)["unavailable"] == ["branch_protection"]


def test_output_evidence_redacts_token_shaped_text():
    raw = _raw()
    _replace_check(
        raw,
        "CI-Tests",
        reason="request failed with Bearer ghp_abcdefghijklmnopqrstuvwxyz0123456789",
    )
    evaluation = _evaluation(_artifact("redacted-reason", raw))
    reason = next(
        item["value"]
        for item in _check(evaluation, "process.ci_tests").evidence
        if item["kind"] == "openssf_reason"
    )

    assert "ghp_" not in reason
    assert "[REDACTED]" in reason


def test_checksum_verified_artifact_rejects_tampered_fixture_bytes():
    fixture = _fixture("scorecard-v5.5.0-happy.json")
    with pytest.raises(ValueError, match="declared sha256"):
        EvidenceArtifact(
            id=fixture.id,
            path=fixture.path,
            sha256=fixture.sha256,
            content=fixture.content + b" ",
        )


def test_fixtures_keep_the_observed_rest_wire_shape_and_full_check_list():
    for name in (
        "scorecard-v5.5.0-happy.json",
        "scorecard-v5.5.0-inconclusive.json",
    ):
        raw = _raw(name)
        assert set(raw) == {"date", "repo", "scorecard", "score", "checks"}
        assert raw["scorecard"] == {
            "version": PINNED_OPENSSF_SCORECARD_VERSION,
            "commit": PINNED_OPENSSF_SCORECARD_COMMIT,
        }
        assert len(raw["checks"]) == 18
        assert all(
            set(item)
            == {"name", "score", "reason", "details", "documentation"}
            and set(item["documentation"]) == {"short", "url"}
            for item in raw["checks"]
        )


def test_policy_selects_each_raw_fact_without_making_control_score_eligible():
    policy = load_policy(POLICY_PATH)
    process = {item.id: item for item in policy.checks if item.dimension == "process_supply_chain"}

    assert set(process) == {
        "process.supply_chain_evidence",
        *(check_id for check_id, _ in OPENSSF_SELECTED_CHECKS),
    }
    assert process["process.supply_chain_evidence"].score_eligible is False
    for check_id, _ in OPENSSF_SELECTED_CHECKS:
        assert process[check_id].score_eligible is True
        assert (process[check_id].criterion.op, process[check_id].criterion.value) == (
            "eq",
            10000,
        )


def test_no_runtime_or_scoring_dependency_was_added_for_http_collection():
    assert "dependencies = []" in (REPO_ROOT / "pyproject.toml").read_text(
        encoding="utf-8"
    )
    assert "requests" not in (REPO_ROOT / "requirements-score.txt").read_text(
        encoding="utf-8"
    ).casefold()
