"""ADR-002 S5 bounded code-health adapter gates."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from tools.score_engine import (
    CheckStatus,
    EvidenceArtifact,
    canonical_json_bytes,
    evaluate_code_health_evidence,
    load_policy,
    policy_from_dict,
    _local_evidence_artifact,
)


REPO_ROOT = Path(__file__).resolve().parents[1]
FIXTURES = REPO_ROOT / "tests" / "fixtures_score" / "code_health"


def _fixture(name: str) -> EvidenceArtifact:
    content = (FIXTURES / name).read_bytes()
    return EvidenceArtifact(
        id=f"code-health.{name.removesuffix('.json')}",
        path=f"tests/fixtures_score/code_health/{name}",
        sha256=hashlib.sha256(content).hexdigest(),
        content=content,
    )


def _artifact(name: str, value: object) -> EvidenceArtifact:
    content = canonical_json_bytes(value)
    return EvidenceArtifact(
        id=f"code-health.{name}",
        path=f"tests/fixtures_score/code_health/{name}.json",
        sha256=hashlib.sha256(content).hexdigest(),
        content=content,
    )


def _evaluation(*, cc=None, mi=None, versions=None, policy=None):
    return evaluate_code_health_evidence(
        policy=policy or load_policy(REPO_ROOT / "scorecard" / "policy-v1.json"),
        scope_artifact=_fixture("scope.json"),
        tool_versions=versions or _fixture("tool-versions.json"),
        radon_complexity=cc or _fixture("radon-cc.json"),
        radon_mi=mi or _fixture("radon-mi.json"),
    )


def _check(evaluation, check_id: str):
    return next(item for item in evaluation.checks if item.id == check_id)


def test_coverage_timestamp_is_noncanonical_but_measurement_changes_are_bound(
    tmp_path,
):
    first = json.loads((FIXTURES / "coverage.json").read_text(encoding="utf-8"))
    second = json.loads(json.dumps(first))
    second["meta"]["timestamp"] = "2030-01-01T12:34:56.000000"
    evidence_dir = tmp_path / "evidence"
    evidence_dir.mkdir()
    path = evidence_dir / "coverage.json"
    path.write_bytes(canonical_json_bytes(first))
    first_artifact = _local_evidence_artifact(
        evidence_dir, "coverage.json", "test.coverage"
    )
    path.write_bytes(canonical_json_bytes(second))
    second_artifact = _local_evidence_artifact(
        evidence_dir, "coverage.json", "test.coverage"
    )
    second["totals"]["covered_lines"] -= 1
    path.write_bytes(canonical_json_bytes(second))
    changed_artifact = _local_evidence_artifact(
        evidence_dir, "coverage.json", "test.coverage"
    )

    assert first_artifact is not None
    assert second_artifact is not None
    assert changed_artifact is not None
    assert first_artifact.raw_sha256 != second_artifact.raw_sha256
    assert first_artifact.sha256 == second_artifact.sha256
    assert changed_artifact.sha256 != second_artifact.sha256
    assert first_artifact.normalization == "coverage-json-volatile-v1"


def test_real_radon_fixture_reports_scope_maximum_distribution_counts_and_coverage():
    evaluation = _evaluation()

    assert evaluation.complexity.to_dict() == {
        "file_count": 2,
        "parsed_file_count": 2,
        "measurement_coverage": {"numerator": 2, "denominator": 2},
        "unmeasured_files": [],
        "parse_error_files": [],
        "block_count": 4,
        "maximum": 15,
        "mean_milli": 7750,
        "distribution": {"A": 2, "B": 1, "C": 1, "D": 0, "E": 0, "F": 0},
    }
    assert evaluation.scope.to_dict()["scopes"] == {
        "production": ["src/example/core.py", "src/example/service.py"],
        "generated": ["src/example/generated_models.py"],
        "vendored": ["vendor/example_vendor.py"],
        "fixture": ["tests/fixtures/example_payload.py"],
    }
    assert all(item.status is CheckStatus.PASS for item in evaluation.checks)


def test_parser_error_is_error_and_names_the_file_instead_of_omitting_it():
    evaluation = _evaluation(cc=_fixture("radon-cc-parse-error.json"))
    parser = _check(evaluation, "code.production_scope_parsed")

    assert parser.status is CheckStatus.ERROR
    assert parser.reason_code == "RADON_PARSE_FAILURE"
    assert parser.exclusions == (("PARSE_FAILURE", 1),)
    assert evaluation.complexity.parse_error_files == ("src/example/service.py",)
    assert evaluation.complexity.unmeasured_files == ()


def test_omitted_production_file_is_unknown_and_distinct_from_parse_failure():
    raw = json.loads((FIXTURES / "radon-cc.json").read_text(encoding="utf-8"))
    del raw["src/example/service.py"]
    evaluation = _evaluation(cc=_artifact("radon-unmeasured", raw))
    parser = _check(evaluation, "code.production_scope_parsed")

    assert parser.status is CheckStatus.UNKNOWN
    assert parser.reason_code == "RADON_PRODUCTION_FILE_UNMEASURED"
    assert parser.exclusions == (("UNMEASURED_FILE", 1),)
    assert evaluation.complexity.unmeasured_files == ("src/example/service.py",)
    assert evaluation.complexity.parse_error_files == ()


def test_complexity_exact_policy_threshold_passes_and_ratchet_fails():
    raw_policy = json.loads(
        (REPO_ROOT / "scorecard" / "policy-v1.json").read_text(encoding="utf-8")
    )
    ratchet = json.loads((FIXTURES / "policy-ratchet.json").read_text(encoding="utf-8"))
    target = next(item for item in raw_policy["checks"] if item["id"] == "code.complexity_maximum")
    assert target["criterion"] == {"op": "gte", "value": 0}
    target["criterion"]["value"] = ratchet["base"][target["id"]]
    exact = _evaluation(policy=policy_from_dict(raw_policy))
    maximum = _check(exact, "code.complexity_maximum")
    assert (maximum.status, maximum.score_bps) == (CheckStatus.PASS, 8600)

    target["criterion"]["value"] = ratchet["ratcheted"][target["id"]]
    ratcheted = _evaluation(policy=policy_from_dict(raw_policy))
    assert _check(ratcheted, "code.complexity_maximum").status is CheckStatus.FAIL


def test_maintainability_index_is_diagnostic_only_and_excluded_from_policy_score():
    policy = load_policy(REPO_ROOT / "scorecard" / "policy-v1.json")
    policy_check = next(item for item in policy.checks if item.id == "code.maintainability_index")
    evaluation = _evaluation(policy=policy)

    assert policy_check.score_eligible is False
    assert _check(evaluation, "code.maintainability_index").status is CheckStatus.PASS
    assert evaluation.maintainability_index.to_dict()["diagnostic_only"] is True


def test_shipped_policy_adds_s5_checks_without_adopting_unmeasured_baseline_floors():
    policy = load_policy(REPO_ROOT / "scorecard" / "policy-v1.json")
    metric_ids = {
        "code.complexity_maximum",
        "test.line_coverage",
        "test.branch_coverage",
        "test.mutation_score",
    }
    metrics = [item for item in policy.checks if item.id in metric_ids]
    assert {item.id for item in metrics} == metric_ids
    assert all((item.criterion.op, item.criterion.value) == ("gte", 0) for item in metrics)


def test_radon_tool_version_mismatch_is_error_for_every_code_health_check():
    versions = json.loads((FIXTURES / "tool-versions.json").read_text(encoding="utf-8"))
    versions["tools"]["radon"] = "6.0.0"
    evaluation = _evaluation(versions=_artifact("versions-mismatch", versions))

    assert all(item.status is CheckStatus.ERROR for item in evaluation.checks)
    assert {item.reason_code for item in evaluation.checks} == {"RADON_VERSION_MISMATCH"}


def test_code_health_fixtures_are_committed_real_tool_shapes():
    assert (FIXTURES / "radon-cc.json").is_file()
    assert (FIXTURES / "radon-cc-parse-error.json").is_file()
    assert (FIXTURES / "radon-mi.json").is_file()
    raw = json.loads((FIXTURES / "radon-cc.json").read_text(encoding="utf-8"))
    assert raw["src/example/core.py"][0]["type"] == "function"
    assert raw["src/example/core.py"][0]["rank"] == "C"


def test_scoring_dependencies_are_separate_exact_pins_with_hashes():
    lock = (REPO_ROOT / "requirements-score.txt").read_text(encoding="utf-8")
    logical_lines = [line for line in lock.splitlines() if line and not line.startswith((" ", "#"))]
    assert logical_lines
    assert all("==" in line and line.endswith("\\") for line in logical_lines)
    assert lock.count("--hash=sha256:") >= len(logical_lines)
    for pin in (
        "coverage==7.15.2",
        "ir_measures==0.4.3",
        "mutmut==3.7.0",
        "pytrec-eval-terrier==0.5.10",
        "radon==6.0.1",
    ):
        assert pin in lock
    pyproject = (REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8")
    assert "dependencies = []" in pyproject
