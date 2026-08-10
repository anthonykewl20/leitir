"""ADR-002 S8 deterministic CLI and profile end-to-end gates."""

from __future__ import annotations

import hashlib
import io
import subprocess
from pathlib import Path

import pytest
from test_score_render import DIMENSIONS, render_assessment

from tools.score_engine import (
    ADR001_OFFLINE_GATE_ARGV,
    POLICY_SCHEMA_VERSION,
    CheckMode,
    CheckPolicy,
    CheckResult,
    CheckStatus,
    CommandExecution,
    Criterion,
    Decision,
    DimensionPolicy,
    EvidenceArtifact,
    ExitCode,
    Policy,
    Producer,
    Profile,
    Subject,
    evaluate,
    load_policy,
    main,
)

REPO_ROOT = Path(__file__).resolve().parents[1]
PYTEST_PASS = REPO_ROOT / "tests" / "fixtures_score" / "engine" / "pytest-pass.xml"


@pytest.mark.parametrize(
    ("status", "score_bps", "expected"),
    [
        (CheckStatus.PASS, 10000, ExitCode.COMPLETE_PASS),
        (CheckStatus.FAIL, 0, ExitCode.KNOWN_FAILURE),
        (CheckStatus.UNKNOWN, None, ExitCode.INDETERMINATE),
    ],
)
def test_render_cli_process_exits_follow_the_canonical_decision(
    tmp_path, status, score_bps, expected
):
    assessment = render_assessment(status=status, score_bps=score_bps)
    source = tmp_path / "assessment.json"
    destination = tmp_path / "assessment.html"
    source.write_bytes(assessment.to_bytes())
    stdout = io.StringIO()
    stderr = io.StringIO()

    actual = main(
        ["render", "--assessment", str(source), "--html", str(destination)],
        stdout=stdout,
        stderr=stderr,
    )

    assert actual == expected
    assert destination.read_bytes()
    assert f"decision={assessment.aggregate.decision.value}" in stdout.getvalue()
    assert stderr.getvalue() == ""


def test_malformed_cli_usage_and_invalid_assessment_exit_two(tmp_path):
    malformed = tmp_path / "malformed.json"
    malformed.write_text('{"schema_version":', encoding="utf-8")

    assert main([]) == ExitCode.INVALID_USAGE_OR_POLICY
    assert main(
        [
            "render",
            "--assessment",
            str(malformed),
            "--html",
            str(tmp_path / "never.html"),
        ],
        stderr=io.StringIO(),
    ) == ExitCode.INVALID_USAGE_OR_POLICY


def test_output_filesystem_infrastructure_error_exits_three(tmp_path):
    assessment = render_assessment()
    source = tmp_path / "assessment.json"
    blocked_parent = tmp_path / "not-a-directory"
    source.write_bytes(assessment.to_bytes())
    blocked_parent.write_text("file\n", encoding="utf-8")

    assert main(
        [
            "render",
            "--assessment",
            str(source),
            "--html",
            str(blocked_parent / "assessment.html"),
        ],
        stderr=io.StringIO(),
    ) == ExitCode.INDETERMINATE


def test_release_cannot_pass_with_any_required_unresolved_evidence():
    policy = load_policy(REPO_ROOT / "scorecard" / "policy-v1.json")
    results = tuple(
        CheckResult(
            id=check.id,
            status=CheckStatus.PASS,
            score_bps=10000,
            reason_code="FIXTURE_EVIDENCE_PASSED",
        )
        for check in policy.checks
        if not check.id.startswith("process.")
        and check.id != "performance.controlled_baseline"
    )
    subject = Subject("https://example.invalid/leitir", "1" * 40, "clean")
    producer = Producer("leitir-score-engine", "8", "2" * 40)

    offline = evaluate(
        policy,
        results,
        profile=Profile.OFFLINE,
        subject=subject,
        producer=producer,
    )
    release = evaluate(
        policy,
        results,
        profile=Profile.RELEASE,
        subject=subject,
        producer=producer,
    )

    assert offline.aggregate.decision is Decision.PASS
    assert release.aggregate.decision is Decision.INDETERMINATE
    assert release.exit_code is ExitCode.INDETERMINATE
    assert release.aggregate.complete is False
    assert {
        blocker.check_id for blocker in release.aggregate.blockers
    } >= {
        "process.supply_chain_evidence",
        "performance.controlled_baseline",
    }


def _offline_run_policy() -> Policy:
    checks = [
        CheckPolicy(
            id=check_id,
            dimension="engine_correctness",
            weight=1,
            score_eligible=True,
            criterion=Criterion("eq", 10000),
            offline_mode=CheckMode.REQUIRED,
            release_mode=CheckMode.REQUIRED,
        )
        for check_id in (
            "engine.offline_contracts",
            "engine.retired_surfaces_absent",
        )
    ]
    checks.extend(
        CheckPolicy(
            id=f"placeholder.{dimension}",
            dimension=dimension,
            weight=1,
            score_eligible=False,
            criterion=Criterion("eq", 10000),
            offline_mode=CheckMode.ADVISORY,
            release_mode=CheckMode.ADVISORY,
        )
        for dimension in DIMENSIONS
        if dimension != "engine_correctness"
    )
    return Policy(
        schema_version=POLICY_SCHEMA_VERSION,
        id="offline-run-policy-v1",
        dimensions=tuple(DimensionPolicy(item, 1) for item in DIMENSIONS),
        checks=tuple(checks),
    )


def _git(root: Path, *argv: str) -> None:
    subprocess.run(
        ("git", *argv),
        cwd=root,
        check=True,
        capture_output=True,
    )


def test_offline_run_composes_collection_evaluation_json_and_html(
    tmp_path, monkeypatch
):
    repository = tmp_path / "repository"
    (repository / "src" / "leitir").mkdir(parents=True)
    (repository / "scorecard").mkdir()
    (repository / "src" / "leitir" / "marker.py").write_text("MARKER = 1\n")
    policy = _offline_run_policy()
    (repository / "scorecard" / "policy-v1.json").write_text(policy.to_json())
    _git(repository, "init", "-q")
    _git(repository, "config", "user.name", "Score Test")
    _git(repository, "config", "user.email", "score@example.invalid")
    _git(repository, "remote", "add", "origin", "https://example.invalid/fixture")
    _git(repository, "add", ".")
    _git(repository, "commit", "-q", "-m", "fixture")

    content = PYTEST_PASS.read_bytes()
    artifact = EvidenceArtifact(
        id="engine.pytest-junit",
        path=".leitir-score/evidence/adr001-offline-junit.xml",
        sha256=hashlib.sha256(content).hexdigest(),
        content=content,
        command=CommandExecution(
            argv=ADR001_OFFLINE_GATE_ARGV,
            process_exit=0,
            collector_reason_code="COLLECTOR_COMPLETE",
        ),
    )
    monkeypatch.setattr(
        "tools.score_engine.collect_adr001_pytest_junit", lambda _root: artifact
    )
    json_out = tmp_path / "assessment.json"
    html_out = tmp_path / "assessment.html"
    stdout = io.StringIO()

    code = main(
        [
            "run",
            "--profile",
            "offline",
            "--root",
            str(repository),
            "--json-out",
            str(json_out),
            "--html-out",
            str(html_out),
        ],
        stdout=stdout,
        stderr=io.StringIO(),
    )

    assert code == ExitCode.COMPLETE_PASS
    assert json_out.read_bytes().startswith(b'{"aggregate":')
    assert html_out.read_bytes().startswith(b"<!doctype html>")
    assert "decision=pass" in stdout.getvalue()
    assert "release_readiness=not_claimed" in stdout.getvalue()
