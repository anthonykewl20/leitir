"""Opt-in live release-profile composition check for ADR-002 S8."""

from __future__ import annotations

import hashlib
import os
from pathlib import Path
import subprocess

import pytest

from tools.score_engine import (
    ADR001_OFFLINE_GATE_ARGV,
    CheckStatus,
    CommandExecution,
    Decision,
    EvidenceArtifact,
    Profile,
    load_policy,
    run_profile_assessment,
)


REPO_ROOT = Path(__file__).resolve().parents[1]
pytestmark = pytest.mark.skipif(
    os.environ.get("LEITIR_ENABLE_SCORE_LIVE") != "1",
    reason="set LEITIR_ENABLE_SCORE_LIVE=1 to run live score e2e checks",
)


def _git(root: Path, *argv: str) -> None:
    subprocess.run(("git", *argv), cwd=root, check=True, capture_output=True)


def test_live_release_collection_stays_visible_and_cannot_fill_other_evidence(
    tmp_path, monkeypatch
):
    repository = tmp_path / "repository"
    (repository / "src" / "leitir").mkdir(parents=True)
    (repository / "src" / "leitir" / "marker.py").write_text("MARKER = 1\n")
    _git(repository, "init", "-q")
    _git(repository, "config", "user.name", "Score Live Test")
    _git(repository, "config", "user.email", "score-live@example.invalid")
    _git(
        repository,
        "remote",
        "add",
        "origin",
        "https://github.com/anthonykewl20/leitir.git",
    )
    _git(repository, "add", ".")
    _git(repository, "commit", "-q", "-m", "fixture")

    content = (
        REPO_ROOT / "tests" / "fixtures_score" / "engine" / "pytest-pass.xml"
    ).read_bytes()
    junit = EvidenceArtifact(
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
        "tools.score_engine.collect_adr001_pytest_junit", lambda _root: junit
    )

    assessment = run_profile_assessment(
        root=repository,
        policy=load_policy(REPO_ROOT / "scorecard" / "policy-v1.json"),
        profile=Profile.RELEASE,
        enable_live=True,
    )

    assert assessment.profile is Profile.RELEASE
    assert assessment.aggregate.decision in {Decision.FAIL, Decision.INDETERMINATE}
    assert assessment.aggregate.decision is not Decision.PASS
    process_checks = tuple(
        check for check in assessment.checks if check.id.startswith("process.")
    )
    assert process_checks
    assert all(not check.missing for check in process_checks)
    assert any(
        check.status in {CheckStatus.FAIL, CheckStatus.UNKNOWN, CheckStatus.ERROR}
        for check in process_checks
    )
