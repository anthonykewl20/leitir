"""ADR-002 S9 published dogfood assessment regeneration gate."""

from __future__ import annotations

import io
import json
import subprocess
from pathlib import Path

import pytest

from tools.score_engine import ExitCode, main

REPO_ROOT = Path(__file__).resolve().parents[1]
PINNED_SUBJECT_COMMIT = "45c028b69fdbab65e6288f82f9f4d0ecbc7e95d4"
PINNED_REPOSITORY = "https://github.com/anthonykewl20/leitir.git"
PUBLISHED_EVIDENCE = REPO_ROOT / ".leitir-score" / "evidence"
PUBLISHED_JSON = REPO_ROOT / "scorecard" / "leitir-assessment.json"
PUBLISHED_HTML = REPO_ROOT / "scorecard" / "leitir-assessment.html"
HISTORICAL_SCORECARDS = {
    "docs/leitir-engine-scorecard.html",
    "docs/leitir-engine-scorecard.png",
    "docs/leitir-engine-scorecard-v2.html",
}


def _git(root: Path, *argv: str) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(
        ("git", *argv),
        cwd=root,
        check=True,
        capture_output=True,
    )


def _assert_published_matches(
    generated_json: Path,
    generated_html: Path,
    *,
    published_json: Path = PUBLISHED_JSON,
    published_html: Path = PUBLISHED_HTML,
) -> None:
    assert generated_json.read_bytes() == published_json.read_bytes(), (
        "published canonical JSON drifted; regenerate it from the pinned clean subject"
    )
    assert generated_html.read_bytes() == published_html.read_bytes(), (
        "published HTML drifted; regenerate it from the pinned canonical assessment"
    )


def _require_pinned_commit() -> None:
    """Skip loudly when the pinned subject commit is not in local history.

    A shallow checkout (``--depth 1``, ``fetch-depth: 1``) does not contain it,
    and ``git checkout`` would then raise CalledProcessError and read as a build
    break rather than a missing precondition. The skip names the cause and the
    fix, because a drift check that vanishes quietly is worse than one that
    fails: the published scorecard would then be unguarded with nothing saying so.
    """
    probe = subprocess.run(
        ("git", "cat-file", "-e", f"{PINNED_SUBJECT_COMMIT}^{{commit}}"),
        cwd=str(REPO_ROOT),
        capture_output=True,
        check=False,
    )
    if probe.returncode != 0:
        pytest.skip(
            f"pinned subject commit {PINNED_SUBJECT_COMMIT} is absent from local "
            "history, so the published assessment CANNOT be checked for drift. "
            "This is a shallow clone; fetch full history (fetch-depth: 0) to run it."
        )


def test_published_assessment_matches_fresh_clean_pinned_run(tmp_path):
    """Byte comparison catches hand edits and unregenerated engine drift."""
    _require_pinned_commit()
    subject = tmp_path / "pinned-subject"
    _git(
        tmp_path,
        "clone",
        "--quiet",
        "--no-hardlinks",
        "--no-checkout",
        str(REPO_ROOT),
        str(subject),
    )
    _git(subject, "checkout", "--quiet", "--detach", PINNED_SUBJECT_COMMIT)
    _git(subject, "remote", "set-url", "origin", PINNED_REPOSITORY)
    assert _git(subject, "status", "--porcelain=v1").stdout == b""

    generated_json = tmp_path / "assessment.json"
    generated_html = tmp_path / "assessment.html"
    stdout = io.StringIO()
    stderr = io.StringIO()
    code = main(
        [
            "run",
            "--profile",
            "offline",
            "--root",
            str(subject),
            "--evidence-dir",
            str(PUBLISHED_EVIDENCE),
            "--json-out",
            str(generated_json),
            "--html-out",
            str(generated_html),
        ],
        stdout=stdout,
        stderr=stderr,
    )

    assert code == ExitCode.COMPLETE_PASS
    assert stderr.getvalue() == ""
    _assert_published_matches(generated_json, generated_html)

    assessment = json.loads(generated_json.read_bytes())
    assert assessment["subject"] == {
        "commit_sha": PINNED_SUBJECT_COMMIT,
        "repository": PINNED_REPOSITORY,
        "worktree": "clean",
    }
    assert assessment["aggregate"]["decision"] == "pass"
    assert assessment["aggregate"]["complete"] is True
    assert assessment["aggregate"]["score_bps"] is None
    assert assessment["aggregate"]["observed_score_bps"] == 8697
    assert assessment["aggregate"]["lower_bound_bps"] == 7247
    assert assessment["aggregate"]["upper_bound_bps"] == 8914
    assert assessment["aggregate"]["blockers"] == []
    performance = next(
        item for item in assessment["checks"]
        if item["id"] == "performance.controlled_baseline"
    )
    assert performance["status"] == "pass"
    assert "release_readiness=not_claimed" in stdout.getvalue()

    consumed_paths = {item["path"] for item in assessment["evidence"]}
    assert consumed_paths.isdisjoint(HISTORICAL_SCORECARDS)
    pytest_evidence = next(
        item for item in assessment["evidence"] if item["id"] == "engine.pytest-junit"
    )
    assert pytest_evidence["normalization"] == (
        "pytest-junit-volatile-v1"
    )


def test_drift_comparator_rejects_hand_edits_to_either_published_file(tmp_path):
    generated_json = tmp_path / "generated.json"
    generated_html = tmp_path / "generated.html"
    edited_json = tmp_path / "edited.json"
    edited_html = tmp_path / "edited.html"
    generated_json.write_bytes(PUBLISHED_JSON.read_bytes())
    generated_html.write_bytes(PUBLISHED_HTML.read_bytes())
    edited_json.write_bytes(PUBLISHED_JSON.read_bytes() + b"\n")
    edited_html.write_bytes(PUBLISHED_HTML.read_bytes() + b"\n")

    with pytest.raises(AssertionError, match="canonical JSON drifted"):
        _assert_published_matches(
            generated_json,
            generated_html,
            published_json=edited_json,
        )
    with pytest.raises(AssertionError, match="HTML drifted"):
        _assert_published_matches(
            generated_json,
            generated_html,
            published_html=edited_html,
        )


def test_manual_scorecards_are_explicitly_historical_not_evidence():
    for name in (
        "leitir-engine-scorecard.html",
        "leitir-engine-scorecard-v2.html",
    ):
        content = (REPO_ROOT / "docs" / name).read_text(encoding="utf-8")
        assert "HISTORICAL MANUAL RESEARCH SNAPSHOT" in content
        assert "../scorecard/leitir-assessment.html" in content
        assert "adr-001-remove-hy3-deterministic-search.md" in content
        assert "adr-002-deterministic-evidence-scoring-engine.md" in content
        assert "must never be consumed by the scorer" in content

    readme = (REPO_ROOT / "README.md").read_text(encoding="utf-8")
    assert "historical PNG snapshot" in readme
    assert "docs/leitir-engine-scorecard.png" in readme
    assert "These manual\nsnapshots are never scorer evidence." in readme
