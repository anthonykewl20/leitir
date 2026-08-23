"""Offline intent tests for the schedule/manual live-provider canary."""

from __future__ import annotations

import re
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]
_WORKFLOW = _ROOT / ".github/workflows/live-canary.yml"


def _text() -> str:
    return _WORKFLOW.read_text(encoding="utf-8")


def _job(text: str, name: str) -> str:
    match = re.search(
        rf"(?ms)^  {re.escape(name)}:\n(?P<body>.*?)(?=^  [a-z][a-z0-9-]*:\n|\Z)",
        text,
    )
    assert match is not None, f"missing workflow job {name}"
    return match.group("body")


def test_canary_is_nightly_manual_only_and_product_failures_are_not_hidden() -> None:
    text = _text()
    trigger = text[text.index("on:\n") : text.index("\npermissions:")]
    assert "workflow_dispatch:" in trigger
    assert "schedule:" in trigger
    assert "cron: '0 3 * * *'" in trigger
    assert "pull_request:" not in trigger
    assert not re.search(r"(?m)^    continue-on-error:", text), (
        "job-level continue-on-error would hide product regressions"
    )
    assert "continue-on-error: true" in text, "probe steps must leave classification to the fail-closed classifier"


def test_dispatch_inputs_are_typed_and_extra_job_is_manual_only() -> None:
    text = _text()
    trigger = text[text.index("on:\n") : text.index("\npermissions:")]
    assert "run_surfaces:" in trigger and "type: choice" in trigger
    assert "enable_tree_v2:" in trigger and "type: boolean" in trigger
    assert "enable_stream_v2:" in trigger and "type: boolean" in trigger
    assert "enable_index_v2:" in trigger and "type: boolean" in trigger
    assert "extra_tests:" in trigger and "type: string" in trigger
    gate = _job(text, "gate")
    assert "GITHUB_EVENT_NAME: ${{ github.event_name }}" in gate
    assert "DISPATCH_EXTRA_TESTS: ${{ inputs.extra_tests }}" in gate
    assert "extra_tests_requested:" in gate
    assert "DISPATCH_EXTRA_TEST_ALLOWLIST" not in gate
    extra = _job(text, "extra-live")
    assert "needs.gate.outputs.extra_tests != ''" in extra
    assert "python -m pytest -v" in extra
    assert "--live-canary-events=events.json" in extra
    assert "scripts/classify_live_canary.py" in extra


def test_baseline_runs_only_selected_opt_in_live_tests() -> None:
    body = _job(_text(), "baseline-live")
    assert "LEITIR_ENABLE_LIVE_E2E: '1'" in body
    assert "tests/test_global_e2e_live.py tests/test_engine_e2e_live.py" in body
    assert "tests/" in body
    assert "python -m pytest -q --tb=short -p tests.live_canary_plugin" in body
    assert body.count("python -m pytest") == 1


def test_each_search_v2_surface_has_a_separate_fail_closed_gate() -> None:
    text = _text()
    expected = {
        "truncated-tree-recovery": ("tree_v2", "tests/test_tree_recovery_e2e_live.py"),
        "streamed-large-blob": ("stream_v2", "tests/test_streaming_e2e_live.py"),
        "index-vs-scan-recall": ("index_v2", "tests/test_index_recall_e2e_live.py"),
    }
    gate = _job(text, "gate")
    assert "python scripts/live_canary_gate.py" in gate
    for job_name, (gate_output, test_path) in expected.items():
        body = _job(text, job_name)
        assert f"needs.gate.outputs.{gate_output} == 'true'" in body
        assert test_path in body
        assert "LEITIR_ENABLE_LIVE_E2E: '1'" in body
        assert "continue-on-error: true" in body
        assert "scripts/classify_live_canary.py" in body


def test_search_v2_canaries_use_immutable_public_fixture_provenance() -> None:
    text = _text()
    tree = _job(text, "truncated-tree-recovery")
    stream = _job(text, "streamed-large-blob")
    index = _job(text, "index-vs-scan-recall")

    sha = r"[0-9a-f]{40}"
    assert "LIVE_CANARY_FIXTURE_REPO: torvalds/linux" in tree
    assert re.search(rf"LIVE_CANARY_FIXTURE_COMMIT: {sha}$", tree, re.MULTILINE)
    assert "LIVE_CANARY_EXPECT_TRUNCATED_TREE: 'true'" in tree

    assert "LIVE_CANARY_FIXTURE_REPO: torvalds/linux" in stream
    assert re.search(rf"LIVE_CANARY_FIXTURE_COMMIT: {sha}$", stream, re.MULTILINE)
    assert re.search(rf"LIVE_CANARY_FIXTURE_BLOB_SHA: {sha}$", stream, re.MULTILINE)
    size = re.search(r"LIVE_CANARY_FIXTURE_SIZE: '(\d+)'", stream)
    assert size is not None and int(size.group(1)) > 2 * 1024 * 1024
    assert "LIVE_CANARY_REQUIRE_STREAM_SHA_VERIFICATION: 'true'" in stream

    assert "LIVE_CANARY_FIXTURE_REPO: python/cpython" in index
    assert re.search(rf"LIVE_CANARY_FIXTURE_COMMIT: {sha}$", index, re.MULTILINE)


def test_index_recall_requires_full_source_identity_equality() -> None:
    body = _job(_text(), "index-vs-scan-recall")
    assert "LIVE_CANARY_COMPARE_FULL_SOURCE_IDENTITY: 'true'" in body
    assert (
        "LIVE_CANARY_SOURCE_IDENTITY_FIELDS: slug,commit_sha,path,blob_sha,start_line,end_line"
        in body
    )
    assert "full-identity equality" in body


def test_actions_are_pinned_to_commit_shas() -> None:
    uses = re.findall(r"(?m)^\s*- uses: ([^\s#]+)", _text())
    assert uses
    assert all(re.fullmatch(r"[^@]+@[0-9a-f]{40}", action) for action in uses)


def test_final_summary_is_always_run_and_carries_every_classification() -> None:
    text = _text()
    body = _job(text, "summarize")
    assert "if: ${{ always() }}" in body
    assert "scripts/classify_live_canary.py --summary-from-env" in body
    assert "EXTRA_TESTS_REQUESTED" in body
    assert "EXTRA_RESULT" in body
    classifier = (_ROOT / "scripts/classify_live_canary.py").read_text(encoding="utf-8")
    for classification in (
        "pass",
        "product-failure",
        "infra-failure",
        "configuration-failure",
        "skipped-not-landed",
    ):
        assert classification in classifier


def test_every_workflow_referenced_test_file_exists() -> None:
    """Static canary-integrity assertion (#197 C-1/AC-1).

    Every ``tests/…py`` path named anywhere in live-canary.yml must exist on
    disk.  A workflow naming a missing test file is a silent one-surface
    canary: the gate variable would flip, pytest would exit 4 (collection
    error), ``continue-on-error`` would swallow it, and the classifier would
    read a nonexistent/empty events file.  This test fails CI instead.
    """
    referenced = sorted(set(re.findall(r"tests/[A-Za-z0-9_/.-]+\.py", _text())))
    assert referenced, "live-canary.yml must reference at least one test file"
    missing = [path for path in referenced if not (_ROOT / path).is_file()]
    assert not missing, f"live-canary.yml references missing test files: {missing}"
