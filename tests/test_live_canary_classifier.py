"""Deterministic offline tests for live-canary failure classification."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from email.message import Message
from http.client import IncompleteRead
from pathlib import Path
from urllib.error import HTTPError

import pytest
from live_canary_plugin import classify_exception

from leitir import _http

_ROOT = Path(__file__).resolve().parents[1]
_CLASSIFIER = _ROOT / "scripts/classify_live_canary.py"
_GATE = _ROOT / "scripts/live_canary_gate.py"
_SECRET = _ROOT / "scripts/check_live_canary_secret.py"


def _http_error(code: int, headers: dict[str, str] | None = None) -> HTTPError:
    message = Message()
    for key, value in sorted((headers or {}).items()):
        message[key] = value
    return HTTPError("https://example.invalid", code, "fixture", message, None)


@pytest.mark.parametrize(
    ("exc", "expected"),
    [
        (_http_error(429), ("infra-failure", "rate_limited")),
        (_http_error(403, {"X-RateLimit-Remaining": "0"}), ("infra-failure", "rate_limited")),
        (_http_error(403, {"Retry-After": "1"}), ("infra-failure", "rate_limited")),
        (_http_error(403), ("configuration-failure", "")),
        (_http_error(408), ("infra-failure", "transient")),
        (_http_error(425), ("infra-failure", "transient")),
        (_http_error(500), ("infra-failure", "transient")),
        (_http_error(599), ("infra-failure", "transient")),
        (_http_error(501), ("configuration-failure", "")),
        (IncompleteRead(b"partial", 10), ("infra-failure", "transient")),
        (TimeoutError("fixture timeout"), ("infra-failure", "transient")),
        (AssertionError("fixture assertion"), ("product-failure", "")),
    ],
)
def test_plugin_matches_http_retry_taxonomy(
    exc: BaseException, expected: tuple[str, str]
) -> None:
    calls = 0

    def fake_transport() -> None:
        nonlocal calls
        calls += 1
        raise exc

    with pytest.raises(type(exc)) as exhausted:
        _http.retry_http(
            fake_transport,
            max_attempts=2,
            base_delay=0,
            max_delay=0,
            max_rate_limit_delay=0,
            sleeper=lambda _delay: None,
        )
    assert classify_exception(exhausted.value) == expected
    assert calls == (2 if expected[0] == "infra-failure" else 1)


def test_plugin_walks_wrapped_network_cause() -> None:
    try:
        try:
            raise TimeoutError("fixture timeout")
        except TimeoutError as exc:
            raise RuntimeError("domain wrapper") from exc
    except RuntimeError as wrapped:
        assert classify_exception(wrapped) == ("infra-failure", "transient")


def _run_classifier(
    tmp_path: Path,
    events: object,
    *,
    outcome: str = "failure",
) -> subprocess.CompletedProcess[str]:
    event_path = tmp_path / "events.json"
    event_path.write_text(json.dumps(events, sort_keys=True), encoding="utf-8")
    return subprocess.run(
        (
            sys.executable,
            str(_CLASSIFIER),
            str(event_path),
            "--surface",
            "fixture-surface",
            "--pytest-outcome",
            outcome,
        ),
        cwd=_ROOT,
        env={**os.environ, "PYTHONPATH": "src"},
        check=False,
        capture_output=True,
        text=True,
    )


def test_infrastructure_failure_warns_but_does_not_turn_product_check_red(tmp_path: Path) -> None:
    result = _run_classifier(
        tmp_path,
        [
            {
                "class": "infra-failure",
                "kind": "rate_limited",
                "nodeid": "tests/test_fixture.py::test_rate_limit",
                "surface": "fixture-surface",
            }
        ],
    )
    assert result.returncode == 0
    assert "`infra-failure`" in result.stdout
    assert "rate-limited" in result.stdout
    assert "::warning" in result.stdout


@pytest.mark.parametrize("event_class", ["product-failure", "configuration-failure"])
def test_product_and_configuration_failures_remain_red(
    tmp_path: Path, event_class: str
) -> None:
    result = _run_classifier(
        tmp_path,
        [
            {
                "class": event_class,
                "kind": "",
                "nodeid": "tests/test_fixture.py::test_failure",
                "surface": "fixture-surface",
            }
        ],
    )
    assert result.returncode == 1
    assert f"`{event_class}`" in result.stdout
    assert "fixture-surface" in result.stdout


def test_success_without_failure_events_is_pass(tmp_path: Path) -> None:
    result = _run_classifier(tmp_path, [], outcome="success")
    assert result.returncode == 0
    assert "`pass`" in result.stdout


def test_failed_probe_without_events_fails_closed(tmp_path: Path) -> None:
    result = _run_classifier(tmp_path, [])
    assert result.returncode == 1
    assert "`configuration-failure`" in result.stdout


def test_malformed_events_fail_closed(tmp_path: Path) -> None:
    result = _run_classifier(tmp_path, {"class": "pass"})
    assert result.returncode == 1
    assert "`configuration-failure`" in result.stdout


def test_disabled_declared_surface_records_explicit_skip(tmp_path: Path) -> None:
    test_file = tmp_path / "test_declared_surface.py"
    events = tmp_path / "events.json"
    test_file.write_text("def test_must_not_run():\n    raise AssertionError('ran')\n", encoding="utf-8")
    result = subprocess.run(
        (
            sys.executable,
            "-m",
            "pytest",
            "-q",
            "-p",
            "tests.live_canary_plugin",
            f"--live-canary-events={events}",
            "--live-canary-surface=declared-surface",
            f"--live-canary-declared-test={test_file.name}",
            "--live-canary-enabled=false",
            str(test_file),
        ),
        cwd=_ROOT,
        env={**os.environ, "PYTHONPATH": f"src{os.pathsep}."},
        check=False,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr
    assert json.loads(events.read_text(encoding="utf-8")) == [
        {
            "class": "skipped-not-landed",
            "kind": "",
            "nodeid": test_file.name,
            "surface": "declared-surface",
        }
    ]


def test_plugin_records_assertion_failure_for_classifier(tmp_path: Path) -> None:
    test_file = tmp_path / "test_product_failure.py"
    events = tmp_path / "events.json"
    test_file.write_text("def test_regression():\n    assert False, 'fixture regression'\n", encoding="utf-8")
    result = subprocess.run(
        (
            sys.executable,
            "-m",
            "pytest",
            "-q",
            "-p",
            "tests.live_canary_plugin",
            f"--live-canary-events={events}",
            "--live-canary-surface=product-surface",
            str(test_file),
        ),
        cwd=_ROOT,
        env={**os.environ, "PYTHONPATH": f"src{os.pathsep}."},
        check=False,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 1
    recorded = json.loads(events.read_text(encoding="utf-8"))
    assert len(recorded) == 1
    event = recorded[0]
    assert event["class"] == "product-failure"
    assert event["kind"] == ""
    assert event["nodeid"].endswith("test_product_failure.py::test_regression")
    assert event["surface"] == "product-surface"


def test_enabled_gate_with_missing_named_test_fails_closed() -> None:
    result = subprocess.run(
        (sys.executable, str(_GATE)),
        cwd=_ROOT,
        env={
            **os.environ,
            "LEITIR_CANARY_TREE_V2": "true",
            "LEITIR_CANARY_STREAM_V2": "false",
            "LEITIR_CANARY_INDEX_V2": "false",
        },
        check=False,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 1
    assert "tree_v2=true" in result.stdout
    assert "required test is missing: tests/test_tree_recovery_e2e_live.py" in result.stderr


def test_absent_feature_gates_are_explicitly_false() -> None:
    env = dict(os.environ)
    for name in (
        "LEITIR_CANARY_TREE_V2",
        "LEITIR_CANARY_STREAM_V2",
        "LEITIR_CANARY_INDEX_V2",
    ):
        env.pop(name, None)
    result = subprocess.run(
        (sys.executable, str(_GATE)),
        cwd=_ROOT,
        env=env,
        check=False,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0
    assert result.stdout.splitlines() == ["index_v2=false", "stream_v2=false", "tree_v2=false"]


def test_secret_probe_emits_only_boolean_presence(tmp_path: Path) -> None:
    output = tmp_path / "output"
    result = subprocess.run(
        (sys.executable, str(_SECRET)),
        cwd=_ROOT,
        env={**os.environ, "LIVE_GITHUB_TOKEN": "do-not-print", "GITHUB_OUTPUT": str(output)},
        check=False,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0
    assert result.stdout == "enabled=true\n"
    assert output.read_text(encoding="utf-8") == "enabled=true\n"
    assert "do-not-print" not in result.stdout


def test_final_summary_distinguishes_skipped_and_configuration_failure() -> None:
    result = subprocess.run(
        (sys.executable, str(_CLASSIFIER), "--summary-from-env"),
        cwd=_ROOT,
        env={
            **os.environ,
            "GATE_RESULT": "success",
            "LIVE_CANARY_ENABLED": "true",
            "TREE_V2": "false",
            "STREAM_V2": "false",
            "INDEX_V2": "true",
            "BASELINE_RESULT": "pass",
            "TREE_RESULT": "",
            "STREAM_RESULT": "",
            "INDEX_RESULT": "",
        },
        check=False,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 1
    assert "| baseline-live | `pass` |" in result.stdout
    assert "| truncated-tree-recovery | `skipped-not-landed` |" in result.stdout
    assert "| streamed-large-blob | `skipped-not-landed` |" in result.stdout
    assert "| index-vs-scan-recall | `configuration-failure` |" in result.stdout
