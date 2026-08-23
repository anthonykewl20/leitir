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
        (_http_error(403, {"Retry-After": "0"}), ("infra-failure", "rate_limited")),
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


def _run_classifier_path(
    tmp_path: Path, event_path: Path, *, outcome: str = "success"
) -> subprocess.CompletedProcess[str]:
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


def test_missing_events_file_fails_closed(tmp_path: Path) -> None:
    # The exact canary failure mode when a probe step dies before the plugin
    # can write events.json: the classifier must never classify a missing
    # events file as a pass, even when the recorded pytest outcome succeeded.
    result = _run_classifier_path(tmp_path, tmp_path / "events-never-written.json")
    assert result.returncode == 1
    assert "`configuration-failure`" in result.stdout
    assert "`pass`" not in result.stdout
    assert "invalid live canary events" in result.stdout


def test_empty_events_file_fails_closed(tmp_path: Path) -> None:
    # Zero-byte events.json (created but never populated) must fail closed
    # with a typed error, never classify as pass.
    event_path = tmp_path / "events.json"
    event_path.write_bytes(b"")
    result = _run_classifier_path(tmp_path, event_path)
    assert result.returncode == 1
    assert "`configuration-failure`" in result.stdout
    assert "`pass`" not in result.stdout
    assert "invalid live canary events" in result.stdout


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


def test_enabled_selected_surface_cannot_report_a_skip_as_not_landed(tmp_path: Path) -> None:
    test_file = tmp_path / "test_selected_surface.py"
    events = tmp_path / "events.json"
    test_file.write_text(
        "import pytest\n\ndef test_selected_probe():\n    pytest.skip('fixture unavailable')\n",
        encoding="utf-8",
    )
    probe = subprocess.run(
        (
            sys.executable,
            "-m",
            "pytest",
            "-q",
            "-p",
            "tests.live_canary_plugin",
            f"--live-canary-events={events}",
            "--live-canary-surface=selected-surface",
            str(test_file),
        ),
        cwd=_ROOT,
        env={**os.environ, "PYTHONPATH": f"src{os.pathsep}."},
        check=False,
        capture_output=True,
        text=True,
    )
    assert probe.returncode == 0, probe.stderr
    recorded = json.loads(events.read_text(encoding="utf-8"))
    assert len(recorded) == 1
    event = recorded[0]
    assert event["class"] == "configuration-failure"
    assert event["kind"] == ""
    assert event["nodeid"].endswith("test_selected_probe")
    assert event["surface"] == "selected-surface"

    classified = _run_classifier(
        tmp_path,
        json.loads(events.read_text(encoding="utf-8")),
        outcome="success",
    )
    assert classified.returncode == 1
    assert "`configuration-failure`" in classified.stdout


def test_enabled_collection_skip_with_another_collected_module_fails_closed(tmp_path: Path) -> None:
    skipped_file = tmp_path / "test_collection_skip.py"
    collected_file = tmp_path / "test_collected.py"
    events = tmp_path / "events.json"
    skipped_file.write_text(
        "import pytest\npytest.skip('fixture unavailable', allow_module_level=True)\n",
        encoding="utf-8",
    )
    collected_file.write_text("def test_collected():\n    pass\n", encoding="utf-8")
    probe = subprocess.run(
        (
            sys.executable,
            "-m",
            "pytest",
            "-q",
            "-p",
            "tests.live_canary_plugin",
            f"--live-canary-events={events}",
            "--live-canary-surface=collection-surface",
            str(skipped_file),
            str(collected_file),
        ),
        cwd=_ROOT,
        env={**os.environ, "PYTHONPATH": f"src{os.pathsep}."},
        check=False,
        capture_output=True,
        text=True,
    )
    assert probe.returncode == 0, probe.stderr
    recorded = json.loads(events.read_text(encoding="utf-8"))
    assert len(recorded) == 1
    assert recorded[0]["class"] == "configuration-failure"
    assert recorded[0]["surface"] == "collection-surface"
    assert recorded[0]["kind"] == ""
    assert recorded[0]["nodeid"].endswith(skipped_file.name)

    classified = _run_classifier(tmp_path, recorded, outcome="success")
    assert classified.returncode == 1
    assert "`configuration-failure`" in classified.stdout


def test_teardown_skip_replaces_setup_infrastructure_event(tmp_path: Path) -> None:
    test_file = tmp_path / "test_mixed_phases.py"
    events = tmp_path / "events.json"
    test_file.write_text(
        "import pytest\n\n"
        "@pytest.fixture\n"
        "def skip_teardown(request):\n"
        "    request.addfinalizer(lambda: pytest.skip('teardown unavailable'))\n\n"
        "@pytest.fixture\n"
        "def infra_setup(skip_teardown):\n"
        "    raise TimeoutError('setup unavailable')\n\n"
        "def test_probe(infra_setup):\n"
        "    pass\n",
        encoding="utf-8",
    )
    probe = subprocess.run(
        (
            sys.executable,
            "-m",
            "pytest",
            "-q",
            "-p",
            "tests.live_canary_plugin",
            f"--live-canary-events={events}",
            "--live-canary-surface=mixed-phase-surface",
            str(test_file),
        ),
        cwd=_ROOT,
        env={**os.environ, "PYTHONPATH": f"src{os.pathsep}."},
        check=False,
        capture_output=True,
        text=True,
    )
    assert probe.returncode == 1
    recorded = json.loads(events.read_text(encoding="utf-8"))
    assert len(recorded) == 1
    assert recorded[0]["class"] == "configuration-failure"
    assert recorded[0]["kind"] == ""
    assert recorded[0]["nodeid"].endswith("test_probe")
    assert recorded[0]["surface"] == "mixed-phase-surface"

    classified = _run_classifier(tmp_path, recorded, outcome="failure")
    assert classified.returncode == 1
    assert "`configuration-failure`" in classified.stdout


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
    assert event["nodeid"].endswith("test_regression")
    assert event["surface"] == "product-surface"


def test_enabled_gate_with_missing_named_test_fails_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Post-#197 every surface test the gate names exists in the repo, so the
    # enabled-but-missing refusal is exercised against an isolated root that
    # deliberately lacks the named file (same typed error as before).
    import importlib.util

    spec = importlib.util.spec_from_file_location("live_canary_gate_module", _GATE)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    monkeypatch.setenv("LEITIR_CANARY_TREE_V2", "true")
    monkeypatch.setenv("LEITIR_CANARY_STREAM_V2", "false")
    monkeypatch.setenv("LEITIR_CANARY_INDEX_V2", "false")
    with pytest.raises(
        ValueError,
        match="required test is missing: tests/test_tree_recovery_e2e_live.py",
    ):
        module.evaluate(tmp_path)


def test_enabled_gate_resolves_true_now_that_every_named_test_exists() -> None:
    # The #197 fail→pass counterpart: with all three surface test files
    # present, enabling every gate must resolve cleanly instead of failing
    # closed on a missing test.
    result = subprocess.run(
        (sys.executable, str(_GATE)),
        cwd=_ROOT,
        env={
            **os.environ,
            "LEITIR_CANARY_TREE_V2": "true",
            "LEITIR_CANARY_STREAM_V2": "true",
            "LEITIR_CANARY_INDEX_V2": "true",
        },
        check=False,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0
    assert result.stdout.splitlines() == [
        "index_v2=true",
        "stream_v2=true",
        "tree_v2=true",
        "extra_tests=",
        "extra_tests_requested=false",
    ]


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
    assert result.stdout.splitlines() == [
        "index_v2=false", "stream_v2=false", "tree_v2=false", "extra_tests=",
        "extra_tests_requested=false",
    ]


def test_malformed_gate_variable_fails_closed_through_the_cli() -> None:
    # Keeps CLI-level coverage of the gate's exit-1 path (fallback outputs +
    # typed stderr) after #197 made the enabled-but-missing-file variant
    # unreachable in-repo: a non-boolean variable must fail closed the same
    # way, and the malformed gate must not be silently reported as enabled.
    result = subprocess.run(
        (sys.executable, str(_GATE)),
        cwd=_ROOT,
        env={
            **os.environ,
            "LEITIR_CANARY_TREE_V2": "maybe",
            "LEITIR_CANARY_STREAM_V2": "false",
            "LEITIR_CANARY_INDEX_V2": "false",
        },
        check=False,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 1
    assert result.stdout.splitlines() == [
        "index_v2=false",
        "stream_v2=false",
        "tree_v2=false",
        "extra_tests=",
        "extra_tests_requested=false",
    ]
    assert "LEITIR_CANARY_TREE_V2 must be an explicit boolean" in result.stderr


def _run_dispatch_gate(**values: str) -> subprocess.CompletedProcess[str]:
    env = {
        **os.environ,
        "GITHUB_EVENT_NAME": "workflow_dispatch",
        "DISPATCH_RUN_SURFACES": "default",
        "DISPATCH_ENABLE_TREE_V2": "false",
        "DISPATCH_ENABLE_STREAM_V2": "false",
        "DISPATCH_ENABLE_INDEX_V2": "false",
        "DISPATCH_EXTRA_TESTS": "",
        "LEITIR_CANARY_TREE_V2": "false",
        "LEITIR_CANARY_STREAM_V2": "false",
        "LEITIR_CANARY_INDEX_V2": "false",
    }
    env.update(values)
    return subprocess.run(
        (sys.executable, str(_GATE)), cwd=_ROOT, env=env, check=False,
        capture_output=True, text=True,
    )


def test_dispatch_surface_overrides_are_honored_only_for_manual_event() -> None:
    manual = _run_dispatch_gate(
        DISPATCH_ENABLE_TREE_V2="true",
        DISPATCH_ENABLE_STREAM_V2="false",
        DISPATCH_ENABLE_INDEX_V2="true",
    )
    assert manual.returncode == 0
    assert "tree_v2=true" in manual.stdout
    assert "index_v2=true" in manual.stdout

    tree_only = _run_dispatch_gate(
        DISPATCH_ENABLE_TREE_V2="true",
        DISPATCH_ENABLE_STREAM_V2="false",
        DISPATCH_ENABLE_INDEX_V2="false",
    )
    assert tree_only.returncode == 0
    assert "tree_v2=true" in tree_only.stdout
    assert "stream_v2=false" in tree_only.stdout
    assert "index_v2=false" in tree_only.stdout

    schedule = subprocess.run(
        (sys.executable, str(_GATE)), cwd=_ROOT,
        env={
            **os.environ,
            "GITHUB_EVENT_NAME": "schedule",
            "DISPATCH_ENABLE_TREE_V2": "true",
            "DISPATCH_ENABLE_STREAM_V2": "true",
            "DISPATCH_ENABLE_INDEX_V2": "true",
            "LEITIR_CANARY_TREE_V2": "false",
            "LEITIR_CANARY_STREAM_V2": "false",
            "LEITIR_CANARY_INDEX_V2": "false",
        }, check=False, capture_output=True, text=True,
    )
    assert schedule.returncode == 0
    assert "tree_v2=false" in schedule.stdout
    assert "stream_v2=false" in schedule.stdout
    assert "index_v2=false" in schedule.stdout


def test_unknown_extra_test_id_fails_closed() -> None:
    result = _run_dispatch_gate(DISPATCH_EXTRA_TESTS="tests/test_info.py::test_not_allowlisted")
    assert result.returncode == 1
    assert "unknown test node ID" in result.stderr


def test_allowlist_environment_divergence_fails_closed() -> None:
    result = _run_dispatch_gate(
        DISPATCH_EXTRA_TESTS="tests/test_info.py::test_live_tinode_routes_study_only",
        DISPATCH_EXTRA_TEST_ALLOWLIST="tests/test_info.py::test_live_tinode_routes_study_only",
    )
    assert result.returncode == 1
    assert "DISPATCH_EXTRA_TEST_ALLOWLIST diverges" in result.stderr
    assert result.stdout.splitlines() == [
        "index_v2=false",
        "stream_v2=false",
        "tree_v2=false",
        "extra_tests=",
        "extra_tests_requested=false",
    ]


def test_dispatch_configuration_error_ignores_repository_feature_variables() -> None:
    result = _run_dispatch_gate(
        DISPATCH_ENABLE_TREE_V2="false",
        LEITIR_CANARY_TREE_V2="true",
        DISPATCH_EXTRA_TESTS="tests/test_info.py::test_not_allowlisted",
    )
    assert result.returncode == 1
    assert result.stdout.splitlines() == [
        "index_v2=false",
        "stream_v2=false",
        "tree_v2=false",
        "extra_tests=",
        "extra_tests_requested=false",
    ]


def test_allowlisted_extra_test_id_passes_validation() -> None:
    result = _run_dispatch_gate(
        DISPATCH_EXTRA_TESTS="tests/test_info.py::test_live_tinode_routes_study_only"
    )
    assert result.returncode == 0
    assert "extra_tests=tests/test_info.py::test_live_tinode_routes_study_only" in result.stdout


def test_malformed_dispatch_boolean_fails_closed() -> None:
    result = _run_dispatch_gate(DISPATCH_ENABLE_TREE_V2="yes")
    assert result.returncode == 1
    assert "canonical boolean true or false" in result.stderr


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
            "EXTRA_TESTS_REQUESTED": "false",
            "EXTRA_RESULT": "",
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
    assert "| extra-live |" not in result.stdout


@pytest.mark.parametrize(
    ("extra_result", "expected_class", "expected_returncode"),
    [
        ("", "configuration-failure", 1),
        ("product-failure", "product-failure", 1),
    ],
)
def test_requested_extra_live_is_rendered_and_fails_closed(
    extra_result: str, expected_class: str, expected_returncode: int
) -> None:
    result = subprocess.run(
        (sys.executable, str(_CLASSIFIER), "--summary-from-env"),
        cwd=_ROOT,
        env={
            **os.environ,
            "GATE_RESULT": "success",
            "LIVE_CANARY_ENABLED": "true",
            "TREE_V2": "false",
            "STREAM_V2": "false",
            "INDEX_V2": "false",
            "BASELINE_RESULT": "pass",
            "EXTRA_TESTS_REQUESTED": "true",
            "EXTRA_RESULT": extra_result,
        },
        check=False,
        capture_output=True,
        text=True,
    )
    assert result.returncode == expected_returncode
    assert f"| extra-live | `{expected_class}` |" in result.stdout
