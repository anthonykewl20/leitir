"""Offline, byte-identical replay and fail-closed tamper rejection (#259).

AC-1: a local verified fixture bundle replays byte-identically offline,
twice, and stays byte-identical across ``PYTHONHASHSEED`` 0/1/42.
SP-1: a tampered bundle is rejected fail-closed -- never silently replayed,
never partially trusted.
"""

from __future__ import annotations

import io
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from leitir.cli import ExitCode, main
from leitir.usage import UsageTamperError, report_from_json_bytes
from leitir.usage.cli_support import load_report, replay_payload

_FIXTURES = Path(__file__).resolve().parent / "fixtures" / "usage"
_POSITIVE = _FIXTURES / "positive"
_TAMPER = _FIXTURES / "tamper"
_ROOT = Path(__file__).resolve().parents[1]


def _run(argv: list[str]) -> tuple[int, str, str]:
    out, err = io.StringIO(), io.StringIO()
    code = main(argv, stdout=out, stderr=err)
    return code, out.getvalue(), err.getvalue()


# ---------------------------------------------------------------------------
# AC-1: offline, byte-identical replay.
# ---------------------------------------------------------------------------


def test_replay_report_twice_is_byte_identical_offline() -> None:
    report = load_report(_POSITIVE / "report.json")
    payload = replay_payload(
        report, corpus_root=_POSITIVE, dependency_path=_POSITIVE / "requirements.txt", times=2
    )
    assert payload["byte_identical"] is True
    assert payload["replay_count"] == 2
    assert "widgetlib" not in sys.modules


def test_replay_via_cli_twice_yields_identical_stdout_bytes() -> None:
    argv = [
        "usage", "replay", str(_POSITIVE / "report.json"),
        "--corpus-root", str(_POSITIVE),
        "--requirements", str(_POSITIVE / "requirements.txt"),
        "--json",
    ]
    first = _run(argv)
    second = _run(argv)
    assert first[0] == second[0] == int(ExitCode.SUCCESS)
    assert first[1] == second[1]
    assert first[1] != ""


def test_replay_performs_no_network_and_executes_no_consumer_code() -> None:
    report = load_report(_POSITIVE / "report.json")
    replay_payload(report, corpus_root=_POSITIVE, dependency_path=_POSITIVE / "requirements.txt")
    # widgetlib is a fixture-only distribution name; if replay ever imported
    # or executed consumer code this would be importable/registered.
    assert "widgetlib" not in sys.modules
    assert "widgetlib" not in sys.builtin_module_names


def test_double_run_is_byte_identical_across_subprocess_hashseeds() -> None:
    script = (
        "import io, sys\n"
        "sys.path.insert(0, 'src')\n"
        "from leitir.cli import main\n"
        "out = io.StringIO()\n"
        "err = io.StringIO()\n"
        "code = main([\n"
        "    'usage', 'replay', 'tests/fixtures/usage/positive/report.json',\n"
        "    '--corpus-root', 'tests/fixtures/usage/positive',\n"
        "    '--requirements', 'tests/fixtures/usage/positive/requirements.txt',\n"
        "    '--json',\n"
        "], stdout=out, stderr=err)\n"
        "assert code == 0, err.getvalue()\n"
        "sys.stdout.write(out.getvalue())\n"
    )
    outputs = []
    for seed in ("0", "1", "42"):
        env = dict(os.environ)
        env["PYTHONHASHSEED"] = seed
        env["PYTHONPATH"] = "src"
        completed = subprocess.run(
            [sys.executable, "-c", script], cwd=_ROOT, env=env, capture_output=True, check=True, text=True
        )
        outputs.append(completed.stdout)
    assert outputs[0] == outputs[1] == outputs[2]
    payload = json.loads(outputs[0])
    assert payload["byte_identical"] is True


# ---------------------------------------------------------------------------
# SP-1: tampered evidence is rejected fail-closed, never weakened.
# ---------------------------------------------------------------------------


def test_replay_payload_rejects_tampered_corpus_bytes() -> None:
    report = load_report(_TAMPER / "report.json")
    with pytest.raises(UsageTamperError) as excinfo:
        replay_payload(report, corpus_root=_TAMPER, dependency_path=_TAMPER / "requirements.txt")
    assert excinfo.value.kind == "usage_tamper"
    assert excinfo.value.evidence.stage == "replay"
    assert "widgetlib" not in sys.modules


def test_cli_usage_replay_tamper_fails_closed_and_reports_stderr_diagnostic() -> None:
    argv = [
        "usage", "replay", str(_TAMPER / "report.json"),
        "--corpus-root", str(_TAMPER),
        "--requirements", str(_TAMPER / "requirements.txt"),
        "--json",
    ]
    code, out, err = _run(argv)
    assert code == int(ExitCode.CORPUS_FAILURE)
    assert out == ""  # never a partial/valid-looking stdout payload
    assert "usage_tamper" in err


def test_tampered_requirements_bytes_are_rejected_before_any_replay_output(tmp_path: Path) -> None:
    report = report_from_json_bytes((_POSITIVE / "report.json").read_bytes())
    consumer_dir = tmp_path / "consumer"
    consumer_dir.mkdir()
    (consumer_dir / "app.py").write_text("import widgetlib\n\nwidgetlib.do_thing()\n", encoding="utf-8")
    requirements_path = tmp_path / "requirements.txt"
    requirements_path.write_text("widgetlib==9.9.9\n", encoding="utf-8")
    with pytest.raises(UsageTamperError) as excinfo:
        replay_payload(report, corpus_root=tmp_path, dependency_path=requirements_path)
    assert "requirements" in (excinfo.value.evidence.field or "")


def test_replay_reports_are_never_substituted_when_tampered() -> None:
    """Replaying a tamper case never returns a report -- only raises."""

    report = load_report(_TAMPER / "report.json")
    try:
        replay_payload(report, corpus_root=_TAMPER, dependency_path=_TAMPER / "requirements.txt")
    except UsageTamperError:
        pass
    else:
        pytest.fail("tampered fixture must be rejected, not silently replayed")
