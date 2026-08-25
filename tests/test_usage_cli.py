"""The `leitir usage` CLI subcommand: verify/replay wiring, stdout purity,
diagnostics-on-stderr, and exit codes (issue #259).

Uses the committed fixtures under ``tests/fixtures/usage/positive`` (valid,
self-consistent report + matching on-disk corpus) and
``tests/fixtures/usage/tamper`` (self-consistent report but corpus bytes
altered after the fact -- SP-1's tamper case). Byte-identical replay and
fail-closed tamper rejection are covered in ``tests/test_usage_replay.py``;
this file focuses on the CLI boundary itself.
"""

from __future__ import annotations

import io
import json
import sys
from pathlib import Path

import pytest

from leitir.cli import ExitCode, main

_FIXTURES = Path(__file__).resolve().parent / "fixtures" / "usage"
_POSITIVE = _FIXTURES / "positive"
_TAMPER = _FIXTURES / "tamper"


def _run(argv: list[str]) -> tuple[int, str, str]:
    out, err = io.StringIO(), io.StringIO()
    code = main(argv, stdout=out, stderr=err)
    return code, out.getvalue(), err.getvalue()


# ---------------------------------------------------------------------------
# verify
# ---------------------------------------------------------------------------


def test_verify_valid_fixture_reports_success_with_pure_json_stdout() -> None:
    code, out, err = _run(["usage", "verify", str(_POSITIVE / "report.json"), "--json"])
    assert code == int(ExitCode.SUCCESS)

    # Stdout parses cleanly as exactly one JSON document and nothing else.
    assert out.endswith("\n")
    assert out.count("\n") == 1
    payload = json.loads(out)
    assert payload["schema_version"] == "leitir-usage-cli-verify-v1"
    assert payload["action"] == "verify"
    assert payload["report_digest"].startswith("sha256:")
    assert payload["provider"]["name"] == "widgetlib"
    assert payload["consumer"]["name"] == "positive-consumer"
    assert payload["reference_count"] == 1

    # Diagnostics land on stderr, never mixed into stdout.
    assert "usage verify ok" in err
    assert payload["report_digest"] in err
    assert "widgetlib" not in sys.modules


def test_verify_valid_fixture_non_json_mode_emits_key_value_lines_on_stdout() -> None:
    code, out, err = _run(["usage", "verify", str(_POSITIVE / "report.json")])
    assert code == int(ExitCode.SUCCESS)
    lines = [line for line in out.splitlines() if line]
    assert all("=" in line for line in lines)
    assert any(line.startswith("report_digest=") for line in lines)
    assert "usage verify ok" in err


def test_verify_malformed_report_fails_closed_with_empty_stdout(tmp_path: Path) -> None:
    bad = tmp_path / "bad.json"
    bad.write_text("{}", encoding="utf-8")
    code, out, err = _run(["usage", "verify", str(bad), "--json"])
    assert code == int(ExitCode.CORPUS_FAILURE)
    assert out == ""
    assert "leitir: error:" in err
    diagnostic = json.loads(err.removeprefix("leitir: error: ").strip())
    assert diagnostic["kind"] == "usage_malformed"


def test_verify_tampered_report_digest_fails_closed(tmp_path: Path) -> None:
    payload = json.loads((_POSITIVE / "report.json").read_text(encoding="utf-8"))
    payload["report_digest"] = "sha256:" + "f" * 64
    tampered = tmp_path / "report.json"
    tampered.write_text(json.dumps(payload), encoding="utf-8")
    code, out, err = _run(["usage", "verify", str(tampered), "--json"])
    assert code == int(ExitCode.CORPUS_FAILURE)
    assert out == ""
    diagnostic = json.loads(err.removeprefix("leitir: error: ").strip())
    assert diagnostic["kind"] == "usage_tamper"


# ---------------------------------------------------------------------------
# replay
# ---------------------------------------------------------------------------


def test_replay_valid_fixture_is_byte_identical_across_two_passes() -> None:
    argv = [
        "usage", "replay", str(_POSITIVE / "report.json"),
        "--corpus-root", str(_POSITIVE),
        "--requirements", str(_POSITIVE / "requirements.txt"),
        "--json",
    ]
    code, out, err = _run(argv)
    assert code == int(ExitCode.SUCCESS)
    assert out.count("\n") == 1
    payload = json.loads(out)
    assert payload["schema_version"] == "leitir-usage-cli-replay-v1"
    assert payload["action"] == "replay"
    assert payload["byte_identical"] is True
    assert payload["replay_count"] == 2
    assert "usage replay ok" in err
    assert "widgetlib" not in sys.modules


def test_replay_missing_required_flags_is_malformed_usage_not_corpus_failure() -> None:
    code, out, err = _run(["usage", "replay", str(_POSITIVE / "report.json"), "--json"])
    assert code == int(ExitCode.MALFORMED_USAGE)
    assert out == ""
    assert "--corpus-root" in err
    assert "--requirements" in err


def test_replay_rejects_times_below_one_as_malformed_usage() -> None:
    argv = [
        "usage", "replay", str(_POSITIVE / "report.json"),
        "--corpus-root", str(_POSITIVE),
        "--requirements", str(_POSITIVE / "requirements.txt"),
        "--times", "0",
        "--json",
    ]
    code, out, err = _run(argv)
    assert code == int(ExitCode.MALFORMED_USAGE)
    assert out == ""
    assert "--times" in err


def test_replay_tampered_fixture_fails_closed_no_stdout_leak() -> None:
    argv = [
        "usage", "replay", str(_TAMPER / "report.json"),
        "--corpus-root", str(_TAMPER),
        "--requirements", str(_TAMPER / "requirements.txt"),
        "--json",
    ]
    code, out, err = _run(argv)
    assert code == int(ExitCode.CORPUS_FAILURE)
    assert out == ""
    diagnostic = json.loads(err.removeprefix("leitir: error: ").strip())
    assert diagnostic["kind"] == "usage_tamper"
    assert diagnostic["stage"] == "replay"
    assert "widgetlib" not in sys.modules


# ---------------------------------------------------------------------------
# stdout/stderr purity is an explicit acceptance item.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "argv",
    [
        ["usage", "verify", str(_POSITIVE / "report.json"), "--json"],
        [
            "usage", "replay", str(_POSITIVE / "report.json"),
            "--corpus-root", str(_POSITIVE),
            "--requirements", str(_POSITIVE / "requirements.txt"),
            "--json",
        ],
    ],
    ids=["verify", "replay"],
)
def test_stdout_is_pure_json_even_when_diagnostics_are_emitted(argv: list[str]) -> None:
    code, out, err = _run(argv)
    assert code == int(ExitCode.SUCCESS)
    # A diagnostic line was in fact written to stderr for this run...
    assert err.strip() != ""
    # ...yet stdout still parses as exactly one JSON document with zero
    # extra bytes: no log lines, no warnings, no progress markers.
    parsed = json.loads(out)
    assert isinstance(parsed, dict)
    assert out == json.dumps(parsed, sort_keys=True) + "\n"
