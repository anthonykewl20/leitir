"""``leitir usage assemble``: the missing producer for the offline usage
evidence pipeline (issue #266 task B2).

ADR-0025..0029 shipped ``assemble_usage_evidence`` (the function that
*builds* a usage report) plus ``verify``/``replay`` (which only ever
*consume* one), but no shipped command called it -- a verifier with no
producer. These tests drive the new ``leitir usage assemble`` action
through the public CLI, using the committed fixture under
``tests/fixtures/usage/assemble_plan`` (a closed assemble-plan document
plus the on-disk consumer source it references).

Covers, per ``docs/testing.md``:

- assemble produces a report that `usage verify` accepts (the round trip
  the module's own docstring calls out as the critical sad path: an
  assembled report that could not pass its own verify must never be
  written to disk).
- assemble output is byte-identical across independent Python processes
  with different ``PYTHONHASHSEED`` values.
- malformed/absent plan input is rejected fail-closed, and no partial
  ``--out`` artifact is ever left behind.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

from leitir.cli import ExitCode, main
from leitir.usage import report_from_json_bytes

_FIXTURES = Path(__file__).resolve().parent / "fixtures" / "usage"
_PLAN_DIR = _FIXTURES / "assemble_plan"
_PLAN_PATH = _PLAN_DIR / "plan.json"
_REQUIREMENTS_PATH = _PLAN_DIR / "requirements.txt"


def _run(argv: list[str]) -> tuple[int, str, str]:
    import io

    out, err = io.StringIO(), io.StringIO()
    code = main(argv, stdout=out, stderr=err)
    return code, out.getvalue(), err.getvalue()


# ---------------------------------------------------------------------------
# assemble -> verify round trip (the critical sad path)
# ---------------------------------------------------------------------------


def test_assemble_produces_a_report_that_verify_accepts(tmp_path: Path) -> None:
    out_path = tmp_path / "report.json"
    code, out, err = _run(
        [
            "usage", "assemble", str(_PLAN_PATH),
            "--out", str(out_path),
            "--corpus-root", str(_PLAN_DIR),
            "--json",
        ]
    )
    assert code == int(ExitCode.SUCCESS)
    assert out.count("\n") == 1
    payload = json.loads(out)
    assert payload["schema_version"] == "leitir-usage-cli-assemble-v1"
    assert payload["action"] == "assemble"
    assert payload["reference_count"] == 1
    assert payload["result_count"] == 1
    assert payload["output_path"] == str(out_path)
    assert "usage assemble ok" in err
    assert payload["report_digest"] in err

    assert out_path.exists()

    verify_code, verify_out, verify_err = _run(["usage", "verify", str(out_path), "--json"])
    assert verify_code == int(ExitCode.SUCCESS)
    verify_payload = json.loads(verify_out)
    assert verify_payload["report_digest"] == payload["report_digest"]
    assert "usage verify ok" in verify_err


def test_assembled_report_also_replays_byte_identically_against_the_real_corpus(tmp_path: Path) -> None:
    out_path = tmp_path / "report.json"
    code, _, _ = _run(
        ["usage", "assemble", str(_PLAN_PATH), "--out", str(out_path), "--corpus-root", str(_PLAN_DIR), "--json"]
    )
    assert code == int(ExitCode.SUCCESS)

    replay_code, replay_out, _ = _run(
        [
            "usage", "replay", str(out_path),
            "--corpus-root", str(_PLAN_DIR),
            "--requirements", str(_REQUIREMENTS_PATH),
            "--json",
        ]
    )
    assert replay_code == int(ExitCode.SUCCESS)
    replay_payload = json.loads(replay_out)
    assert replay_payload["byte_identical"] is True


def test_assemble_without_out_flag_is_malformed_usage() -> None:
    code, out, err = _run(["usage", "assemble", str(_PLAN_PATH), "--json"])
    assert code == int(ExitCode.MALFORMED_USAGE)
    assert out == ""
    assert "--out" in err


# ---------------------------------------------------------------------------
# Determinism: byte-identical output across PYTHONHASHSEED values.
# ---------------------------------------------------------------------------


def test_assemble_output_is_byte_identical_across_four_hash_seeds(tmp_path: Path) -> None:
    digests: set[bytes] = set()
    for seed in ("0", "1", "2", "3"):
        out_path = tmp_path / f"report-{seed}.json"
        env = dict(os.environ)
        env["PYTHONHASHSEED"] = seed
        env["PYTHONPATH"] = str(Path(__file__).resolve().parents[1] / "src")
        result = subprocess.run(
            [
                sys.executable, "-m", "leitir.cli",
                "usage", "assemble", str(_PLAN_PATH),
                "--out", str(out_path),
                "--corpus-root", str(_PLAN_DIR),
                "--json",
            ],
            env=env,
            capture_output=True,
            text=True,
            timeout=60,
        )
        assert result.returncode == int(ExitCode.SUCCESS), result.stderr
        digests.add(out_path.read_bytes())
    assert len(digests) == 1, "assembled report.json bytes differ across PYTHONHASHSEED values"


# ---------------------------------------------------------------------------
# Fail-closed: malformed/absent plan input, no partial artifact.
# ---------------------------------------------------------------------------


def test_assemble_missing_plan_file_fails_closed_and_writes_no_artifact(tmp_path: Path) -> None:
    out_path = tmp_path / "report.json"
    missing = tmp_path / "does-not-exist.json"
    code, out, err = _run(["usage", "assemble", str(missing), "--out", str(out_path), "--json"])
    assert code == int(ExitCode.CORPUS_FAILURE)
    assert out == ""
    assert not out_path.exists()
    diagnostic = json.loads(err.removeprefix("leitir: error: ").strip())
    assert diagnostic["kind"] == "usage_malformed"


def test_assemble_malformed_plan_json_fails_closed_and_writes_no_artifact(tmp_path: Path) -> None:
    bad = tmp_path / "bad-plan.json"
    bad.write_text("{}", encoding="utf-8")
    out_path = tmp_path / "report.json"
    code, out, err = _run(["usage", "assemble", str(bad), "--out", str(out_path), "--json"])
    assert code == int(ExitCode.CORPUS_FAILURE)
    assert out == ""
    assert not out_path.exists()
    diagnostic = json.loads(err.removeprefix("leitir: error: ").strip())
    assert diagnostic["kind"] == "usage_malformed"


def test_assemble_plan_with_unknown_field_is_rejected(tmp_path: Path) -> None:
    payload = json.loads(_PLAN_PATH.read_text(encoding="utf-8"))
    payload["unexpected_field"] = "surprise"
    bad = tmp_path / "plan.json"
    bad.write_text(json.dumps(payload), encoding="utf-8")
    out_path = tmp_path / "report.json"
    code, out, err = _run(["usage", "assemble", str(bad), "--out", str(out_path), "--json"])
    assert code == int(ExitCode.CORPUS_FAILURE)
    assert out == ""
    assert not out_path.exists()
    diagnostic = json.loads(err.removeprefix("leitir: error: ").strip())
    assert diagnostic["kind"] == "usage_malformed"


def test_assemble_plan_with_unsupported_schema_version_is_rejected(tmp_path: Path) -> None:
    payload = json.loads(_PLAN_PATH.read_text(encoding="utf-8"))
    payload["schema_version"] = "leitir-usage-cli-assemble-plan-v999"
    bad = tmp_path / "plan.json"
    bad.write_text(json.dumps(payload), encoding="utf-8")
    out_path = tmp_path / "report.json"
    code, out, err = _run(["usage", "assemble", str(bad), "--out", str(out_path), "--json"])
    assert code == int(ExitCode.CORPUS_FAILURE)
    assert out == ""
    assert not out_path.exists()
    diagnostic = json.loads(err.removeprefix("leitir: error: ").strip())
    assert diagnostic["kind"] == "usage_unsupported"


def test_assemble_plan_with_tampered_requirements_digest_is_rejected(tmp_path: Path) -> None:
    payload = json.loads(_PLAN_PATH.read_text(encoding="utf-8"))
    payload["dependency_evidence"]["requirements_digest"] = "sha256:" + "a" * 64
    bad = tmp_path / "plan.json"
    bad.write_text(json.dumps(payload), encoding="utf-8")
    out_path = tmp_path / "report.json"
    code, out, err = _run(["usage", "assemble", str(bad), "--out", str(out_path), "--json"])
    assert code == int(ExitCode.CORPUS_FAILURE)
    assert out == ""
    assert not out_path.exists()
    diagnostic = json.loads(err.removeprefix("leitir: error: ").strip())
    assert diagnostic["kind"] == "usage_tamper"


def test_assemble_plan_with_mismatched_code_digest_is_rejected_not_silently_assembled(tmp_path: Path) -> None:
    """A reference whose code_digest fails the sha256 shape check is malformed;
    assemble never invents or repairs a digest -- fail-closed all the way
    through to the produced (or, here, un-produced) report."""

    payload = json.loads(_PLAN_PATH.read_text(encoding="utf-8"))
    payload["reference_batches"][0]["references"][0]["code_digest"] = "not-a-digest"
    bad = tmp_path / "plan.json"
    bad.write_text(json.dumps(payload), encoding="utf-8")
    out_path = tmp_path / "report.json"
    code, out, err = _run(["usage", "assemble", str(bad), "--out", str(out_path), "--json"])
    assert code == int(ExitCode.CORPUS_FAILURE)
    assert out == ""
    assert not out_path.exists()
    diagnostic = json.loads(err.removeprefix("leitir: error: ").strip())
    assert diagnostic["kind"] == "usage_malformed"


def test_assemble_never_overwrites_an_existing_out_path_with_a_partial_file_on_failure(tmp_path: Path) -> None:
    out_path = tmp_path / "report.json"
    sentinel = b'{"already": "here"}'
    out_path.write_bytes(sentinel)

    bad = tmp_path / "bad-plan.json"
    bad.write_text("{}", encoding="utf-8")
    code, out, err = _run(["usage", "assemble", str(bad), "--out", str(out_path), "--json"])
    assert code == int(ExitCode.CORPUS_FAILURE)
    # A failed assemble must never touch a pre-existing --out file.
    assert out_path.read_bytes() == sentinel


# ---------------------------------------------------------------------------
# Direct unit coverage of the self-verify gate in cli_support.assemble_payload.
# ---------------------------------------------------------------------------


def test_assemble_payload_self_verifies_before_writing(tmp_path: Path) -> None:
    from leitir.usage.cli_support import assemble_payload, load_assemble_plan

    plan = load_assemble_plan(_PLAN_PATH)
    out_path = tmp_path / "report.json"
    payload = assemble_payload(plan, consumer_root=_PLAN_DIR, out_path=out_path)

    # The exact function `leitir usage verify` calls must accept the bytes
    # this call wrote to disk.
    report = report_from_json_bytes(out_path.read_bytes())
    assert report.report_digest == payload["report_digest"]
