"""Contract tests for the pure capability-to-comparison CLI adapters."""

from __future__ import annotations

import io
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from leitir.bts_errors import BTSError, BTSRejectReason
from leitir.cli import ExitCode, main
from leitir.funnel_cli import build_recipient_profile, run_discovery, run_funnel, validate_capability_spec

_FIXTURES = Path(__file__).parent / "fixtures" / "funnel_cli"
_SPEC = _FIXTURES / "spec.json"
_RECIPIENT = _FIXTURES / "recipient.json"
_STAGES = _FIXTURES / "stages.json"


def _write_json(path: Path, value: object) -> Path:
    path.write_text(json.dumps(value, sort_keys=True, separators=(",", ":")), encoding="utf-8")
    return path


def test_validate_capability_spec_returns_the_pinned_canonical_summary() -> None:
    assert validate_capability_spec(_SPEC) == {
        "schema_version": "leitir-funnel-capability-summary-v1",
        "spec": json.loads(_SPEC.read_text(encoding="utf-8")),
        "spec_digest": "sha256:03d934858ab68c9800b78864a7076f89602c760a79125d2970060870eb392949",
    }


@pytest.mark.parametrize("payload", [b"{", b"[]", b'{"schema_version":"wrong"}', b'{"spec_digest":"sha256:' + b"0" * 64 + b'"}'])
def test_validate_capability_spec_rejects_malformed_input(tmp_path: Path, payload: bytes) -> None:
    path = tmp_path / "invalid.json"
    path.write_bytes(payload)
    with pytest.raises(BTSError) as caught:
        validate_capability_spec(path)
    assert caught.value.evidence.detail_code == "funnel_cli_spec_invalid_v1"


def test_funnel_rejects_a_final_component_symlink(tmp_path: Path) -> None:
    link = tmp_path / "spec.json"
    try:
        link.symlink_to(_SPEC)
    except OSError:
        pytest.skip("symlinks unavailable")

    with pytest.raises(BTSError) as caught:
        validate_capability_spec(link)
    assert caught.value.evidence.detail_code == "funnel_cli_spec_invalid_v1"


def test_funnel_missing_file_names_path_and_os_error(tmp_path: Path) -> None:
    missing = tmp_path / "missing.json"

    with pytest.raises(BTSError) as caught:
        validate_capability_spec(missing)

    assert caught.value.evidence.detail_code == "funnel_cli_spec_invalid_v1"
    assert caught.value.reason is BTSRejectReason.REJECT_HARD_GATE_FAILED
    assert str(missing) in caught.value.evidence.message


def test_funnel_reads_digest_anchored_inputs_without_no_follow(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delattr(os, "O_NOFOLLOW", raising=False)

    assert validate_capability_spec(_SPEC)["spec_digest"] == "sha256:03d934858ab68c9800b78864a7076f89602c760a79125d2970060870eb392949"


def test_build_recipient_profile_is_canonical_and_rejects_unknown_keys(tmp_path: Path) -> None:
    summary, profile = build_recipient_profile(_RECIPIENT)
    assert summary == {
        "manifest_digest": "sha256:8ae822b72b08141d9019c61ee8e82cc301d8137f57d35486b7ce26f15bcbfdbb",
        "profile": json.loads(profile.to_bytes()),
        "schema_version": "leitir-funnel-recipient-profile-summary-v1",
    }
    payload = json.loads(_RECIPIENT.read_text(encoding="utf-8"))
    payload["extra"] = True
    with pytest.raises(BTSError) as caught:
        build_recipient_profile(_write_json(tmp_path / "recipient.json", payload))
    assert caught.value.evidence.detail_code == "funnel_cli_recipient_manifest_invalid_v1"


@pytest.mark.parametrize(
    "entry",
    [
        {"path": "src/a.py", "role": "source", "content_b64": "not base64"},
        {"path": "src/a.py", "role": "source", "content_b64": "YQ"},
    ],
)
def test_recipient_manifest_rejects_noncanonical_base64(tmp_path: Path, entry: dict[str, str]) -> None:
    path = _write_json(tmp_path / "recipient.json", {"schema_version": "leitir-recipient-input-v1", "project_root_identity": "recipient", "entries": [entry]})

    with pytest.raises(BTSError) as caught:
        build_recipient_profile(path)
    assert caught.value.evidence.detail_code == "funnel_cli_recipient_manifest_invalid_v1"


def test_discovery_and_full_funnel_have_pinned_summaries() -> None:
    # Search evidence now includes method provenance in its canonical digest;
    # retain exact pins for the complete resulting candidate/survivor chain.
    discovery = run_discovery(_SPEC, _RECIPIENT, _STAGES)
    assert {
        "schema_version": discovery["schema_version"],
        "candidate_set_digest": discovery["candidate_set"]["candidate_set_digest"],
        "status": discovery["candidate_set"]["status"],
        "proposal_count": len(discovery["candidate_set"]["proposals"]),
    } == {
        "schema_version": "leitir-funnel-discovery-summary-v1",
        "candidate_set_digest": "sha256:9500222d1a65faaf87a91ca53aaa91e8e512f1485e999fc85410c25eda359a65",
        "status": "comparison_ready",
        "proposal_count": 3,
    }


def test_bts_funnel_cli_wires_the_pure_funnel_surface() -> None:
    stdout, stderr = io.StringIO(), io.StringIO()
    code = main(
        ["bts-funnel", "--spec", str(_SPEC), "--recipient-manifest", str(_RECIPIENT), "--stages", str(_STAGES), "--json"],
        stdout=stdout,
        stderr=stderr,
    )
    assert code == int(ExitCode.SUCCESS)
    assert stderr.getvalue() == ""
    assert json.loads(stdout.getvalue())["schema_version"] == "leitir-funnel-summary-v1"

    summary = run_funnel(_SPEC, _RECIPIENT, _STAGES)
    assert {
        "schema_version": summary["schema_version"],
        "candidate_set_digest": summary["candidate_set"]["candidate_set_digest"],
        "survivor_set_digest": summary["survivor_set"]["survivor_set_digest"],
        "report_digest": summary["best3_report"]["report_digest"],
        "role_statuses": [role["status"] for role in summary["best3_report"]["roles"]],
    } == {
        "schema_version": "leitir-funnel-summary-v1",
        "candidate_set_digest": "sha256:9500222d1a65faaf87a91ca53aaa91e8e512f1485e999fc85410c25eda359a65",
        "survivor_set_digest": "sha256:dcdef1d4dc019c96a69c2a290af09336fb938062d82d58524c73eb2465f01617",
        "report_digest": "sha256:b19d6ef52cfe86114a4d02857f6ada83ccad33e4a5ad71b76d282367afb98f5c",
        "role_statuses": ["equal_identity_tiebreak"] * 3,
    }


def test_tampered_spec_digest_is_typed_and_stage_report_binds_outcome(tmp_path: Path) -> None:
    spec = json.loads(_SPEC.read_text(encoding="utf-8"))
    spec["spec_digest"] = "sha256:" + "0" * 64
    with pytest.raises(BTSError) as caught:
        run_discovery(_write_json(tmp_path / "spec.json", spec), _RECIPIENT, _STAGES)
    assert caught.value.evidence.detail_code == "funnel_cli_spec_invalid_v1"

    stages = json.loads(_STAGES.read_text(encoding="utf-8"))
    stages[0]["report"]["matches"][0]["score"] = 2.0
    altered = run_discovery(_SPEC, _RECIPIENT, _write_json(tmp_path / "stages.json", stages))
    assert altered != run_discovery(_SPEC, _RECIPIENT, _STAGES)
    assert altered["candidate_set"]["candidate_set_digest"] != run_discovery(_SPEC, _RECIPIENT, _STAGES)["candidate_set"]["candidate_set_digest"]


@pytest.mark.parametrize("seed", ["0", "1", "42"])
def test_funnel_summary_bytes_are_hashseed_independent(seed: str) -> None:
    script = """
import json
from pathlib import Path
from leitir.funnel_cli import run_funnel
root = Path('tests/fixtures/funnel_cli')
result = run_funnel(root / 'spec.json', root / 'recipient.json', root / 'stages.json')
print(json.dumps(result, sort_keys=True, separators=(',', ':'), ensure_ascii=False))
"""
    completed = subprocess.run(
        [sys.executable, "-c", script],
        check=True,
        capture_output=True,
        cwd=Path(__file__).parent.parent,
        env=dict(os.environ, PYTHONHASHSEED=seed, PYTHONPATH="src"),
        text=True,
    )
    baseline = subprocess.run(
        [sys.executable, "-c", script],
        check=True,
        capture_output=True,
        cwd=Path(__file__).parent.parent,
        env=dict(os.environ, PYTHONHASHSEED="0", PYTHONPATH="src"),
        text=True,
    )
    assert completed.stdout == baseline.stdout
