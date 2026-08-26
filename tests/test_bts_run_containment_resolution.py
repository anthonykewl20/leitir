"""User-level intent tests for the ``leitir bts-run`` containment environment
resolution introduced for issue #266 (task C1).

Before this change, ``bts-run`` required eleven mandatory flags, five of
which are containment-substrate identity values that almost never vary
across invocations (``--nsjail-sha256``, ``--nsjail-version``,
``--nsjail-build-identity``, ``--config-schema-digest``,
``--rootfs-digest``). These tests establish that:

* the short invocation (only the flags that genuinely vary per run) resolves
  those five values from the committed, self-verified descriptor and wires
  the pipeline identically to the long, fully explicit invocation;
* an explicit flag always overrides the descriptor, per field;
* a descriptor that fails its own internal consistency check (the offline,
  deterministic analogue of "does not match the measured runtime": its
  ``nsjail_build_identity`` is not the value derived from its own
  ``nsjail_sha256``/``nsjail_version``) rejects with the same
  ``BTSRejectReason`` taxonomy used elsewhere in this codebase, never
  silently proceeding -- the real, on-disk measurement in
  ``exec_sandbox._verify_backend`` is exercised unmodified by
  ``tests/test_exec_sandbox.py::test_binary_digest_tamper_rejects``, which
  this change does not touch;
* a missing or malformed descriptor rejects rather than defaulting;
* every resolved value is named, with its source, in the run's audit trail;
* resolution is byte-identical across ``PYTHONHASHSEED`` values.

See docs/adr/0009-transplant-validation.md, "Amendment 1" for the design
rationale and the explicit restatement that this is a convenience over
containment verification, never a substitute for it.
"""

from __future__ import annotations

import io
import json
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from leitir import cli
from leitir.bts_cli import (
    DEFAULT_CONTAINMENT_ENVIRONMENT_PATH,
    DEFAULT_ROOTFS_SOURCE_PATH,
    ROOTFS_SOURCE_ENV_VAR,
    load_containment_environment_descriptor,
    resolve_containment_substrate,
    write_containment_environment_receipt,
)
from leitir.bts_errors import BTSError, BTSRejectReason

_REAL_DESCRIPTOR_TEXT = DEFAULT_CONTAINMENT_ENVIRONMENT_PATH.read_bytes()
_SHA = "b" * 40


def _write_json(path: Path, payload: object) -> None:
    path.write_text(json.dumps(payload), encoding="utf-8")


# --- resolution: defaults, overrides, provenance ----------------------------


def test_resolve_defaults_from_committed_descriptor() -> None:
    descriptor = load_containment_environment_descriptor()
    resolved = resolve_containment_substrate(
        nsjail_sha256=None,
        nsjail_version=None,
        nsjail_build_identity=None,
        config_schema_digest=None,
        rootfs_source=None,
        rootfs_digest=None,
        environ={},
    )
    for field in ("nsjail_sha256", "nsjail_version", "nsjail_build_identity", "config_schema_digest", "rootfs_digest"):
        item = getattr(resolved, field)
        assert item.source == "descriptor"
        assert item.value == getattr(descriptor, field)
    assert resolved.rootfs_source.source == "default"
    assert resolved.rootfs_source.value == str(DEFAULT_ROOTFS_SOURCE_PATH)


def test_explicit_flag_overrides_descriptor_per_field() -> None:
    descriptor = load_containment_environment_descriptor()
    override_digest = "sha256:" + "9" * 64
    assert override_digest != descriptor.nsjail_sha256
    resolved = resolve_containment_substrate(
        nsjail_sha256=override_digest,
        nsjail_version=None,
        nsjail_build_identity=None,
        config_schema_digest=None,
        rootfs_source="/explicit/rootfs",
        rootfs_digest=None,
        environ={},
    )
    assert resolved.nsjail_sha256.value == override_digest
    assert resolved.nsjail_sha256.source == "flag"
    assert resolved.rootfs_source.value == "/explicit/rootfs"
    assert resolved.rootfs_source.source == "flag"
    # Untouched fields still come from the descriptor.
    assert resolved.nsjail_version.source == "descriptor"
    assert resolved.nsjail_version.value == descriptor.nsjail_version
    assert resolved.config_schema_digest.source == "descriptor"
    assert resolved.rootfs_digest.source == "descriptor"


def test_rootfs_source_env_var_precedence_over_default() -> None:
    resolved = resolve_containment_substrate(
        nsjail_sha256=None,
        nsjail_version=None,
        nsjail_build_identity=None,
        config_schema_digest=None,
        rootfs_source=None,
        rootfs_digest=None,
        environ={ROOTFS_SOURCE_ENV_VAR: "/env/rootfs"},
    )
    assert resolved.rootfs_source.value == "/env/rootfs"
    assert resolved.rootfs_source.source == f"env:{ROOTFS_SOURCE_ENV_VAR}"


def test_explicit_rootfs_source_flag_wins_over_env_var() -> None:
    resolved = resolve_containment_substrate(
        nsjail_sha256=None,
        nsjail_version=None,
        nsjail_build_identity=None,
        config_schema_digest=None,
        rootfs_source="/flag/rootfs",
        rootfs_digest=None,
        environ={ROOTFS_SOURCE_ENV_VAR: "/env/rootfs"},
    )
    assert resolved.rootfs_source.value == "/flag/rootfs"
    assert resolved.rootfs_source.source == "flag"


def test_all_explicit_flags_never_touch_the_descriptor(tmp_path: Path) -> None:
    """A fully explicit call must not even read the descriptor file."""

    missing = tmp_path / "does-not-exist.json"
    resolved = resolve_containment_substrate(
        nsjail_sha256="sha256:" + "1" * 64,
        nsjail_version="nsjail@" + "0" * 40,
        nsjail_build_identity="sha256:" + "2" * 64,
        config_schema_digest="sha256:" + "3" * 64,
        rootfs_source="/explicit/rootfs",
        rootfs_digest="sha256:" + "4" * 64,
        descriptor_path=missing,
        environ={},
    )
    assert all(getattr(resolved, field).source == "flag" for field in ("nsjail_sha256", "nsjail_version", "nsjail_build_identity", "config_schema_digest", "rootfs_digest", "rootfs_source"))


# --- fail-closed: missing / malformed / tampered descriptor -----------------


def test_missing_descriptor_rejects(tmp_path: Path) -> None:
    with pytest.raises(BTSError) as caught:
        resolve_containment_substrate(
            nsjail_sha256=None,
            nsjail_version=None,
            nsjail_build_identity=None,
            config_schema_digest=None,
            rootfs_source=None,
            rootfs_digest=None,
            descriptor_path=tmp_path / "missing.json",
            environ={},
        )
    assert caught.value.reason is BTSRejectReason.REJECT_EXECUTION_THREAT
    assert caught.value.evidence.detail_code == "bts_cli_containment_env_unavailable_v1"


def test_malformed_json_descriptor_rejects(tmp_path: Path) -> None:
    path = tmp_path / "environment.json"
    path.write_text("{not json", encoding="utf-8")
    with pytest.raises(BTSError) as caught:
        load_containment_environment_descriptor(path)
    assert caught.value.reason is BTSRejectReason.REJECT_EXECUTION_THREAT
    assert caught.value.evidence.detail_code == "bts_cli_containment_env_json_v1"


def test_descriptor_missing_field_rejects(tmp_path: Path) -> None:
    payload = json.loads(_REAL_DESCRIPTOR_TEXT)
    del payload["rootfs_digest"]
    path = tmp_path / "environment.json"
    _write_json(path, payload)
    with pytest.raises(BTSError) as caught:
        load_containment_environment_descriptor(path)
    assert caught.value.reason is BTSRejectReason.REJECT_EXECUTION_THREAT
    assert caught.value.evidence.detail_code == "bts_cli_containment_env_fields_v1"


def test_descriptor_bad_digest_format_rejects(tmp_path: Path) -> None:
    payload = json.loads(_REAL_DESCRIPTOR_TEXT)
    payload["rootfs_digest"] = "not-a-digest"
    path = tmp_path / "environment.json"
    _write_json(path, payload)
    with pytest.raises(BTSError) as caught:
        load_containment_environment_descriptor(path)
    assert caught.value.reason is BTSRejectReason.REJECT_EXECUTION_THREAT
    assert caught.value.evidence.detail_code == "bts_cli_containment_env_digest_v1"


def test_tampered_descriptor_digest_mismatch_rejects(tmp_path: Path) -> None:
    """The critical tamper test: a descriptor internally inconsistent with its
    own pins -- the deterministic, offline analogue of a digest that does not
    match the measured runtime -- rejects with the correct reason, exactly as
    a caller-supplied mismatched flag rejects downstream in exec_sandbox
    (see tests/test_exec_sandbox.py::test_binary_digest_tamper_rejects, which
    this change leaves untouched)."""

    payload = json.loads(_REAL_DESCRIPTOR_TEXT)
    # A different, well-formed digest: the file no longer describes the
    # binary its own nsjail_build_identity was derived from.
    payload["nsjail_sha256"] = "sha256:" + "7" * 64
    path = tmp_path / "environment.json"
    _write_json(path, payload)
    with pytest.raises(BTSError) as caught:
        load_containment_environment_descriptor(path)
    assert caught.value.reason is BTSRejectReason.REJECT_EXECUTION_THREAT
    assert caught.value.evidence.detail_code == "bts_cli_containment_env_identity_mismatch_v1"

    # The same tamper surfaces through the full resolver, not just the loader.
    with pytest.raises(BTSError) as caught_via_resolver:
        resolve_containment_substrate(
            nsjail_sha256=None,
            nsjail_version=None,
            nsjail_build_identity=None,
            config_schema_digest=None,
            rootfs_source=None,
            rootfs_digest=None,
            descriptor_path=path,
            environ={},
        )
    assert caught_via_resolver.value.evidence.detail_code == "bts_cli_containment_env_identity_mismatch_v1"


def test_wrong_schema_version_rejects(tmp_path: Path) -> None:
    payload = json.loads(_REAL_DESCRIPTOR_TEXT)
    payload["schema_version"] = "leitir-containment-environment-v2"
    path = tmp_path / "environment.json"
    _write_json(path, payload)
    with pytest.raises(BTSError) as caught:
        load_containment_environment_descriptor(path)
    assert caught.value.evidence.detail_code == "bts_cli_containment_env_schema_v1"


# --- receipt: every resolved value is named, with its source ---------------


def test_receipt_names_every_resolved_value_and_source(tmp_path: Path) -> None:
    resolved = resolve_containment_substrate(
        nsjail_sha256="sha256:" + "1" * 64,
        nsjail_version=None,
        nsjail_build_identity=None,
        config_schema_digest=None,
        rootfs_source="/explicit/rootfs",
        rootfs_digest=None,
        environ={},
    )
    receipt = resolved.receipt()
    assert receipt["schema_version"] == "leitir-containment-environment-resolution-v1"
    fields = receipt["resolved"]
    assert set(fields) == {"nsjail_sha256", "nsjail_version", "nsjail_build_identity", "config_schema_digest", "rootfs_source", "rootfs_digest"}
    assert fields["nsjail_sha256"] == {"value": "sha256:" + "1" * 64, "source": "flag"}
    assert fields["rootfs_source"] == {"value": "/explicit/rootfs", "source": "flag"}
    assert fields["nsjail_version"]["source"] == "descriptor"

    out_dir = tmp_path / "out"
    out_dir.mkdir()
    write_containment_environment_receipt(out_dir, resolved)
    on_disk = json.loads((out_dir / "containment-environment-resolution.json").read_text(encoding="utf-8"))
    assert on_disk == receipt


# --- determinism -------------------------------------------------------------


def test_resolution_is_byte_identical_across_pythonhashseed(tmp_path: Path) -> None:
    src_dir = str(Path(__file__).resolve().parents[1] / "src")
    script = tmp_path / "resolve.py"
    script.write_text(
        f"import sys; sys.path.insert(0, {src_dir!r})\n"
        "from leitir.bts_cli import resolve_containment_substrate\n"
        "resolved = resolve_containment_substrate(nsjail_sha256=None, nsjail_version=None, "
        "nsjail_build_identity=None, config_schema_digest=None, rootfs_source=None, rootfs_digest=None, environ={})\n"
        "sys.stdout.buffer.write(resolved.to_bytes())\n",
        encoding="utf-8",
    )
    outputs = set()
    for seed in ("0", "1", "2", "42"):
        result = subprocess.run(
            [sys.executable, str(script)],
            env={"PYTHONHASHSEED": seed, "PATH": ""},
            capture_output=True,
            check=True,
        )
        outputs.add(result.stdout)
    assert len(outputs) == 1


# --- CLI wiring: short invocation vs. long invocation -----------------------


def _stub_pipeline_result(digest_prefix: str) -> SimpleNamespace:
    return SimpleNamespace(
        verdict=SimpleNamespace(
            status=SimpleNamespace(value="complete"),
            bts_digest=f"{digest_prefix}-bts",
            relocation_digest=f"{digest_prefix}-relocation",
            rerun_report_digest=f"{digest_prefix}-rerun",
            probe_report_digest=f"{digest_prefix}-probe",
        )
    )


def _run_bts_run_cli(monkeypatch: pytest.MonkeyPatch, argv: list[str]) -> tuple[int, dict[str, object], list[dict[str, object]]]:
    calls: list[dict[str, object]] = []

    def fake_run_pipeline(root: Path, owner: str, repo: str, commit_sha: str, **kwargs: object) -> SimpleNamespace:
        calls.append({"root": root, "owner": owner, "repo": repo, "commit_sha": commit_sha, **kwargs})
        return _stub_pipeline_result("fixture")

    monkeypatch.setattr("leitir.pipeline_cli.run_pipeline", fake_run_pipeline)
    out = io.StringIO()
    err = io.StringIO()
    code = cli.main(argv, stdout=out, stderr=err)
    payload = json.loads(out.getvalue()) if out.getvalue().strip() else {}
    if code != 0:
        raise AssertionError(f"bts-run exited {code}: {err.getvalue()}")
    return code, payload, calls


def test_short_invocation_resolves_and_runs_equivalently_to_long_form(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    descriptor = load_containment_environment_descriptor()
    contract_spec = tmp_path / "contract.json"
    contract_spec.write_text("[]", encoding="utf-8")
    short_out = tmp_path / "short-out"
    long_out = tmp_path / "long-out"

    base_argv = [
        "bts-run", f"owner/repo@{_SHA}",
        "--root", str(tmp_path / "root"),
        "--seed-module", "donor_pkg.value",
        "--seed-name", "VALUE",
        "--contract-spec", str(contract_spec),
        "--recipient-package", "transplant",
        "--json",
    ]

    _, short_payload, short_calls = _run_bts_run_cli(
        monkeypatch, [*base_argv, "--out", str(short_out)]
    )
    _, long_payload, long_calls = _run_bts_run_cli(
        monkeypatch,
        [
            *base_argv, "--out", str(long_out),
            "--nsjail-sha256", descriptor.nsjail_sha256,
            "--nsjail-version", descriptor.nsjail_version,
            "--nsjail-build-identity", descriptor.nsjail_build_identity,
            "--config-schema-digest", descriptor.config_schema_digest,
            "--rootfs-source", str(DEFAULT_ROOTFS_SOURCE_PATH),
            "--rootfs-digest", descriptor.rootfs_digest,
        ],
    )

    assert len(short_calls) == 1 and len(long_calls) == 1
    short_call, long_call = short_calls[0], long_calls[0]
    substrate_fields = ("nsjail_sha256", "nsjail_version", "nsjail_build_identity", "config_schema_digest", "rootfs_source", "rootfs_digest")
    for field in substrate_fields:
        assert short_call[field] == long_call[field], field
    assert short_call["nsjail_sha256"] == descriptor.nsjail_sha256
    assert short_call["rootfs_source"] == Path(str(DEFAULT_ROOTFS_SOURCE_PATH))

    # Both invocations produced the same audit-trail payload shape and
    # resolved values (only the source labels legitimately differ).
    short_resolution = short_payload["containment_environment_resolution"]["resolved"]
    long_resolution = long_payload["containment_environment_resolution"]["resolved"]
    for field in substrate_fields:
        assert short_resolution[field]["value"] == long_resolution[field]["value"]
    assert short_resolution["nsjail_sha256"]["source"] == "descriptor"
    assert long_resolution["nsjail_sha256"]["source"] == "flag"

    # The receipt was written to disk in both output directories.
    assert json.loads((short_out / "containment-environment-resolution.json").read_text(encoding="utf-8")) == short_payload["containment_environment_resolution"]
    assert json.loads((long_out / "containment-environment-resolution.json").read_text(encoding="utf-8")) == long_payload["containment_environment_resolution"]


def test_cli_explicit_flag_overrides_descriptor(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    contract_spec = tmp_path / "contract.json"
    contract_spec.write_text("[]", encoding="utf-8")
    override_digest = "sha256:" + "9" * 64

    _, payload, calls = _run_bts_run_cli(
        monkeypatch,
        [
            "bts-run", f"owner/repo@{_SHA}",
            "--root", str(tmp_path / "root"),
            "--seed-module", "donor_pkg.value",
            "--seed-name", "VALUE",
            "--contract-spec", str(contract_spec),
            "--recipient-package", "transplant",
            "--out", str(tmp_path / "out"),
            "--nsjail-sha256", override_digest,
            "--json",
        ],
    )
    assert calls[0]["nsjail_sha256"] == override_digest
    resolution = payload["containment_environment_resolution"]["resolved"]
    assert resolution["nsjail_sha256"] == {"value": override_digest, "source": "flag"}
    assert resolution["nsjail_version"]["source"] == "descriptor"


def test_cli_rejects_before_running_when_descriptor_is_tampered(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    payload = json.loads(_REAL_DESCRIPTOR_TEXT)
    payload["nsjail_sha256"] = "sha256:" + "7" * 64
    tampered = tmp_path / "tampered-environment.json"
    _write_json(tampered, payload)
    contract_spec = tmp_path / "contract.json"
    contract_spec.write_text("[]", encoding="utf-8")

    calls: list[object] = []
    monkeypatch.setattr(
        "leitir.pipeline_cli.run_pipeline",
        lambda *a, **k: calls.append((a, k)) or _stub_pipeline_result("unused"),
    )
    out = io.StringIO()
    err = io.StringIO()
    code = cli.main(
        [
            "bts-run", f"owner/repo@{_SHA}",
            "--root", str(tmp_path / "root"),
            "--seed-module", "donor_pkg.value",
            "--seed-name", "VALUE",
            "--contract-spec", str(contract_spec),
            "--recipient-package", "transplant",
            "--out", str(tmp_path / "out"),
            "--containment-environment", str(tampered),
            "--json",
        ],
        stdout=out,
        stderr=err,
    )
    assert code != 0
    assert not calls, "the pipeline must never run once the descriptor fails its own integrity check"
    error_payload = json.loads(err.getvalue().removeprefix("leitir: error: ").strip())
    assert error_payload["reason"] == BTSRejectReason.REJECT_EXECUTION_THREAT.value
    assert error_payload["evidence"]["detail_code"] == "bts_cli_containment_env_identity_mismatch_v1"
    assert not (tmp_path / "out" / "containment-environment-resolution.json").exists()
