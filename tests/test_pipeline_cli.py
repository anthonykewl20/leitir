from __future__ import annotations

import base64
import hashlib
import importlib.util
import json
import os
import shutil
import subprocess
import sys
from dataclasses import replace
from pathlib import Path

import pytest

from leitir.bts_bench import CandidateIdentity, SeedSpan, load_manifest
from leitir.bts_cli import SeedSelector, load_donor_snapshot
from leitir.bts_errors import BTSError, TransplantError
from leitir.exit_corpus import add_runnable_section
from leitir.materialize import manifest_digest_fields, target_path
from leitir.pipeline_cli import (
    BTSSubstratePins,
    ContractTestSpec,
    _prepare_shared_stage,
    _prepared,
    _require_runtime_ratification,
    assemble_bts_task_request,
    build_containment_policy,
    exit_gate_run,
    record_baseline,
    run_pipeline,
)
from leitir.relocate import ContractTest, ModuleMap
from leitir.rerun import ContractBaselineEvidence, TestOutcome, TestOutcomeEvidence
from leitir.treehash import compute_materialized_tree_hash

_FIXTURE = Path(__file__).parent / "fixtures" / "pipeline_cli"
_DIGEST = "sha256:" + "1" * 64
_SHA = "a" * 40
_BLOB_SHA = "d3400504c93fd42b1fd39d180e08940d2443bf63"
_ROOT = Path(__file__).resolve().parents[1]


def _without_donor_execution() -> None:
    os.environ.pop("LEITIR_ENABLE_DONOR_EXECUTION", None)


def test_pipeline_cli_import_does_not_require_fcntl() -> None:
    """Keep pure pipeline assembly surfaces importable on platforms without fcntl."""

    script = """
import builtins
import sys

original_import = builtins.__import__

def blocked_import(name, *args, **kwargs):
    if name == 'fcntl':
        raise ModuleNotFoundError("fcntl is unavailable")
    return original_import(name, *args, **kwargs)

builtins.__import__ = blocked_import
import leitir.pipeline_cli
assert 'fcntl' not in sys.modules
"""
    completed = subprocess.run(
        (sys.executable, "-c", script),
        cwd=_ROOT,
        env={**os.environ, "PYTHONPATH": "src"},
        capture_output=True,
        text=True,
        check=False,
    )
    assert completed.returncode == 0, completed.stderr


def test_shared_stage_rejects_unsupported_host_before_staging(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("leitir.pipeline_cli.platform.system", lambda: "Windows")

    with pytest.raises(TransplantError) as caught:
        _prepare_shared_stage(tmp_path, {}, object())  # type: ignore[arg-type]

    assert caught.value.evidence.detail_code == "unsupported_host"
    assert list(tmp_path.iterdir()) == []


def _bench_shelf(tmp_path: Path) -> None:
    target = target_path(tmp_path, "owner", "donor", _SHA)
    shutil.copytree(Path(__file__).parent / "fixtures" / "bts_cli" / "donor", target)
    (target / "LICENSE").write_text("MIT License\nPermission is hereby granted, free of charge\n", encoding="utf-8")
    digest, scope = compute_materialized_tree_hash(target)
    manifest = {
        "commit_sha": _SHA, "fetch_method": "codeload-tarball", "fetched_at": "2026-08-15T00:00:00Z",
        "host": "github.com", "owner": "owner", "repo": "donor", "repo_url": "https://github.com/owner/donor",
        "source": "git-commit", "parity": "exact", "spec": "github:owner/donor", "tag": None,
        "verified": True, "verified_at": "2026-08-15T00:00:00Z",
    }
    manifest.update(manifest_digest_fields(digest, scope=scope))
    (target / "leitir-manifest.json").write_text(json.dumps(manifest), encoding="utf-8")


def _bench_task_sidecars(tmp_path: Path):
    task = load_manifest(_ROOT / "benchmarks" / "bts-v1" / "tasks" / "async-retry-backoff.json").tasks[0]
    identity = CandidateIdentity("owner/donor", _SHA, "package/policy.py", _BLOB_SHA, "package.policy.normalize_contract", 5, 6)
    task = replace(
        task,
        gold=replace(task.gold, candidate_qrels=tuple(replace(item, identity=identity) if item.grade == 2 else item for item in task.gold.candidate_qrels), seed_span=SeedSpan(identity)),
        observation=replace(task.observation, candidates=(identity,), execution_candidates=(identity,), seed=identity),
    )
    tests = tuple(ContractTest(path, b"def test_sidecar():\n    pass\n", "sidecars." + Path(path).stem) for path in task.gold.required_tests)
    sidecar = tmp_path / "baseline.json"
    counts = task.gold.expected_counts
    assert counts is not None and task.gold.expected_selected_test_ids is not None
    sidecar.write_text(json.dumps({
        "contract_test_count": sum(counts),
        "expected_pass": counts[0],
        "expected_fail": counts[1],
        "expected_skip": counts[2],
        "selected_test_ids": list(task.gold.expected_selected_test_ids),
        "runner_convention": "fixture fresh subprocess",
    }, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8")
    return task, tests, sidecar


def test_record_baseline_fails_closed_without_containment_substrate() -> None:
    _without_donor_execution()
    with pytest.raises(TransplantError) as caught:
        record_baseline(_FIXTURE, [ContractTestSpec("contracts/contract_sample.py", "donor.contract_sample")], substrate=BTSSubstratePins(_DIGEST, "fixture", _DIGEST, _DIGEST, _FIXTURE, _DIGEST))
    assert caught.value.evidence.detail_code == "pipeline_cli_substrate_unavailable_v1"


def test_inline_contract_content_mismatch_rejects() -> None:
    with pytest.raises(Exception) as caught:
        record_baseline(_FIXTURE, [ContractTestSpec("contracts/contract_sample.py", "donor.contract_sample", b"tampered\n")], substrate=BTSSubstratePins(_DIGEST, "fixture", _DIGEST, _DIGEST, _FIXTURE, _DIGEST))
    assert getattr(caught.value, "evidence").detail_code == "pipeline_cli_contract_content_mismatch_v1"


def test_build_containment_policy_fails_closed_without_opt_in() -> None:
    _without_donor_execution()
    with pytest.raises(TransplantError) as caught:
        build_containment_policy(nsjail_sha256=_DIGEST, nsjail_version="fixture", nsjail_build_identity=_DIGEST, config_schema_digest=_DIGEST, rootfs_source=Path("/fixture-root"), rootfs_digest=_DIGEST)
    assert caught.value.evidence.detail_code == "pipeline_cli_substrate_unavailable_v1"


def test_pipeline_rejects_before_loading_or_running_donor_without_substrate(tmp_path: Path) -> None:
    _without_donor_execution()
    marker = tmp_path / "donor-ran"
    with pytest.raises(TransplantError) as caught:
        run_pipeline(tmp_path / "missing-shelf", "owner", "repo", "a" * 40, seed=SeedSelector("donor_pkg.value", "VALUE"), contract_tests_path=tmp_path / "missing.json", out_dir=tmp_path / "out", recipient_package="transplant", nsjail_sha256=_DIGEST, nsjail_version="fixture", nsjail_build_identity=_DIGEST, config_schema_digest=_DIGEST, rootfs_source=tmp_path / "rootfs", rootfs_digest=_DIGEST)
    assert caught.value.evidence.detail_code == "pipeline_cli_substrate_unavailable_v1"
    assert not marker.exists()


@pytest.mark.parametrize("seed", ["0", "1", "42"])
def test_offline_preflight_is_seed_independent(seed: str) -> None:
    _without_donor_execution()
    with pytest.raises(TransplantError) as caught:
        build_containment_policy(nsjail_sha256=_DIGEST, nsjail_version=seed, nsjail_build_identity=_DIGEST, config_schema_digest=_DIGEST, rootfs_source=Path("/fixture-root"), rootfs_digest=_DIGEST)
    assert caught.value.evidence.detail_code == "pipeline_cli_substrate_unavailable_v1"


def test_assemble_bts_task_request_maps_pinned_task_sidecars_without_executing(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _bench_shelf(tmp_path)
    task, tests, sidecar = _bench_task_sidecars(tmp_path)
    monkeypatch.setattr("leitir.pipeline_cli._require_substrate", lambda: None)

    assembly = assemble_bts_task_request(task, tmp_path, contract_tests=tests, baseline_sidecar=sidecar, substrate=BTSSubstratePins(_DIGEST, "fixture", _DIGEST, _DIGEST, tmp_path, _DIGEST))

    request = assembly.request
    assert (request.snapshot.slug, request.snapshot.commit_sha) == ("owner/donor", _SHA)
    assert (request.seed.module, request.seed.qualified_name) == ("package.policy", "package.policy.normalize_contract")
    assert len(request.module_map.entries) == 1
    assert {item.donor for item in request.module_map.entries} == {"package.policy"}
    assert request.contract_tests == tests
    assert request.baseline.selected_test_ids == task.gold.expected_selected_test_ids


def test_task_assembly_observation_is_unchanged_after_gold_is_poisoned(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """C3 observation reads the captured non-gold plan, not qrels or expected values."""

    _bench_shelf(tmp_path)
    task, tests, sidecar = _bench_task_sidecars(tmp_path)
    monkeypatch.setattr("leitir.pipeline_cli._require_substrate", lambda: None)
    substrate = BTSSubstratePins(_DIGEST, "fixture", _DIGEST, _DIGEST, tmp_path, _DIGEST)

    captured = assemble_bts_task_request(task, tmp_path, contract_tests=tests, baseline_sidecar=sidecar, substrate=substrate).to_bytes()
    poisoned = replace(task, gold=replace(task.gold, expected_license="not-a-real-license", required_helpers=("garbage",)))
    observed = assemble_bts_task_request(poisoned, tmp_path, contract_tests=tests, baseline_sidecar=sidecar, substrate=substrate).to_bytes()

    assert observed == captured


def test_assemble_bts_task_request_rejects_missing_substrate_before_loading_sidecars(tmp_path: Path) -> None:
    task, _, _ = _bench_task_sidecars(tmp_path)

    with pytest.raises(BTSError) as caught:
        assemble_bts_task_request(task, tmp_path)

    assert caught.value.evidence.detail_code == "pipeline_cli_task_substrate_pins_v1"


def test_assembled_bts_task_request_bytes_are_hash_seed_independent(tmp_path: Path) -> None:
    _bench_shelf(tmp_path)
    _, _, sidecar = _bench_task_sidecars(tmp_path)
    script = """
from dataclasses import replace
from pathlib import Path
import sys
from leitir.bts_bench import CandidateIdentity, SeedSpan, load_manifest
from leitir.pipeline_cli import BTSSubstratePins, assemble_bts_task_request
from leitir.relocate import ContractTest
import leitir.pipeline_cli as pipeline_cli
root = Path(sys.argv[1])
task = load_manifest(Path(sys.argv[2])).tasks[0]
identity = CandidateIdentity('owner/donor', 'a' * 40, 'package/policy.py', 'd3400504c93fd42b1fd39d180e08940d2443bf63', 'package.policy.normalize_contract', 5, 6)
task = replace(task, gold=replace(task.gold, candidate_qrels=tuple(replace(item, identity=identity) if item.grade == 2 else item for item in task.gold.candidate_qrels), seed_span=SeedSpan(identity)), observation=replace(task.observation, candidates=(identity,), execution_candidates=(identity,), seed=identity))
tests = tuple(ContractTest(path, b'def test_sidecar():\\n    pass\\n', 'sidecars.' + Path(path).stem) for path in task.gold.required_tests)
pipeline_cli._require_substrate = lambda: None
assembly = assemble_bts_task_request(task, root, contract_tests=tests, baseline_sidecar=Path(sys.argv[3]), substrate=BTSSubstratePins('sha256:' + '1' * 64, 'fixture', 'sha256:' + '1' * 64, 'sha256:' + '1' * 64, root, 'sha256:' + '1' * 64))
sys.stdout.buffer.write(assembly.to_bytes())
"""
    outputs = [
        subprocess.check_output((sys.executable, "-c", script, str(tmp_path), str(_ROOT / "benchmarks" / "bts-v1" / "tasks" / "async-retry-backoff.json"), str(sidecar)), cwd=_ROOT, env={**os.environ, "PYTHONHASHSEED": seed, "PYTHONPATH": "src"})
        for seed in ("0", "1", "42")
    ]

    assert outputs[0] == outputs[1] == outputs[2]


def test_exit_corpus_webcolors_seed_and_policy_assemble_offline(tmp_path: Path) -> None:
    """The source-root module identity, policy, and module-map input agree."""

    corpus = json.loads((_ROOT / "benchmarks" / "exit-corpus" / "corpus-v1.1.json").read_text(encoding="utf-8"))
    case = next(item for item in corpus["cases"] if item["case_id"] == "webcolors-rgb-to-hex")
    runnable = next(item for item in corpus["runnable"]["per_case"] if item["case_id"] == case["case_id"])
    shelf = target_path(tmp_path, case["donor"]["owner"], case["donor"]["repo"], case["donor"]["commit_sha"])
    (shelf / "src" / "webcolors").mkdir(parents=True)
    (shelf / "src" / "__init__.py").write_text("", encoding="utf-8")
    (shelf / "src" / "webcolors" / "__init__.py").write_text("", encoding="utf-8")
    (shelf / "src" / "webcolors" / "_normalization.py").write_text("def normalize_hex(value):\n    return value\n", encoding="utf-8")
    (shelf / "src" / "webcolors" / "_conversion.py").write_text("from src.webcolors._normalization import normalize_hex\n\ndef rgb_to_hex(value):\n    return normalize_hex(value)\n", encoding="utf-8")
    (shelf / "LICENSE").write_text("BSD-3-Clause\n", encoding="utf-8")
    digest, scope = compute_materialized_tree_hash(shelf)
    manifest = {
        "commit_sha": case["donor"]["commit_sha"], "fetch_method": "codeload-tarball", "fetched_at": "2026-08-15T00:00:00Z",
        "host": "github.com", "owner": case["donor"]["owner"], "repo": case["donor"]["repo"], "repo_url": "https://github.com/ubernostrum/webcolors",
        "source": "git-commit", "parity": "exact", "spec": "github:ubernostrum/webcolors", "tag": None,
        "verified": True, "verified_at": "2026-08-15T00:00:00Z",
    }
    manifest.update(manifest_digest_fields(digest, scope=scope))
    (shelf / "leitir-manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    snapshot = load_donor_snapshot(tmp_path, case["donor"]["owner"], case["donor"]["repo"], case["donor"]["commit_sha"])
    policy = _ROOT / "benchmarks" / "exit-corpus" / runnable["policy_path"]

    _resolution, seed, result = _prepared(snapshot, SeedSelector(case["seed"]["module"], f"{case['seed']['module']}.{case['seed']['qualified_name']}"), policy)

    assert seed.module == case["seed"]["module"] == "src.webcolors._conversion"
    assert seed.qualified_name == f"{case['seed']['module']}.{case['seed']['qualified_name']}"
    assert result.bts is not None
    assert {member.node.module for member in result.bts.members} >= {seed.module}
    module_map = ModuleMap.from_pairs(*((module, f"transplant.webcolors.{module}") for module in sorted({member.node.module for member in result.bts.members})))
    assert any(entry.donor == seed.module and entry.recipient == f"transplant.webcolors.{seed.module}" for entry in module_map.entries)


def _exit_sidecars(root: Path) -> None:
    corpus = json.loads((_FIXTURE / "corpus-runnable-v1.1.json").read_text())
    for case in corpus["cases"]:
        case_id = case["case_id"]
        contract = root / "contracts" / f"{case_id}.py"
        contract.parent.mkdir(parents=True, exist_ok=True)
        contract.write_text("def test_recorded():\n    pass\n")
        outcomes = tuple(
            TestOutcomeEvidence(f"{case_id}::test_{number}::-", TestOutcome.PASS, "recorded_v1", "sha256:" + str(number + 1) * 64)
            for number in range(3)
        )
        baseline = ContractBaselineEvidence.create(outcomes, baseline_mount_plan_digest="sha256:" + "a" * 64, baseline_execution_policy_digest="sha256:" + "b" * 64)
        sidecar = root / "donors" / case_id / "baseline.json"
        sidecar.parent.mkdir(parents=True, exist_ok=True)
        sidecar.write_bytes(baseline.to_bytes())


def test_exit_gate_parses_v11_runnable_contracts_and_sidecars_before_substrate(tmp_path: Path) -> None:
    _without_donor_execution()
    _exit_sidecars(tmp_path)
    substrate = json.loads((_FIXTURE / "corpus-runnable-v1.1.json").read_text())["runnable"]["substrate"]
    with pytest.raises(TransplantError) as caught:
        exit_gate_run(
            _FIXTURE / "corpus-runnable-v1.1.json", tmp_path / "donors", corpus_root=tmp_path,
            nsjail_version="fixture", nsjail_build_identity=_DIGEST, config_schema_digest=_DIGEST,
            rootfs_source=tmp_path / "rootfs",
            substrate_nsjail_sha256=substrate["nsjail_sha256"], substrate_rootfs_digest=substrate["rootfs_digest"],
        )
    assert caught.value.evidence.detail_code == "pipeline_cli_substrate_unavailable_v1"


def test_add_runnable_section_rejects_case_alignment_errors() -> None:
    manifest = json.loads((_FIXTURE / "corpus-runnable-v1.1.json").read_text())
    runnable = manifest["runnable"]
    runnable["per_case"] = runnable["per_case"][:-1]
    with pytest.raises(BTSError) as caught:
        add_runnable_section(manifest, runnable)
    assert caught.value.evidence.detail_code == "exit_corpus_runnable_case_alignment_v1"


_HAS_CRYPTOGRAPHY = importlib.util.find_spec("cryptography") is not None


def _l5_ratification(tmp_path: Path) -> tuple[dict[str, object], Path, Path, Path]:
    """Create the L5 projection with the fixed manifest-auth vector key."""

    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    vectors = json.loads((_ROOT / "tests" / "fixtures" / "manifest_auth" / "vectors.json").read_text(encoding="utf-8"))
    private_key = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
    public_key = private_key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    corpus_digest = "sha256:" + "a" * 64
    manifest: dict[str, object] = {
        "corpus_id": "fixture-corpus",
        "ratified_runtime_digest": corpus_digest,
    }
    projection = {
        "corpus_id": manifest["corpus_id"],
        "corpus_manifest_digest": corpus_digest,
        "ratified_runtime_digest": corpus_digest,
    }
    canonical = json.dumps(projection, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode() + b"\n"
    record = {
        "algorithm": "ed25519",
        "key_id": vectors["key_id"],
        "projection": projection,
        "projection_digest": hashlib.sha256(canonical).hexdigest(),
        "schema_version": "leitir-manifest-auth-v1",
        "signature": base64.b64encode(private_key.sign(canonical)).decode("ascii"),
    }
    sidecar = tmp_path / "ratification-v1.json"
    sidecar.write_text(json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8")
    keys = tmp_path / "trusted-keys.json"
    keys.write_text(json.dumps({"keys": [{"key_id": vectors["key_id"], "public_key_b64": base64.b64encode(public_key).decode("ascii"), "note": "fixed manifest-auth vector key"}]}), encoding="utf-8")
    return manifest, sidecar, keys, tmp_path / "donors"


@pytest.mark.skipif(not _HAS_CRYPTOGRAPHY, reason="requires optional auth extra")
def test_l5_ratification_valid_signature_allows_authority_to_proceed(tmp_path: Path) -> None:
    manifest, sidecar, keys, donors = _l5_ratification(tmp_path)

    _require_runtime_ratification(manifest, corpus_manifest_digest="sha256:" + "a" * 64, donors_dir=donors, trusted_keys_path=keys, ratification_sidecar=sidecar, default_sidecar=sidecar)


@pytest.mark.skipif(not _HAS_CRYPTOGRAPHY, reason="requires optional auth extra")
def test_l5_ratification_missing_sidecar_rejects_typed(tmp_path: Path) -> None:
    manifest, sidecar, keys, donors = _l5_ratification(tmp_path)
    sidecar.unlink()

    with pytest.raises(BTSError) as caught:
        _require_runtime_ratification(manifest, corpus_manifest_digest="sha256:" + "a" * 64, donors_dir=donors, trusted_keys_path=keys, ratification_sidecar=sidecar, default_sidecar=sidecar)

    assert caught.value.evidence.detail_code == "pipeline_cli_ratification_invalid_v1"


@pytest.mark.skipif(not _HAS_CRYPTOGRAPHY, reason="requires optional auth extra")
@pytest.mark.parametrize("field", ["signature", "projection"])
def test_l5_ratification_tampered_signature_or_projection_rejects_typed(tmp_path: Path, field: str) -> None:
    manifest, sidecar, keys, donors = _l5_ratification(tmp_path)
    record = json.loads(sidecar.read_text(encoding="utf-8"))
    if field == "signature":
        record[field] = "B" + record[field][1:]
    else:
        record[field]["corpus_id"] = "tampered"
    sidecar.write_text(json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8")

    with pytest.raises(BTSError) as caught:
        _require_runtime_ratification(manifest, corpus_manifest_digest="sha256:" + "a" * 64, donors_dir=donors, trusted_keys_path=keys, ratification_sidecar=sidecar, default_sidecar=sidecar)

    assert caught.value.evidence.detail_code == "pipeline_cli_ratification_invalid_v1"


@pytest.mark.skipif(not _HAS_CRYPTOGRAPHY, reason="requires optional auth extra")
def test_l5_ratification_self_signed_untrusted_key_rejects_typed(tmp_path: Path) -> None:
    manifest, sidecar, keys, donors = _l5_ratification(tmp_path)
    record = json.loads(sidecar.read_text(encoding="utf-8"))
    record["key_id"] = "0" * 64
    sidecar.write_text(json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8")

    with pytest.raises(BTSError) as caught:
        _require_runtime_ratification(manifest, corpus_manifest_digest="sha256:" + "a" * 64, donors_dir=donors, trusted_keys_path=keys, ratification_sidecar=sidecar, default_sidecar=sidecar)

    assert caught.value.evidence.detail_code == "pipeline_cli_ratification_invalid_v1"
