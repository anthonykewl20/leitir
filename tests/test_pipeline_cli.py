from __future__ import annotations

import base64
import hashlib
import importlib.util
import json
import os
import shutil
import subprocess
import sys
import textwrap
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast

import pytest

import leitir.pipeline_cli as pipeline_cli
from leitir.bts import BTSStatus
from leitir.bts_bench import CandidateIdentity, SeedSpan, load_manifest
from leitir.bts_cli import SeedSelector, load_donor_snapshot
from leitir.bts_errors import BTSError, BTSRejectReason, TransplantError
from leitir.bts_exit_gate import rejected_preparation_report
from leitir.exit_corpus import add_runnable_section
from leitir.materialize import manifest_digest_fields, target_path
from leitir.pipeline_cli import (
    BaselineTestExecutionEvidence,
    BTSSubstratePins,
    ContractTestSpec,
    _baseline_from_sidecar,
    _baseline_recording_bytes,
    _baseline_test_execution_evidence,
    _exit_seed_span,
    _license_from_materialized_donor,
    _prepare_shared_stage,
    _prepared,
    _require_runtime_ratification,
    _runnable_contract_tests,
    _task_spec,
    assemble_bts_task_request,
    build_containment_policy,
    execution_contract_tests,
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
_HAS_NO_FOLLOW = hasattr(os, "O_NOFOLLOW")


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


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="shared staging requires Linux fcntl locking")
def test_shared_stage_prepares_a_writable_policy_pinned_scratch_directory(tmp_path: Path) -> None:
    class RelocationFixture:
        relocation_digest = _DIGEST
        files: tuple[object, ...] = ()

        def publish(self, destination: Path) -> None:
            destination.mkdir()

    stage, _staged = _prepare_shared_stage(tmp_path, {"fixture": "scratch"}, RelocationFixture())  # type: ignore[arg-type]

    scratch = stage / "scratch"
    assert scratch.is_dir() and not scratch.is_symlink()
    assert scratch.stat().st_mode & 0o777 == 0o777


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
        record_baseline(_FIXTURE, [ContractTestSpec("contracts/contract_sample.py", "donor.contract_sample")], substrate=BTSSubstratePins(_DIGEST, "fixture", _DIGEST, _DIGEST, _FIXTURE, _DIGEST), scratch_dir=_FIXTURE / "scratch")
    assert caught.value.evidence.detail_code == "pipeline_cli_substrate_unavailable_v1"


def test_inline_contract_content_mismatch_rejects() -> None:
    with pytest.raises(Exception) as caught:
        record_baseline(_FIXTURE, [ContractTestSpec("contracts/contract_sample.py", "donor.contract_sample", b"tampered\n")], substrate=BTSSubstratePins(_DIGEST, "fixture", _DIGEST, _DIGEST, _FIXTURE, _DIGEST), scratch_dir=_FIXTURE / "scratch")
    assert getattr(caught.value, "evidence").detail_code == "pipeline_cli_contract_content_mismatch_v1"


@pytest.mark.skipif(sys.platform != "linux", reason="startup attestation reads Linux procfs")
def test_baseline_runner_emits_startup_attestation_before_donor_can_mutate_environment(tmp_path: Path) -> None:
    marker = tmp_path / "donor-executed"
    test_source = tmp_path / "test_mutates_environment.py"
    test_source.write_text(
        "import os\n"
        "\n"
        "def test_mutates_parent_namespace_environment():\n"
        "    for name in ('net', 'user', 'mnt', 'pid', 'ipc', 'uts'):\n"
        "        identity = os.stat('/proc/self/ns/' + name)\n"
        "        os.environ['LEITIR_PARENT_NS_' + name.upper()] = f'{identity.st_dev}:{identity.st_ino}'\n"
        f"    open({str(marker)!r}, 'w', encoding='utf-8').write('executed')\n"
        "    print('donor-executed')\n",
        encoding="utf-8",
    )
    environment = os.environ.copy()
    environment.update({f"LEITIR_PARENT_NS_{name.upper()}": "0:0" for name in ("net", "user", "mnt", "pid", "ipc", "uts")})
    completed = subprocess.run(
        (sys.executable, "-c", pipeline_cli._BASELINE_CHILD, str(test_source), "test_mutates_parent_namespace_environment"),
        check=False,
        capture_output=True,
        env=environment,
    )

    assert completed.returncode == 0, completed.stderr.decode("utf-8", "strict")
    frames = completed.stdout.splitlines()
    assert len(frames) == 3
    assert json.loads(frames[0])["namespace_mismatch"] is True
    assert frames[1] == b"donor-executed"
    assert json.loads(frames[2]) == {"outcome": "pass"}
    assert marker.read_text(encoding="utf-8") == "executed"


def test_containment_runners_textually_emit_attestations_before_module_execution() -> None:
    workflow = (_ROOT / ".github/workflows/bts-containment.yml").read_text(encoding="utf-8")

    assert pipeline_cli._BASELINE_CHILD.index("startup_attestation=containment_attestation()") < pipeline_cli._BASELINE_CHILD.index("spec.loader.exec_module(module)")
    runner = workflow.split("install -m 0644 /dev/stdin \"$rootfs/harness/runner.py\" <<'PY'", 1)[1].split("          PY\n", 1)[0]
    assert runner.index("def main():") < runner.index("startup_attestation = containment_attestation()") < runner.index("spec.loader.exec_module(module)")


def test_containment_workflow_runs_benchmark_after_only_exit_gate_failure() -> None:
    workflow = (_ROOT / ".github/workflows/bts-containment.yml").read_text(encoding="utf-8")

    exit_gate = workflow.index("- name: Run exit gate")
    benchmark = workflow.index("- name: Run optional BTS task corpus")
    next_step = workflow.index("- name:", benchmark + 1)
    assert "id: exit_gate" in workflow[exit_gate:benchmark]
    assert "if: ${{ inputs.run_bench && (success() || steps.exit_gate.outcome == 'failure') }}" in workflow[benchmark:next_step]


def test_contained_rootfs_runner_import_does_not_require_parent_namespace_environment(tmp_path: Path) -> None:
    workflow = (_ROOT / ".github/workflows/bts-containment.yml").read_text(encoding="utf-8")
    runner = workflow.split("install -m 0644 /dev/stdin \"$rootfs/harness/runner.py\" <<'PY'", 1)[1].split("          PY\n", 1)[0]
    runner_path = tmp_path / "runner.py"
    runner_path.write_text(textwrap.dedent(runner), encoding="utf-8")
    completed = subprocess.run(
        (
            sys.executable,
            "-c",
            "import importlib.util, sys; spec = importlib.util.spec_from_file_location('rootfs_runner', sys.argv[1]); module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)",
            str(runner_path),
        ),
        check=False,
        capture_output=True,
        env={},
    )

    assert completed.returncode == 0, completed.stderr.decode("utf-8", "strict")


def test_exit_baseline_sidecar_and_runnable_contracts_are_digest_anchored_without_no_follow(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    baseline = ContractBaselineEvidence.create(
        (TestOutcomeEvidence("contract.py::test_one::-", TestOutcome.PASS, "recorded", _DIGEST),),
        baseline_mount_plan_digest=_DIGEST,
        baseline_execution_policy_digest="sha256:" + "2" * 64,
    )
    sidecar = tmp_path / "baseline.json"
    sidecar.write_bytes(baseline.to_bytes())
    contract = tmp_path / "contracts" / "contract.py"
    contract.parent.mkdir()
    contract.write_text("def test_one():\n    pass\n", encoding="utf-8")
    monkeypatch.delattr(os, "O_NOFOLLOW", raising=False)

    assert _baseline_from_sidecar(sidecar) == baseline
    assert _runnable_contract_tests(tmp_path, [{"path": "contracts/contract.py", "module": "contract"}]) == (
        ContractTest("contracts/contract.py", b"def test_one():\n    pass\n", "contract"),
    )


def test_task_spec_and_composition_contract_subset_are_deterministic() -> None:
    task = load_manifest(_ROOT / "benchmarks" / "bts-v1" / "tasks" / "three-repo-combine.json").tasks[0]
    assert task.observation is not None
    spec = _task_spec(task.observation.required_behaviors)
    tests = (
        ContractTest("a.py", b"import donor.selected\n", "a"),
        ContractTest("b.py", b"from donor.other import value\n", "b"),
    )
    identity = CandidateIdentity("owner/donor", _SHA, "package/policy.py", _BLOB_SHA, "donor.selected.value", 1, 1)

    assert tuple(f"{item.behavior_id}@{item.contract_version}" for item in spec.required_behaviors) == task.observation.required_behaviors
    assert execution_contract_tests(task, identity, tests) == (tests[0],)


def test_pipeline_helpers_reject_malformed_sidecars_and_classify_pinned_license(tmp_path: Path) -> None:
    malformed = tmp_path / "malformed.json"
    malformed.write_text("{}", encoding="utf-8")
    with pytest.raises(BTSError) as caught:
        _baseline_from_sidecar(malformed)
    assert caught.value.evidence.detail_code == "pipeline_cli_exit_baseline_sidecar_v1"
    with pytest.raises(BTSError) as caught:
        _runnable_contract_tests(tmp_path, {"not": "a list"})
    assert caught.value.evidence.detail_code == "pipeline_cli_exit_runnable_v1"

    (tmp_path / "LICENSE").write_text("Apache License\nVersion 2.0\n", encoding="utf-8")
    assert _license_from_materialized_donor(tmp_path) == "Apache-2.0"
    (tmp_path / "LICENSE").unlink()
    (tmp_path / "LICENCE").write_text("MIT License\nPermission is hereby granted, free of charge\n", encoding="utf-8")
    assert _license_from_materialized_donor(tmp_path) == "MIT"


def test_build_containment_policy_fails_closed_without_opt_in() -> None:
    _without_donor_execution()
    with pytest.raises(TransplantError) as caught:
        build_containment_policy(nsjail_sha256=_DIGEST, nsjail_version="fixture", nsjail_build_identity=_DIGEST, config_schema_digest=_DIGEST, rootfs_source=Path("/fixture-root"), rootfs_digest=_DIGEST, scratch_dir=Path("/fixture-scratch"))
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
        build_containment_policy(nsjail_sha256=_DIGEST, nsjail_version=seed, nsjail_build_identity=_DIGEST, config_schema_digest=_DIGEST, rootfs_source=Path("/fixture-root"), rootfs_digest=_DIGEST, scratch_dir=Path("/fixture-scratch"))
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


def test_exit_corpus_url_seed_span_authorizes_the_module_future_import() -> None:
    corpus = json.loads((_ROOT / "benchmarks" / "exit-corpus" / "corpus-v1.1.json").read_text(encoding="utf-8"))
    case = next(item for item in corpus["cases"] if item["case_id"] == "url-normalize-fragment")

    assert _exit_seed_span(_ROOT / "benchmarks" / "exit-corpus", "url-normalize-fragment", case["seed"]) == (1, 27)


def test_baseline_policy_adds_rootfs_site_packages_before_donor(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setattr(pipeline_cli, "_require_substrate", lambda: None)
    rootfs = tmp_path / "rootfs"
    donor = tmp_path / "donor"
    tests = tmp_path / "tests"
    for path in (rootfs, donor, tests):
        path.mkdir()
    scratch = tmp_path / "scratch"
    scratch.mkdir()
    policy = pipeline_cli._baseline_containment_policy(
        BTSSubstratePins(_DIGEST, "fixture", _DIGEST, _DIGEST, rootfs, _DIGEST), donor, tests, scratch, (".",)
    )
    assert "PYTHONPATH=/opt/leitir/site-packages:/donor" in policy.environment


@pytest.mark.skipif(os.name == "nt", reason="POSIX directory search permissions are required by nsjail")
def test_deterministic_stage_ancestors_are_searchable_without_being_writable(tmp_path: Path) -> None:
    stage = pipeline_cli._deterministic_stage_directory(tmp_path, {"case": "fixture"})

    assert os.stat(stage.parent).st_mode & 0o777 == 0o711
    assert os.stat(stage).st_mode & 0o777 == 0o711


@pytest.mark.skipif(os.name == "nt", reason="POSIX ownership and mode semantics are required by nsjail")
def test_stage_relocation_preserves_modes_while_mapping_sudo_runner_ownership(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    class _Relocation:
        def publish(self, target: Path) -> None:
            target.mkdir()
            (target / "private").mkdir()
            (target / "private" / "input.py").write_text("x = 1\n", encoding="utf-8")
            (target / "private").chmod(0o500)
            (target / "private" / "input.py").chmod(0o400)

    ownership: list[tuple[Path, int, int]] = []
    monkeypatch.setattr(pipeline_cli.os, "geteuid", lambda: 0, raising=False)
    monkeypatch.setenv("SUDO_UID", "1001")
    monkeypatch.setenv("SUDO_GID", "1002")
    monkeypatch.setattr(pipeline_cli.os, "chown", lambda path, uid, gid: ownership.append((Path(path), uid, gid)), raising=False)

    staged = pipeline_cli._stage_relocation(cast(Any, _Relocation()), tmp_path)

    assert (staged / "private").stat().st_mode & 0o777 == 0o500
    assert (staged / "private" / "input.py").stat().st_mode & 0o777 == 0o400
    assert ownership == [
        (staged, 1001, 1002),
        (staged / "private", 1001, 1002),
        (staged / "private" / "input.py", 1001, 1002),
    ]


def test_baseline_recording_preserves_bounded_child_abort_evidence() -> None:
    baseline = ContractBaselineEvidence.create(
        (TestOutcomeEvidence("contract.py::test_one::-", TestOutcome.FAIL, "recorded", _DIGEST),),
        baseline_mount_plan_digest=_DIGEST,
        baseline_execution_policy_digest=_DIGEST,
    )
    result = SimpleNamespace(completed=False, exit_code=137, stderr=b"x" * 3000 + b"child aborted")
    observation = _baseline_test_execution_evidence("contract.py::test_one::-", result)

    evidence = json.loads(_baseline_recording_bytes(baseline, (observation,)))

    assert set(evidence) == {"baseline", "per_test", "schema_version"}
    assert evidence["schema_version"] == "leitir-baseline-recording-v1"
    assert evidence["per_test"] == [{
        "canonical_test_id": "contract.py::test_one::-",
        "completed": False,
        "returncode": 137,
        "child_stderr_tail": "x" * (2048 - len("child aborted")) + "child aborted",
    }]


def test_baseline_recording_rejects_observations_outside_the_baseline() -> None:
    baseline = ContractBaselineEvidence.create(
        (TestOutcomeEvidence("contract.py::test_one::-", TestOutcome.PASS, "recorded", _DIGEST),),
        baseline_mount_plan_digest=_DIGEST,
        baseline_execution_policy_digest=_DIGEST,
    )
    observation = BaselineTestExecutionEvidence("other.py::test_two::-", True, 0, "")

    with pytest.raises(ValueError, match="do not match"):
        _baseline_recording_bytes(baseline, (observation,))


def test_preparation_rejection_retains_recorded_and_expected_outcome_vectors() -> None:
    recorded = ContractBaselineEvidence.create(
        (TestOutcomeEvidence("contract.py::test_one::-", TestOutcome.FAIL, "recorded", _DIGEST),),
        baseline_mount_plan_digest=_DIGEST,
        baseline_execution_policy_digest=_DIGEST,
    )
    expected = ContractBaselineEvidence.create(
        (TestOutcomeEvidence("contract.py::test_one::-", TestOutcome.PASS, "expected", _DIGEST),),
        baseline_mount_plan_digest=_DIGEST,
        baseline_execution_policy_digest=_DIGEST,
    )
    report = rejected_preparation_report(
        "case", BTSRejectReason.REJECT_HARD_GATE_FAILED, "baseline_mismatch",
        recorded_baseline=recorded, expected_baseline=expected,
    )
    assert report.recorded_outcome_vector == (("contract.py::test_one::-", "fail"),)
    assert report.expected_outcome_vector == (("contract.py::test_one::-", "pass"),)
    assert report.recorded_counts == (("failed", 1), ("passed", 0), ("skipped", 0))
    assert report.expected_counts == (("failed", 0), ("passed", 1), ("skipped", 0))


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


def test_exit_gate_writes_rejected_report_for_untyped_case_preparation_error(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
) -> None:
    _exit_sidecars(tmp_path)
    manifest_path = _FIXTURE / "corpus-runnable-v1.1.json"
    substrate = json.loads(manifest_path.read_text())["runnable"]["substrate"]
    monkeypatch.setattr(pipeline_cli, "_require_substrate", lambda: None)

    def unavailable_snapshot(*args: object, **kwargs: object) -> object:
        raise OSError("donor shelf unavailable")

    monkeypatch.setattr(pipeline_cli.bts_cli, "load_donor_snapshot", unavailable_snapshot)
    summary = exit_gate_run(
        manifest_path,
        tmp_path / "donors",
        corpus_root=tmp_path,
        out_dir=tmp_path / "out",
        nsjail_version="fixture",
        nsjail_build_identity=_DIGEST,
        config_schema_digest=_DIGEST,
        rootfs_source=tmp_path / "rootfs",
        substrate_nsjail_sha256=substrate["nsjail_sha256"],
        substrate_rootfs_digest=substrate["rootfs_digest"],
    )
    report = json.loads((tmp_path / "out" / "exit-gate-report.json").read_text())
    assert summary["status"] == "reject"
    assert len(report["donors"]) == 5
    assert all(
        "exit_preparation_error_v1:reject_hard_gate_failed:pipeline_cli_case_preparation_v1"
        in donor["detail_categories"]
        for donor in report["donors"]
    )
    assert all(
        "exit_preparation_cause_v1:OSError:donor shelf unavailable" in donor["detail_categories"]
        for donor in report["donors"]
    )


def test_exit_gate_sanitizes_hyphenated_case_ids_for_relocation_recipient_package(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
) -> None:
    """The package passed to relocate must be a dotted Python module path."""

    _exit_sidecars(tmp_path)
    manifest_path = _FIXTURE / "corpus-runnable-v1.1.json"
    substrate = json.loads(manifest_path.read_text())["runnable"]["substrate"]
    packages: list[str] = []
    monkeypatch.setattr(pipeline_cli, "_require_substrate", lambda: None)
    monkeypatch.setattr(pipeline_cli.bts_cli, "load_donor_snapshot", lambda *args, **kwargs: object())
    preliminary = SimpleNamespace(status=BTSStatus.COMPLETE, bts=object())
    monkeypatch.setattr(pipeline_cli, "_prepared", lambda *args, **kwargs: (object(), object(), preliminary))
    monkeypatch.setattr(pipeline_cli, "_exit_module_aliases", lambda *args, **kwargs: ())

    def capture_package(*args: object, **kwargs: object) -> object:
        packages.append(str(kwargs["recipient_package"]))
        raise BTSError(BTSRejectReason.REJECT_HARD_GATE_FAILED, "stop after relocation package capture")

    monkeypatch.setattr(pipeline_cli, "_relocate_prepared", capture_package)
    summary = exit_gate_run(
        manifest_path,
        tmp_path / "donors",
        corpus_root=tmp_path,
        out_dir=tmp_path / "out",
        nsjail_version="fixture",
        nsjail_build_identity=_DIGEST,
        config_schema_digest=_DIGEST,
        rootfs_source=tmp_path / "rootfs",
        substrate_nsjail_sha256=substrate["nsjail_sha256"],
        substrate_rootfs_digest=substrate["rootfs_digest"],
    )

    assert summary["status"] == "reject"
    assert packages == [
        "transplant.alpha_parser",
        "transplant.bravo_tokenizer",
        "transplant.charlie_router",
        "transplant.delta_cache",
        "transplant.echo_store",
    ]


def test_exit_gate_empty_cases_writes_typed_rejection(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    manifest_path = _FIXTURE / "corpus-runnable-v1.1.json"
    manifest = json.loads(manifest_path.read_text())
    manifest["cases"] = []
    manifest["runnable"]["per_case"] = []
    substrate = manifest["runnable"]["substrate"]
    monkeypatch.setattr(pipeline_cli, "_require_substrate", lambda: None)
    monkeypatch.setattr(pipeline_cli, "load_corpus_manifest", lambda path: manifest)
    summary = exit_gate_run(
        manifest_path,
        tmp_path / "donors",
        corpus_root=tmp_path,
        out_dir=tmp_path / "out",
        nsjail_version="fixture",
        nsjail_build_identity=_DIGEST,
        config_schema_digest=_DIGEST,
        rootfs_source=tmp_path / "rootfs",
        substrate_nsjail_sha256=substrate["nsjail_sha256"],
        substrate_rootfs_digest=substrate["rootfs_digest"],
    )
    report = json.loads((tmp_path / "out" / "exit-gate-report.json").read_text())
    assert summary["status"] == "reject"
    assert report["donors"][0]["detail_categories"] == [
        "exit_preparation_error_v1:reject_hard_gate_failed:pipeline_cli_exit_empty_cases_v1"
    ]


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


@pytest.mark.skipif(not _HAS_CRYPTOGRAPHY or not _HAS_NO_FOLLOW, reason="ratification trust-anchor reads require cryptography and O_NOFOLLOW")
def test_l5_ratification_valid_signature_allows_authority_to_proceed(tmp_path: Path) -> None:
    manifest, sidecar, keys, donors = _l5_ratification(tmp_path)

    _require_runtime_ratification(manifest, corpus_manifest_digest="sha256:" + "a" * 64, donors_dir=donors, trusted_keys_path=keys, ratification_sidecar=sidecar, default_sidecar=sidecar)


@pytest.mark.skipif(not _HAS_CRYPTOGRAPHY or not _HAS_NO_FOLLOW, reason="ratification trust-anchor reads require cryptography and O_NOFOLLOW")
def test_l5_ratification_missing_sidecar_rejects_typed(tmp_path: Path) -> None:
    manifest, sidecar, keys, donors = _l5_ratification(tmp_path)
    sidecar.unlink()

    with pytest.raises(BTSError) as caught:
        _require_runtime_ratification(manifest, corpus_manifest_digest="sha256:" + "a" * 64, donors_dir=donors, trusted_keys_path=keys, ratification_sidecar=sidecar, default_sidecar=sidecar)

    assert caught.value.evidence.detail_code == "pipeline_cli_ratification_invalid_v1"


@pytest.mark.skipif(not _HAS_CRYPTOGRAPHY or not _HAS_NO_FOLLOW, reason="ratification trust-anchor reads require cryptography and O_NOFOLLOW")
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


@pytest.mark.skipif(not _HAS_CRYPTOGRAPHY or not _HAS_NO_FOLLOW, reason="ratification trust-anchor reads require cryptography and O_NOFOLLOW")
def test_l5_ratification_self_signed_untrusted_key_rejects_typed(tmp_path: Path) -> None:
    manifest, sidecar, keys, donors = _l5_ratification(tmp_path)
    record = json.loads(sidecar.read_text(encoding="utf-8"))
    record["key_id"] = "0" * 64
    sidecar.write_text(json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8")

    with pytest.raises(BTSError) as caught:
        _require_runtime_ratification(manifest, corpus_manifest_digest="sha256:" + "a" * 64, donors_dir=donors, trusted_keys_path=keys, ratification_sidecar=sidecar, default_sidecar=sidecar)

    assert caught.value.evidence.detail_code == "pipeline_cli_ratification_invalid_v1"
