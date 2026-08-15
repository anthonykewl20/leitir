"""E4a's first complete vertical slice over reviewed Leitir fixture code.

The offline donor under ``tests/fixtures/bts_skeleton`` is Leitir-authored,
committed, and reviewed test code, not an untrusted external donor.  Its child
runner therefore deliberately runs without nsjail while still removing the
fixture donor from ``sys.path`` and reporting B6-style diagnostic import
evidence to the real E2 boundary.  This narrow test exception does not weaken
ADR-0009: external donor execution remains live-gated by both
``LEITIR_ENABLE_DONOR_EXECUTION=1`` and a pinned nsjail installation.

The fixture uses only direct functions, lexical helper calls, builtins, and
ordinary control flow.  It has no receiver dispatch, decorators, registries,
dynamic imports, or star imports and is therefore inside the ADR-0008 v1 subset.
"""

from __future__ import annotations

import hashlib
import json
import os
import platform
import shutil
import subprocess
import sys
import tempfile
from dataclasses import replace
from pathlib import Path

import pytest

import leitir.rerun as rerun_module
from leitir.bts import (
    BTS_SCHEMA_VERSION,
    AdapterCatalog,
    BTSBudget,
    BTSStatus,
    DonorSnapshot,
    ResolutionPolicy,
    StdlibIdentity,
)
from leitir.bts_errors import BTSRejectReason
from leitir.bts_pipeline import BTSPipelineRequest, BTSPipelineResult, run_bts_pipeline
from leitir.exec_sandbox import POLICY_SCHEMA, ContainmentPolicy, ExecutionResult, ReadOnlyMount
from leitir.graph.python import extract_static_edges
from leitir.probes import ProbeExecutionRequest, ProbeExecutionResult, ProbeSet, ProbeStatus
from leitir.relocate import ContractTest, FileRole, ModuleMap, Relocation, SourceFile
from leitir.rerun import (
    RERUN_POLICY_SCHEMA_VERSION,
    ContractBaselineEvidence,
    RerunExecutionPolicy,
    RerunReport,
    ValidationStatus,
)
from leitir.rerun import (
    TestOutcome as Outcome,
)
from leitir.rerun import (
    TestOutcomeEvidence as OutcomeEvidence,
)
from leitir.treehash import FULL, TREE_HASH_ALGORITHM, compute_materialized_tree_hash

REPO_ROOT = Path(__file__).resolve().parents[1]
FIXTURE = Path(__file__).parent / "fixtures" / "bts_skeleton"
COMMIT_SHA = "e4a0" * 10
DONOR_SLUG = "leitir/e4a-reviewed-fixture"
RECIPIENT_MODULE = "bts_recipient.policy"
PASS_IDS = (
    "test_contract.py::test_clamps_at_upper_bound::-",
    "test_contract.py::test_increments_inside_range::-",
)
SKIP_ID = "test_contract.py::test_platform_specific_contract::-"


def _digest(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def _git_blob_sha(value: bytes) -> str:
    return hashlib.sha1(b"blob %d\x00" % len(value) + value).hexdigest()


def _outcome(test_id: str, outcome: Outcome) -> OutcomeEvidence:
    return OutcomeEvidence(test_id, outcome, "runner_result_v1", _digest((test_id + outcome.value).encode()))


BASELINE_OUTCOMES = tuple(
    sorted((*(_outcome(test_id, Outcome.PASS) for test_id in PASS_IDS), _outcome(SKIP_ID, Outcome.SKIP)))
)


def _json_digest(value: object) -> str:
    encoded = (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n").encode()
    return _digest(encoded)


def _budget() -> BTSBudget:
    return BTSBudget(1_000_000, 1_000_000, 100_000, 20, 10_000, 10_000, 10_000, 100, 2_000_000, 10_000, 10_000, 100, 100)


def _resolution_policy() -> ResolutionPolicy:
    return ResolutionPolicy(
        BTS_SCHEMA_VERSION,
        "leitir-maintainers",
        "e4a-reviewed-fixture-v1",
        _digest(b"e4a-resolution-policy-v1"),
        StdlibIdentity("cpython", ">=3.11,<3.12", "v1", _digest(b"empty-stdlib-allowlist")),
        AdapterCatalog("empty", "v1", _digest(b"empty-adapter-catalog")),
    )


def _containment(relocation: Relocation | None = None) -> ContainmentPolicy:
    rootfs_digest = _digest(b"trusted-fixture-rootfs-placeholder")
    mounts = [ReadOnlyMount("/", "/pinned/rootfs", rootfs_digest)]
    if relocation is None:
        logical_digests = ((f"staging-v1/{name}", _digest(f"/staging-v1/{name}".encode())) for name in ("manifests", "probes", "src", "tests/rewritten"))
    else:
        files = {item.path: item for item in relocation.files}
        logical_digests = ((item.logical_path, files[item.logical_path].sha256) for item in relocation.rerun_mounts)
    for logical, digest in logical_digests:
        mounts.append(ReadOnlyMount(f"/{logical}", f"/relocated/{logical}", digest))
    ordered = tuple(sorted(mounts))
    mount_payload = {
        "readonly_mounts": [
            {"destination": item.destination, "source": item.source, "source_digest": item.source_digest}
            for item in ordered
        ],
        "rootfs_digest": rootfs_digest,
        "scratch_dir": "/scratch",
        "writable_tmpfs": "/work",
        "writable_tmpfs_bytes": 1_048_576,
        "writable_tmpfs_inodes": 128,
    }
    return ContainmentPolicy(
        POLICY_SCHEMA,
        "/usr/bin/nsjail",
        _digest(b"nsjail-not-used-for-reviewed-fixture"),
        "not-used-for-reviewed-fixture",
        _digest(b"trusted-fixture-build"),
        _digest(b"nsjail-schema"),
        platform.machine(),
        rootfs_digest,
        _json_digest(mount_payload),
        ordered,
        "/work",
        1_048_576,
        128,
        "/scratch",
        "/work",
        "ONCE",
        True,
        True,
        True,
        True,
        True,
        True,
        True,
        False,
        67_108_864,
        16,
        500,
        2,
        64,
        1,
        1,
        32,
        16,
        8,
        0,
        65_536,
        ("LANG=C.UTF-8", "PYTHONHASHSEED=0", "TZ=UTC"),
        True,
    )


def _rerun_policy(relocation: Relocation | None = None) -> RerunExecutionPolicy:
    return RerunExecutionPolicy(
        RERUN_POLICY_SCHEMA_VERSION,
        _containment(relocation),
        (sys.executable, "-S", "-s", "-P", "<trusted-fixture-runner>"),
        _digest(b"e4a-trusted-fixture-runner"),
        _digest(b"e4a-baseline-policy"),
        ("/donor/e4a-reviewed-fixture",),
    )


def _baseline() -> ContractBaselineEvidence:
    return ContractBaselineEvidence.create(
        BASELINE_OUTCOMES,
        baseline_mount_plan_digest=_digest(b"e4a-baseline-mount-plan"),
        baseline_execution_policy_digest=_digest(b"e4a-baseline-policy"),
    )


class EmptyProbePolicy:
    execution_policy_digest = _digest(b"e4a-empty-probe-policy")

    def execute_probe(self, request: ProbeExecutionRequest, relocation: Relocation) -> ProbeExecutionResult:
        raise AssertionError(f"empty applicability must not execute {request.probe_id}")


def _request(root: Path) -> BTSPipelineRequest:
    source_path = "skeleton_donor/policy.py"
    source = (root / source_path).read_bytes()
    test_source = (root / "test_contract.py").read_bytes()
    tree_hash, scope = compute_materialized_tree_hash(root)
    assert scope == FULL
    snapshot = DonorSnapshot(
        DONOR_SLUG,
        COMMIT_SHA,
        "git-commit",
        "exact",
        tree_hash,
        TREE_HASH_ALGORITHM,
        FULL,
        root.parent,
        root,
    )
    extraction = extract_static_edges(
        source,
        slug=DONOR_SLUG,
        commit_sha=COMMIT_SHA,
        path=source_path,
        blob_sha=_git_blob_sha(source),
        package_root="",
    )
    graph = extraction.to_graph()
    seed = next(item.id for item in graph.nodes if item.id.qualified_name == "skeleton_donor.policy.normalized_score")
    empty_probes = ProbeSet.pin(
        bts_digest="sha256:" + "0" * 64,
        seed=seed,
        bts_members=(seed,),
        catalog_edges=(),
        probes=(),
    )
    # The probe set is BTS-bound, so its final pin is filled after static
    # computation by the request wrapper below.
    return BTSPipelineRequest(
        snapshot,
        seed,
        graph,
        _budget(),
        _resolution_policy(),
        ModuleMap.from_pairs(("skeleton_donor.policy", RECIPIENT_MODULE)),
        (SourceFile(source_path, source),),
        (ContractTest("test_contract.py", test_source, "skeleton_donor.test_contract"),),
        _baseline(),
        _rerun_policy(),
        empty_probes,
        EmptyProbePolicy(),
    )


_RUNNER = r'''
import builtins, hashlib, importlib.util, json, pathlib, sys
startup_attestation = {"namespace_mismatch":True,"no_new_privs":True,"pid_namespace_init":True,"schema_version":"leitir-contained-startup-attestation-v1","seccomp_mode":2}
sys.stdout.buffer.write(json.dumps(startup_attestation,sort_keys=True,separators=(",",":")).encode("utf-8") + b"\n")
sys.stdout.buffer.flush()
src, test_file, donor_root = sys.argv[1:]
sys.path[:] = [src] + [item for item in sys.path if item and not pathlib.Path(item).resolve().is_relative_to(pathlib.Path(donor_root).resolve())]
donor_absent = all(not pathlib.Path(item).resolve().is_relative_to(pathlib.Path(donor_root).resolve()) for item in sys.path if item)
observed = []
original_import = builtins.__import__
def recording_import(name, globals=None, locals=None, fromlist=(), level=0):
    observed.append(name)
    return original_import(name, globals, locals, fromlist, level)
builtins.__import__ = recording_import
spec = importlib.util.spec_from_file_location("relocated_contract", test_file)
module = importlib.util.module_from_spec(spec)
collection_failed = False
try:
    spec.loader.exec_module(module)
except BaseException:
    collection_failed = True
skips = set(getattr(module, "SKIPPED_CONTRACTS", ())) if not collection_failed else set()
outcomes = []
for name in sorted(item for item in vars(module) if item.startswith("test_")) if not collection_failed else ():
    test_id = "test_contract.py::" + name + "::-"
    outcome = "skip" if name in skips else "pass"
    if name not in skips:
        try:
            getattr(module, name)()
        except BaseException:
            outcome = "fail"
    detail = "sha256:" + hashlib.sha256((test_id + outcome).encode()).hexdigest()
    outcomes.append({"canonical_test_id":test_id,"detail_category":"runner_result_v1","detail_digest":detail,"outcome":outcome})
builtins.__import__ = original_import
runtime = "sha256:" + hashlib.sha256(json.dumps(sorted(set(observed)),separators=(",",":")).encode()).hexdigest()
frame = {"containment_attestation":startup_attestation,"donor_import_observed":any(name == "skeleton_donor" or name.startswith("skeleton_donor.") for name in observed),"outcomes":outcomes,"recorder_complete":True,"runtime_observation_digest":runtime,"schema_version":"leitir-rerun-runner-frame-v1","teardown_complete":donor_absent}
sys.stdout.buffer.write(json.dumps(frame,sort_keys=True,separators=(",",":")).encode("utf-8") + b"\n")
'''


def test_runner_emits_canonical_frame_bytes_via_binary_stdout() -> None:
    assert "sys.stdout.buffer.write(" in _RUNNER
    assert "print(json.dumps" not in _RUNNER


class TrustedFixtureExecution:
    """Actual child runner reserved for the committed reviewed fixture."""

    def __init__(self, relocation: Relocation, donor_root: Path, *, remove_helper: bool = False) -> None:
        self.relocation = relocation
        self.donor_root = donor_root
        self.remove_helper = remove_helper
        self.donor_absent = False

    def run(self) -> ExecutionResult:
        with tempfile.TemporaryDirectory(prefix="leitir-e4a-run-") as temporary:
            root = Path(temporary)
            for item in self.relocation.files:
                if item.role not in {FileRole.SOURCE, FileRole.TEST_REWRITTEN}:
                    continue
                relative = item.path.removeprefix("staging-v1/")
                output = root / relative
                output.parent.mkdir(parents=True, exist_ok=True)
                content = item.content
                if self.remove_helper and item.role is FileRole.SOURCE and item.path.endswith("policy.py"):
                    content = b"from bts_recipient.required_helper import clamp\n\n" + content[content.index(b"def normalized_score") :]
                output.write_bytes(content)
            source_root = root / "src"
            test_file = root / "tests" / "rewritten" / "test_contract.py"
            environment = {"LANG": "C.UTF-8", "PYTHONHASHSEED": "0", "TZ": "UTC"}
            # Windows interpreter bootstrap requires these host-startup accommodations;
            # they are not integrity controls (issue #128).
            if sys.platform == "win32":
                for _name in ("SYSTEMROOT", "WINDIR", "TEMP", "TMP", "PATHEXT"):
                    if _name in os.environ:
                        environment[_name] = os.environ[_name]
            completed = subprocess.run(
                (sys.executable, "-S", "-s", "-P", "-c", _RUNNER, str(source_root), str(test_file), str(self.donor_root)),
                check=False,
                capture_output=True,
                env=environment,
            )
            frame = completed.stdout
            _startup_frame, _separator, result_frame = frame.partition(b"\n")
            parsed = json.loads(result_frame)
            self.donor_absent = parsed["teardown_complete"] and not parsed["donor_import_observed"]
            if completed.returncode != 0:
                return ExecutionResult(False, _digest(b"trusted-plan"), None, b"", b"", None, None, None, None)
            return ExecutionResult(
                True,
                _digest(b"trusted-plan"),
                0,
                frame,
                completed.stderr,
                _digest(frame),
                _digest(completed.stderr),
                _digest(b"trusted-result" + frame),
                None,
            )


def _run(root: Path, *, remove_helper: bool = False) -> tuple[BTSPipelineResult, TrustedFixtureExecution]:
    request = _request(root)
    static = __import__("leitir.bts", fromlist=["compute_bts"]).compute_bts(
        request.snapshot, request.seed, request.graph, request.budget, request.resolution_policy
    )
    assert static.status is BTSStatus.COMPLETE and static.bts is not None
    probe_set = ProbeSet.pin(
        bts_digest=static.bts.bts_digest,
        seed=request.seed,
        bts_members=tuple(member.node for member in static.bts.members),
        catalog_edges=(),
        probes=(),
    )
    request = replace(request, probe_set=probe_set)
    relocation = __import__("leitir.relocate", fromlist=["relocate_tests"]).relocate_tests(
        static,
        module_map=request.module_map,
        source_files=request.source_files,
        tests=request.contract_tests,
    )
    execution = TrustedFixtureExecution(relocation, root, remove_helper=remove_helper)
    request = replace(request, rerun_execution_policy=_rerun_policy(relocation))
    original_prepare = rerun_module.prepare_execution
    original_run = rerun_module.run_contained
    try:
        rerun_module.prepare_execution = lambda containment: object()  # type: ignore[assignment]
        rerun_module.run_contained = lambda plan, argv: execution.run()  # type: ignore[assignment]
        result = run_bts_pipeline(request)
    finally:
        rerun_module.prepare_execution = original_prepare
        rerun_module.run_contained = original_run
    return result, execution


@pytest.fixture
def fixture_copy(tmp_path: Path) -> Path:
    target = tmp_path / "bts_skeleton"
    shutil.copytree(FIXTURE, target)
    return target


def test_offline_walking_skeleton_exact_counts_donor_ban_and_content_identity(fixture_copy: Path) -> None:
    result, execution = _run(fixture_copy)

    assert result.bts.status is BTSStatus.COMPLETE
    assert result.bts.bts is not None
    assert [member.node.qualified_name for member in result.bts.bts.members] == [
        "skeleton_donor.policy.clamp",
        "skeleton_donor.policy.normalized_score",
    ]
    assert isinstance(result.rerun, RerunReport)
    assert result.rerun.status is ValidationStatus.COMPLETE
    assert result.rerun.counts == _baseline().counts
    assert (result.rerun.counts.passed, result.rerun.counts.failed, result.rerun.counts.skipped) == (2, 0, 1)
    assert result.rerun.selected_test_ids == tuple(item.canonical_test_id for item in BASELINE_OUTCOMES)
    assert execution.donor_absent
    assert result.probes.status is ProbeStatus.COMPLETE
    assert result.verdict.status is ValidationStatus.COMPLETE
    assert result.to_bytes() == result.to_bytes()
    assert result.verdict.validation_digest.startswith("sha256:")


def test_offline_missing_required_helper_rejects(fixture_copy: Path) -> None:
    result, execution = _run(fixture_copy, remove_helper=True)

    assert execution.donor_absent
    assert isinstance(result.rerun, RerunReport)
    assert result.rerun.status is ValidationStatus.REJECT
    assert result.rerun.reason is BTSRejectReason.REJECT_COVERAGE_MISCOUNT
    assert result.verdict.status is ValidationStatus.REJECT


def test_skeleton_rendering_is_pythonhashseed_independent() -> None:
    script = """
import shutil, tempfile
from pathlib import Path
from tests.test_bts_skeleton import FIXTURE, _run
with tempfile.TemporaryDirectory() as value:
    root=Path(value)/'fixture'; shutil.copytree(FIXTURE,root)
    print(_run(root)[0].to_bytes().hex())
"""
    outputs = []
    for seed in ("0", "1", "42"):
        environment = dict(
            os.environ,
            PYTHONHASHSEED=seed,
            PYTHONPATH=os.pathsep.join((str((REPO_ROOT / "src").resolve()), str(REPO_ROOT.resolve()))),
        )
        outputs.append(subprocess.check_output((sys.executable, "-c", script), env=environment))
    assert outputs[0] == outputs[1] == outputs[2]


@pytest.mark.skipif(os.environ.get("LEITIR_ENABLE_LIVE_E2E") != "1", reason="set LEITIR_ENABLE_LIVE_E2E=1 for pinned external donor acquisition")
def test_live_pinned_external_donor_is_rematerialized(tmp_path: Path) -> None:
    from leitir.materialize import materialize_github_repo

    commit = "4d394574f5555a8ddcc38f707e0c9f57f55d9a3b"
    target = materialize_github_repo(tmp_path, "psf/requests", "psf", "requests", commit)
    assert (target / "requests" / "utils.py").is_file()


@pytest.mark.skipif(
    os.environ.get("LEITIR_ENABLE_LIVE_E2E") != "1"
    or os.environ.get("LEITIR_ENABLE_DONOR_EXECUTION") != "1"
    or shutil.which("nsjail") is None,
    reason="real external donor execution requires live opt-in, donor opt-in, and nsjail",
)
def test_live_untrusted_pipeline_requires_release_pinned_s2_artifacts() -> None:
    pytest.skip("release-pinned nsjail rootfs/runner policy is supplied by the dedicated containment job")
