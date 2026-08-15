"""Fail-closed adapters for the BTS pipeline commands.

Intended CLI help (the public argparse integration belongs in :mod:`leitir.cli`)::

    leitir bts-run ROOT OWNER REPO COMMIT --seed-module MODULE --seed-name NAME
        --contract-tests SPEC.json --out DIRECTORY --recipient-package PACKAGE
        --nsjail-sha256 DIGEST --nsjail-version VERSION --nsjail-build-identity DIGEST
        --config-schema-digest DIGEST --rootfs-source DIRECTORY --rootfs-digest DIGEST
        [--emit-packets PACKET-INPUTS.json]
    leitir bts-packets ...                 # folded into bts-run --emit-packets
    leitir exit-gate-run CORPUS.json DONORS_DIRECTORY ...
    leitir occupied-validate SPEC.json ...

``record_baseline`` records donor-present contract-test behaviour only through
the same verified ``exec_sandbox.prepare_execution/run_contained`` authority as
the donor-absent rerun.  The baseline policy differs solely by mounting the
verified donor root read-only at ``/donor``; there is no host fallback.
"""

from __future__ import annotations

import ast
import hashlib
import json
import os
import platform
import re
import shutil
import stat
import tempfile
from collections.abc import Callable, Mapping
from contextlib import ExitStack
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import NoReturn, cast

from leitir import bts_cli
from leitir.bts import (
    BTS,
    BTSBudget,
    BTSResult,
    BTSStatus,
    DonorSnapshot,
    ResolutionPolicy,
    compute_bts,
    load_bts_artifact,
)
from leitir.bts_bench import AdaptationProbeObs, BTSEvalTask, CandidateIdentity
from leitir.bts_errors import BTSError, BTSRejectReason, TransplantError
from leitir.bts_exit_gate import (
    ExitCorpus,
    ExitCorpusCase,
    _run_case,
    rejected_preparation_report,
    report_prepared_cases,
    run_exit_gate,
)
from leitir.bts_pipeline import BTSPipelineRequest, BTSPipelineResult, run_bts_pipeline
from leitir.candidates import CandidateProposal, EvidencePointer, RetrievalProvenance
from leitir.capability import (
    PINNED_BEHAVIOR_CONTRACT_REGISTRY,
    BehaviorRequirement,
    CapabilitySpec,
    LicensePolicy,
)
from leitir.comparison import compare_and_select
from leitir.composition import (
    COMPOSITION_MATRIX_SCHEMA,
    CandidateDependencyEvidence,
    ClosureCompleteness,
    CompatibilityStatus,
    CompositionCandidateRef,
    ConflictKind,
    ConflictMatrix,
    ConflictRecord,
)
from leitir.exec_sandbox import (
    POLICY_SCHEMA,
    ContainmentPolicy,
    ReadOnlyMount,
    donor_execution_enabled,
    prepare_execution,
    run_contained,
)
from leitir.exit_corpus import content_digest, load_corpus_manifest
from leitir.graph.model import NodeId
from leitir.lockfiles import DependencyManifestPolicy
from leitir.occupied import (
    OccupiedAttachmentPolicy,
    OccupiedRerunEvidence,
    OccupiedRole,
    RecipientBaselineEvidence,
    derive_recipient_binding_inventory,
    validate_collisions,
    validate_conflict_matrix,
    validate_recipient_parity,
)
from leitir.probes import ProbeExecutionRequest, ProbeExecutionResult, ProbeSet
from leitir.project_profile import RecipientInputManifest, RecipientManifestEntry, profile_project
from leitir.relocate import ContractTest, ModuleMap, Relocation, SourceFile, relocate_tests
from leitir.rerun import (
    RERUN_POLICY_SCHEMA_VERSION,
    ContractBaselineEvidence,
    OutcomeCounts,
    RerunExecutionPolicy,
    TestOutcome,
    TestOutcomeEvidence,
    canonical_test_id,
)
from leitir.safeio import confined_path, read_regular_file
from leitir.suitability import build_survivor_set
from leitir.transplant import PacketInputs, build_reference_packet, publish_packet

PIPELINE_CLI_SCHEMA_VERSION = "leitir-pipeline-cli-v1"
CONTRACT_TESTS_SCHEMA_VERSION = "leitir-pipeline-contract-tests-v1"
_MAX_SPEC_BYTES = 1 << 20
_SHA256_DIGEST_RE = re.compile(r"sha256:[0-9a-f]{64}\Z")


def _reject(message: str, detail_code: str, *, cause: BaseException | None = None) -> NoReturn:
    raise TransplantError(BTSRejectReason.REJECT_EXECUTION_THREAT, message, detail_code=detail_code, cause=cause)


def _digest(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def _canonical(value: object) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False) + "\n").encode("utf-8", "strict")


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def _read_regular_json_bytes(path: Path) -> bytes:
    try:
        # Published task/exit sidecars are canonical and digest-validated after
        # reading, so their inputs retain a digest anchor without O_NOFOLLOW.
        return read_regular_file(path, maximum_bytes=_MAX_SPEC_BYTES, no_follow=False)
    except (OSError, UnicodeError, ValueError, json.JSONDecodeError) as exc:
        detail = exc.strerror if isinstance(exc, OSError) and exc.strerror else str(exc)
        raise BTSError(
            BTSRejectReason.REJECT_HARD_GATE_FAILED,
            f"pipeline CLI JSON input is malformed: {path}: {detail}",
            detail_code="pipeline_cli_schema_v1",
            cause=exc,
        ) from exc


def _parse_json_bytes(data: bytes) -> object:
    try:
        return json.loads(data.decode("utf-8", "strict"), object_pairs_hook=_unique_object)
    except (UnicodeError, ValueError, json.JSONDecodeError) as exc:
        raise BTSError(BTSRejectReason.REJECT_HARD_GATE_FAILED, "pipeline CLI JSON input is malformed", detail_code="pipeline_cli_schema_v1", cause=exc) from exc


def _read_json(path: Path) -> object:
    return _parse_json_bytes(_read_regular_json_bytes(path))


@dataclass(frozen=True, slots=True, order=True)
class ContractTestSpec:
    """One closed-schema donor-present test source declaration."""

    path: str
    module: str
    content: bytes | None = None

    def __post_init__(self) -> None:
        candidate = PurePosixPath(self.path)
        if (not self.path.endswith(".py") or candidate.is_absolute() or ".." in candidate.parts or candidate.as_posix() != self.path):
            raise ValueError("contract test path must be a normalized relative Python path")
        if not self.module or any(not part.isidentifier() for part in self.module.split(".")):
            raise ValueError("contract test module must be a Python module name")
        if self.content is not None and not isinstance(self.content, bytes):
            raise ValueError("contract test content must be bytes or absent")


def load_contract_tests(path: Path) -> list[ContractTestSpec]:
    """Load canonical contract-test JSON: path/module and optional inline content."""

    raw = _read_json(path)
    try:
        if not isinstance(raw, dict) or set(raw) != {"schema_version", "tests"} or raw["schema_version"] != CONTRACT_TESTS_SCHEMA_VERSION:
            raise ValueError("invalid contract-test envelope")
        tests = raw["tests"]
        if not isinstance(tests, list):
            raise ValueError("tests is not a list")
        result: list[ContractTestSpec] = []
        for item in tests:
            if not isinstance(item, dict) or set(item) not in ({"path", "module"}, {"path", "module", "content"}):
                raise ValueError("invalid contract-test item")
            content = item.get("content")
            if content is not None and not isinstance(content, str):
                raise ValueError("content must be UTF-8 text")
            result.append(ContractTestSpec(item["path"], item["module"], None if content is None else content.encode("utf-8", "strict")))
        if result != sorted(result) or len(set((item.path, item.module) for item in result)) != len(result):
            raise ValueError("tests must be sorted and unique")
        return result
    except (TypeError, UnicodeError, ValueError) as exc:
        raise BTSError(BTSRejectReason.REJECT_HARD_GATE_FAILED, "contract-test spec violates its closed schema", detail_code="pipeline_cli_contract_spec_v1", cause=exc) from exc


def _test_functions(source: bytes) -> tuple[str, ...]:
    try:
        tree = ast.parse(source.decode("utf-8", "strict"), type_comments=True, feature_version=(3, 11))
    except (UnicodeError, SyntaxError, ValueError) as exc:
        raise BTSError(BTSRejectReason.REJECT_HARD_GATE_FAILED, "contract test cannot be parsed", detail_code="pipeline_cli_contract_spec_v1", cause=exc) from exc
    return tuple(sorted(node.name for node in tree.body if isinstance(node, ast.FunctionDef) and node.name.startswith("test_")))


_BASELINE_CHILD = r'''import importlib.util,json,sys,traceback,unittest
p,f=sys.argv[1:]
spec=importlib.util.spec_from_file_location("_leitir_baseline_test",p)
module=importlib.util.module_from_spec(spec)
try:
 spec.loader.exec_module(module)
 getattr(module,f)()
 result="pass"
except unittest.SkipTest:
 result="skip"
except BaseException:
 result="fail"
print(json.dumps({"outcome":result},sort_keys=True,separators=(",",":")))
'''


def _baseline_containment_policy(substrate: BTSSubstratePins, donor_root: Path, test_root: Path, import_roots: tuple[str, ...]) -> ContainmentPolicy:
    """Build the donor-present variant: rootfs plus read-only donor/test mounts."""

    from leitir.exec_sandbox import _verified_directory_tree_digest

    roots = tuple(sorted(import_roots))
    donor_digest = _verified_directory_tree_digest(donor_root)
    test_digest = donor_digest if test_root == donor_root else _verified_directory_tree_digest(test_root)
    # Contract tests are always role-separated from donor bytes, even where a
    # legacy caller stored them below the donor root.  This makes the baseline
    # policy's test mount explicit and lets callers use the staged original
    # tests from the same two-phase relocation assembly as S2.
    mounts = [ReadOnlyMount("/contract", str(test_root), test_digest), ReadOnlyMount("/donor", str(donor_root), donor_digest)]
    return build_containment_policy(
        nsjail_sha256=substrate.nsjail_sha256,
        nsjail_version=substrate.nsjail_version,
        nsjail_build_identity=substrate.nsjail_build_identity,
        config_schema_digest=substrate.config_schema_digest,
        rootfs_source=substrate.rootfs_source,
        rootfs_digest=substrate.rootfs_digest,
        readonly_mounts=tuple(mounts),
        environment=("LANG=C.UTF-8", "LD_LIBRARY_PATH=/usr/lib/leitir-native", "PYTHONHASHSEED=0", "TZ=UTC", "PYTHONPATH=" + ":".join("/donor" if root == "." else "/donor/" + root for root in roots)),
    )


_BASELINE_RUNNER_ARGV = ("/usr/bin/python3", "-S", "-s", "-P", "-c", _BASELINE_CHILD)


def _baseline_execution_digest(policy: ContainmentPolicy) -> str:
    """Bind baseline evidence to the policy and runner that actually ran it."""

    return _digest(_canonical({"role": "donor-present-contained-v1", "runner_argv": list(_BASELINE_RUNNER_ARGV), "mount_plan_digest": policy.mount_plan_digest}))


def record_baseline(donor_root: Path, contract_tests: list[ContractTestSpec], *, substrate: BTSSubstratePins, import_roots: tuple[str, ...] = (".",), contract_root: Path | None = None) -> ContractBaselineEvidence:
    """Record donor-present outcomes through the verified contained executor."""

    if not isinstance(donor_root, Path) or not isinstance(contract_tests, list):
        raise TypeError("donor_root and contract_tests have invalid types")
    test_root = donor_root if contract_root is None else contract_root
    # Validate caller-provided inline bytes before attempting the optional S2
    # backend so a provenance mismatch is never obscured by local substrate
    # availability.
    for test in sorted(contract_tests):
        try:
            source = read_regular_file(test_root / test.path, maximum_bytes=_MAX_SPEC_BYTES, no_follow=False)
        except (OSError, ValueError) as exc:
            raise BTSError(BTSRejectReason.REJECT_HARD_GATE_FAILED, "contract test cannot be read", detail_code="pipeline_cli_contract_read_v1", cause=exc) from exc
        if test.content is not None and source != test.content:
            raise BTSError(BTSRejectReason.REJECT_PROVENANCE_MISMATCH, "inline contract bytes differ from donor bytes", detail_code="pipeline_cli_contract_content_mismatch_v1")
    policy = _baseline_containment_policy(substrate, donor_root, test_root, import_roots)
    outcomes: list[TestOutcomeEvidence] = []
    for test in sorted(contract_tests):
        source_path = test_root / test.path
        source = read_regular_file(source_path, maximum_bytes=_MAX_SPEC_BYTES, no_follow=False)
        for name in _test_functions(source):
            identifier = canonical_test_id(test.path, name)
            outcome, category = _run_donor_present_test(policy, "/contract/" + test.path, name)
            outcomes.append(TestOutcomeEvidence(identifier, outcome, category, _digest(_canonical({"id": identifier, "outcome": outcome.value}))))
    ordered = tuple(sorted(outcomes))
    return ContractBaselineEvidence.create(ordered, baseline_mount_plan_digest=policy.mount_plan_digest, baseline_execution_policy_digest=_baseline_execution_digest(policy))


def _run_donor_present_test(policy: ContainmentPolicy, source_path: str, name: str) -> tuple[TestOutcome, str]:
    """Run one bare donor-present function only through the containment seam."""

    try:
        result = run_contained(prepare_execution(policy), (*_BASELINE_RUNNER_ARGV, source_path, name))
        payload = json.loads(result.stdout.decode("utf-8", "strict")) if result.completed and result.exit_code == 0 else {"outcome": "fail"}
        value = payload.get("outcome") if isinstance(payload, dict) else "fail"
        outcome = {"pass": TestOutcome.PASS, "fail": TestOutcome.FAIL, "skip": TestOutcome.SKIP}.get(value if isinstance(value, str) else "fail", TestOutcome.FAIL)
        return outcome, f"pipeline_cli_baseline_{outcome.value}_v1"
    except (UnicodeError, ValueError, json.JSONDecodeError):
        return TestOutcome.FAIL, "pipeline_cli_baseline_runner_failure_v1"


def _record_runnable_baseline(donor_root: Path, contract_tests: tuple[ContractTest, ...], *, substrate: BTSSubstratePins, import_roots: tuple[str, ...], contract_root: Path) -> ContractBaselineEvidence:
    """Record a donor-present baseline for corpus-owned contract-test bytes.

    The committed corpus deliberately keeps its contract tests outside donor
    shelves so a materialized tree hash cannot be modified to inject them.
    This uses the same donor-present containment model as :func:`record_baseline`.
    """

    specs = [ContractTestSpec(item.path, item.module, item.content) for item in contract_tests]
    return record_baseline(donor_root, specs, substrate=substrate, import_roots=import_roots, contract_root=contract_root)


def _require_substrate() -> None:
    """Fail before snapshot/test/donor bytes can reach an execution process."""

    if not donor_execution_enabled() or not Path("/usr/bin/nsjail").is_file():
        _reject("the required nsjail substrate and exact opt-in are unavailable", "pipeline_cli_substrate_unavailable_v1")


def build_containment_policy(*, nsjail_sha256: str, nsjail_version: str, nsjail_build_identity: str, config_schema_digest: str, rootfs_source: Path, rootfs_digest: str, readonly_mounts: tuple[ReadOnlyMount, ...] = (), environment: tuple[str, ...] = ("LANG=C.UTF-8", "LD_LIBRARY_PATH=/usr/lib/leitir-native", "PYTHONHASHSEED=0", "TZ=UTC")) -> ContainmentPolicy:
    """Build the fixed S2 policy template from caller-supplied pinned inputs."""

    _require_substrate()
    mounts = tuple(sorted((ReadOnlyMount("/", str(rootfs_source), rootfs_digest), *readonly_mounts)))
    payload = {"readonly_mounts": [{"destination": item.destination, "source": item.source, "source_digest": item.source_digest} for item in mounts], "rootfs_digest": rootfs_digest, "writable_tmpfs": "/work", "writable_tmpfs_bytes": 1_048_576, "writable_tmpfs_inodes": 128}
    return ContainmentPolicy(POLICY_SCHEMA, "/usr/bin/nsjail", nsjail_sha256, nsjail_version, nsjail_build_identity, config_schema_digest, platform.machine(), rootfs_digest, _digest(_canonical(payload)), mounts, "/work", 1_048_576, 128, "/work", "ONCE", False, True, True, True, True, True, True, True, 67_108_864, 16, 500, 2, 64, 1, 1, 32, 16, 8, 0, 65_536, tuple(sorted(environment)), True)


def _stage_relocation(relocation: Relocation, directory: Path) -> Path:
    """Write E1 bytes once, then return the immutable source for exact S2 binds."""

    staged = directory / "recipient"
    relocation.publish(staged)
    return staged


_STAGING_LOCK_NAME = ".lock"
_STAGING_COMPLETE_NAME = "COMPLETE"


def _remove_staging(path: Path, *, ignore_errors: bool = False) -> None:
    """Retire a non-shared relocation tree whose files are intentionally 0444."""

    def make_writable(function: object, failed_path: str, _exception: object) -> None:
        os.chmod(Path(failed_path).parent, 0o700)
        os.chmod(failed_path, 0o700)
        cast(Callable[[str], object], function)(failed_path)

    shutil.rmtree(path, onerror=make_writable, ignore_errors=ignore_errors)


def _deterministic_stage_directory(corpus_root: Path, identity: object) -> Path:
    """Return the content-addressed E1 staging location below the stable corpus root.

    The mount plan binds actual source paths.  Callers must consequently keep
    ``corpus_root`` at a CI-stable absolute location when comparing assembly
    digests across runs; random temporary staging would otherwise leak into the
    authority bytes.
    """

    root = corpus_root.resolve(strict=True)
    base = root / ".leitir-bts-staging"
    if base.is_symlink():
        raise BTSError(BTSRejectReason.REJECT_EXECUTION_THREAT, "BTS staging base must not be a symlink", detail_code="pipeline_cli_staging_path_v1")
    base.mkdir(mode=0o700, exist_ok=True)
    digest = hashlib.sha256(_canonical({"schema_version": "leitir-deterministic-staging-v1", "identity": identity})).hexdigest()
    stage = base / digest
    if stage.is_symlink():
        raise BTSError(BTSRejectReason.REJECT_EXECUTION_THREAT, "BTS staging path must not be a symlink", detail_code="pipeline_cli_staging_path_v1")
    stage.mkdir(mode=0o700, exist_ok=True)
    if not stage.is_dir() or stage.is_symlink():
        raise BTSError(BTSRejectReason.REJECT_EXECUTION_THREAT, "BTS staging path is not a directory", detail_code="pipeline_cli_staging_path_v1")
    return stage


def _stage_marker(relocation: Relocation) -> bytes:
    """Return the exact completion marker binding a shared stage to its bytes."""

    return (relocation.relocation_digest + "\n").encode("ascii")


def _complete_stage_matches(stage: Path, relocation: Relocation) -> bool:
    """Verify that a reusable stage has precisely the expected E1 projection."""

    try:
        marker = stage / _STAGING_COMPLETE_NAME
        if (
            marker.is_symlink()
            or not stat.S_ISREG(marker.stat(follow_symlinks=False).st_mode)
            or marker.read_bytes() != _stage_marker(relocation)
        ):
            return False
        expected = {f"recipient/{item.path}": item for item in relocation.files}
        observed: set[str] = set()
        for directory, directories, files in os.walk(stage, topdown=True, followlinks=False):
            current = Path(directory)
            relative_directory = current.relative_to(stage).as_posix()
            for name in sorted(directories):
                child = current / name
                if child.is_symlink():
                    return False
                relative = (Path(relative_directory) / name).as_posix()
                if relative != "recipient" and not any(path.startswith(relative + "/") for path in expected):
                    return False
            for name in sorted(files):
                child = current / name
                relative = (Path(relative_directory) / name).as_posix()
                if relative in {_STAGING_LOCK_NAME, _STAGING_COMPLETE_NAME} and relative_directory == ".":
                    continue
                item = expected.get(relative)
                if item is None or child.is_symlink() or not child.is_file():
                    return False
                if stat.S_IMODE(child.stat().st_mode) != item.mode or child.read_bytes() != item.content:
                    return False
                observed.add(relative)
        return observed == set(expected)
    except (OSError, ValueError):
        return False


def _clear_incomplete_stage(stage: Path) -> None:
    """Clear only an unlocked, incomplete stage while retaining its lock inode."""

    for entry in sorted(stage.iterdir(), key=lambda item: item.name):
        if entry.name == _STAGING_LOCK_NAME:
            continue
        if entry.is_symlink():
            entry.unlink()
        elif entry.is_dir():
            _remove_staging(entry)
        else:
            entry.unlink()


def _prepare_shared_stage(corpus_root: Path, identity: object, relocation: Relocation) -> tuple[Path, Path]:
    """Build or verify-and-reuse one complete content-addressed E1 stage.

    The flock is held only while publishing the immutable stage.  Completed
    stages are never removed by consumers, so a second assembly may safely
    reuse one while an earlier assembly's contained run still references it.
    """

    if platform.system() != "Linux":
        _reject("BTS staging is supported only on Linux", "unsupported_host")
    try:
        import fcntl
    except ImportError as exc:
        _reject("BTS staging requires the Linux fcntl interface", "unsupported_host", cause=exc)

    stage = _deterministic_stage_directory(corpus_root, identity)
    lock_path = stage / _STAGING_LOCK_NAME
    flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(lock_path, flags, 0o600)
    try:
        with os.fdopen(descriptor, "r+b", closefd=False):
            fcntl.flock(descriptor, fcntl.LOCK_EX)
            try:
                if not _complete_stage_matches(stage, relocation):
                    _clear_incomplete_stage(stage)
                    _stage_relocation(relocation, stage)
                    _write_atomic(stage / _STAGING_COMPLETE_NAME, _stage_marker(relocation))
                    os.chmod(stage / _STAGING_COMPLETE_NAME, 0o444)
                    if not _complete_stage_matches(stage, relocation):
                        raise BTSError(BTSRejectReason.REJECT_EXECUTION_THREAT, "BTS staging completion verification failed", detail_code="pipeline_cli_staging_integrity_v1")
                return stage, stage / "recipient"
            finally:
                fcntl.flock(descriptor, fcntl.LOCK_UN)
    finally:
        os.close(descriptor)


def _rerun_policy_for_relocation(
    relocation: Relocation,
    staged_root: Path,
    *,
    substrate: BTSSubstratePins,
    baseline: ContractBaselineEvidence,
) -> RerunExecutionPolicy:
    """Construct the S2 policy from E1's exact, file-granular authorization.

    ``run_bts_pipeline`` re-derives E1 to defend its normal public API.  Its
    deterministic relocation digest is checked against this staged result, so
    using this precomputed output to assemble mounts cannot widen authority.
    """

    files = {item.path: item for item in relocation.files}
    mounts = tuple(
        ReadOnlyMount(
            "/" + authorization.logical_path,
            str(staged_root.joinpath(*authorization.logical_path.split("/"))),
            files[authorization.logical_path].sha256,
        )
        for authorization in relocation.rerun_mounts
    )
    policy = build_containment_policy(
        nsjail_sha256=substrate.nsjail_sha256,
        nsjail_version=substrate.nsjail_version,
        nsjail_build_identity=substrate.nsjail_build_identity,
        config_schema_digest=substrate.config_schema_digest,
        rootfs_source=substrate.rootfs_source,
        rootfs_digest=substrate.rootfs_digest,
        readonly_mounts=mounts,
    )
    return RerunExecutionPolicy(
        RERUN_POLICY_SCHEMA_VERSION,
        policy,
        ("/usr/bin/python3", "-S", "-s", "-P", "/harness/runner.py"),
        _digest(b"pipeline-cli-runner-v1"),
        baseline.baseline_execution_policy_digest,
        ("/donor",),
    )


@dataclass(slots=True)
class _EmptyProbePolicy:
    execution_policy_digest: str

    def execute_probe(self, request: ProbeExecutionRequest, relocation: Relocation) -> ProbeExecutionResult:
        del request, relocation
        raise RuntimeError("an empty probe policy cannot execute a probe")


@dataclass(frozen=True, slots=True)
class BTSSubstratePins:
    """Measured containment identity supplied by a BTS task-run invoker."""

    nsjail_sha256: str
    nsjail_version: str
    nsjail_build_identity: str
    config_schema_digest: str
    rootfs_source: Path
    rootfs_digest: str


@dataclass(frozen=True, slots=True)
class BTSTaskRequestAssembly:
    """A non-executing task projection consumed by ``tools/run_bts_tasks.py``."""

    request: BTSPipelineRequest
    candidate_ranking: tuple[CandidateIdentity, ...]
    classified_license: str | None
    relocated_examples: tuple[str, ...] = ()
    adaptation_probes: tuple[AdaptationProbeObs, ...] = ()
    staging: Path | None = None
    ranking_unranked: bool = False

    def close(self) -> None:
        """Release this assembly's reference to its shared immutable stage."""

        return

    def to_bytes(self) -> bytes:
        """Return a host-path-independent canonical identity for this assembly."""

        request = self.request
        containment = request.rerun_execution_policy.containment
        return _canonical({
            "baseline": json.loads(request.baseline.to_bytes()),
            "candidate_ranking": [item.to_dict() for item in self.candidate_ranking],
            "classified_license": self.classified_license,
            "contract_tests": [
                {"content_digest": _digest(item.content), "module": item.module, "path": item.path}
                for item in request.contract_tests
            ],
            "module_map": [
                {"donor": item.donor, "recipient": item.recipient}
                for item in request.module_map.entries
            ],
            "rerun_policy": {
                "baseline_execution_policy_digest": request.rerun_execution_policy.baseline_execution_policy_digest,
                "config_schema_digest": containment.config_schema_digest,
                "mount_plan_digest": containment.mount_plan_digest,
                "nsjail_build_identity": containment.nsjail_build_identity,
                "nsjail_sha256": containment.nsjail_sha256,
                "nsjail_version": containment.nsjail_version,
                "rootfs_digest": containment.rootfs_digest,
                "runner_closure_digest": request.rerun_execution_policy.runner_closure_digest,
            },
            "seed": {
                "kind": request.seed.kind.value,
                "location_key": request.seed.location_key,
                "module": request.seed.module,
                "origin": request.seed.origin.value,
                "qualified_name": request.seed.qualified_name,
            },
            "snapshot": {
                "commit_sha": request.snapshot.commit_sha,
                "materialized_tree_hash": request.snapshot.materialized_tree_hash,
                "slug": request.snapshot.slug,
            },
            "source_files": [
                {"content_digest": _digest(item.content), "path": item.path}
                for item in request.source_files
            ],
        })


def _prepared(snapshot: DonorSnapshot, seed: bts_cli.SeedSelector, policy_path: Path | None) -> tuple[ResolutionPolicy, NodeId, BTSResult]:
    graph = bts_cli.python_graph_provider(snapshot)
    if not callable(graph):
        raise TypeError("Python graph provider must be callable")
    rendered = graph(snapshot.source_root)
    selected = bts_cli.resolve_seed(rendered, seed)
    resolution = bts_cli.load_resolution_policy(policy_path, rendered) if policy_path is not None else bts_cli._default_resolution_policy()
    bts = compute_bts(snapshot, selected, graph, BTSBudget(1_000_000, 1_000_000, 100_000, 20, 10_000, 10_000, 10_000, 100, 2_000_000, 10_000, 10_000, 100, 100), resolution)
    return resolution, selected, bts


def _complete_bts(preliminary: BTSResult) -> BTS:
    if preliminary.status is not BTSStatus.COMPLETE or preliminary.bts is None:
        raise BTSError(BTSRejectReason.REJECT_HARD_GATE_FAILED, "pipeline requires a complete static BTS", detail_code="pipeline_cli_non_complete_bts_v1")
    return preliminary.bts


def _relocate_prepared(
    snapshot: DonorSnapshot,
    preliminary: BTSResult,
    *,
    recipient_package: str,
    contract_tests: tuple[ContractTest, ...],
) -> Relocation:
    """Compute E1 before S2 policy assembly, without executing donor bytes."""

    bts = _complete_bts(preliminary)
    modules = tuple(sorted({member.node.module for member in bts.members}))
    module_map = ModuleMap.from_pairs(*((module, f"{recipient_package}.{module}") for module in modules))
    source_files = tuple(
        SourceFile(item.path, read_regular_file(snapshot.source_root / item.path, maximum_bytes=_MAX_SPEC_BYTES, no_follow=False))
        for item in bts.required_files
    )
    external_modules = tuple(sorted({item.node.module for item in bts.members if item.disposition.value == "external"}))
    return relocate_tests(
        preliminary,
        module_map=module_map,
        source_files=source_files,
        tests=contract_tests,
        declared_external_modules=external_modules,
    )


def _assemble_pipeline_request(snapshot: DonorSnapshot, selected: NodeId, resolution: ResolutionPolicy, preliminary: BTSResult, *, recipient_package: str, contract_tests: tuple[ContractTest, ...], baseline: ContractBaselineEvidence, rerun_policy: RerunExecutionPolicy, precomputed_relocation: Relocation | None) -> BTSPipelineRequest:
    """Build the shared non-executing request portion for CLI and bench callers."""

    bts = _complete_bts(preliminary)
    modules = tuple(sorted({member.node.module for member in bts.members}))
    module_map = ModuleMap.from_pairs(*((module, f"{recipient_package}.{module}") for module in modules))
    source_files = tuple(SourceFile(item.path, read_regular_file(snapshot.source_root / item.path, maximum_bytes=_MAX_SPEC_BYTES, no_follow=False)) for item in bts.required_files)
    probe_set = ProbeSet.pin(bts_digest=bts.bts_digest, seed=selected, bts_members=tuple(member.node for member in bts.members), catalog_edges=(), probes=())
    external_modules = tuple(sorted({item.node.module for item in bts.members if item.disposition.value == "external"}))
    return BTSPipelineRequest(snapshot, selected, bts_cli.python_graph_provider(snapshot), BTSBudget(1_000_000, 1_000_000, 100_000, 20, 10_000, 10_000, 10_000, 100, 2_000_000, 10_000, 10_000, 100, 100), resolution, module_map, source_files, contract_tests, baseline, rerun_policy, probe_set, _EmptyProbePolicy(_digest(b"pipeline-cli-empty-probes-v1")), external_modules, precomputed_relocation=precomputed_relocation)


def _license_from_materialized_donor(root: Path) -> str | None:
    """Classify the pinned donor's own license bytes, never benchmark gold."""

    for name in ("LICENSE", "LICENSE.txt", "LICENSE.md", "COPYING"):
        candidate = root / name
        try:
            text = read_regular_file(candidate, maximum_bytes=256 * 1024, no_follow=False).decode("utf-8", "strict")
        except (OSError, UnicodeError, ValueError):
            continue
        upper = text.upper()
        if "MIT LICENSE" in upper or "PERMISSION IS HEREBY GRANTED, FREE OF CHARGE" in upper:
            return "MIT"
        if "APACHE LICENSE" in upper and "VERSION 2.0" in upper:
            return "Apache-2.0"
        if "REDISTRIBUTION AND USE IN SOURCE AND BINARY FORMS" in upper and "NEITHER THE NAME" in upper:
            return "BSD-3-Clause"
        if "GNU LESSER GENERAL PUBLIC LICENSE" in upper:
            return "LGPL-3.0-or-later"
    return None


def _task_profile():
    """Return the empty, manifest-bound recipient used solely for BTS ranking."""

    return profile_project(RecipientInputManifest.create("bts-empty-recipient-v1", ()), DependencyManifestPolicy(()))


def execution_contract_tests(
    task: BTSEvalTask, identity: CandidateIdentity, contract_tests: tuple[ContractTest, ...]
) -> tuple[ContractTest, ...]:
    """Return the manifest-authorized contract subset for one task execution.

    The composition task is intentionally split by each contract test's direct
    import of the selected donor module. This parses only committed sidecar
    bytes, rejects ambiguity, and gives each one-donor validator no authority
    over another donor's tests.
    """

    if task.task_id != "three-repo-combine":
        return contract_tests
    module, separator, _name = identity.symbol.rpartition(".")
    if not separator:
        raise BTSError(BTSRejectReason.REJECT_HARD_GATE_FAILED, "composition identity has no module", detail_code="pipeline_cli_task_contract_subset_v1")
    selected: list[ContractTest] = []
    for test in contract_tests:
        try:
            tree = ast.parse(test.content.decode("utf-8", "strict"), filename=test.path)
        except (SyntaxError, UnicodeError) as exc:
            raise BTSError(BTSRejectReason.REJECT_HARD_GATE_FAILED, "composition contract test is malformed", detail_code="pipeline_cli_task_contract_subset_v1", cause=exc) from exc
        imports = {
            alias.name for node in ast.walk(tree) if isinstance(node, ast.Import) for alias in node.names
        } | {
            node.module for node in ast.walk(tree) if isinstance(node, ast.ImportFrom) and node.level == 0 and node.module is not None
        }
        if module in imports:
            selected.append(test)
    if not selected:
        raise BTSError(BTSRejectReason.REJECT_HARD_GATE_FAILED, "composition contract subset is empty", detail_code="pipeline_cli_task_contract_subset_v1")
    return tuple(selected)


def _task_spec(required_behaviors: tuple[str, ...]) -> CapabilitySpec:
    """Build a minimal deterministic spec from ``id@version`` task identifiers."""

    requirements = tuple(BehaviorRequirement(item[:item.rfind("@")], item[item.rfind("@") + 1:]) for item in required_behaviors)
    return CapabilitySpec(
        requirements, (), "python", "python>=3.11", (), (),
        LicensePolicy.create(policy_id="bts-task-permissive", policy_version="v1", allowed_spdx_expressions=("Apache-2.0", "BSD-3-Clause", "MIT")),
        (), ("any",), "bts-task-budget", "v1", _digest(b"bts-task-budget-v1"), PINNED_BEHAVIOR_CONTRACT_REGISTRY,
    )


def _evidence(kind: str, data: bytes, *, collector_id: str = "leitir.bts_task_observation", collector_version: str = "v1") -> EvidencePointer:
    return EvidencePointer(kind, collector_id, collector_version, _digest(data))


def _materialized_candidate(identity: CandidateIdentity, root: Path, spec: CapabilitySpec) -> tuple[CandidateProposal, str | None]:
    """Project a pinned candidate into C3 inputs using only materialized bytes."""

    owner, separator, repo = identity.slug.partition("/")
    if not owner or separator != "/" or not repo:
        raise BTSError(BTSRejectReason.REJECT_HARD_GATE_FAILED, "task candidate slug is malformed", detail_code="pipeline_cli_task_candidate_evidence_v1")
    # C3 discovery/ranking is evidence over the candidate search space, not a
    # transplant.  It deliberately has structural materialization authority
    # only; exact snapshot parity is checked immediately before execution.
    source_root = bts_cli.load_donor_materialization(root, owner, repo, identity.commit_sha)
    try:
        source = read_regular_file(source_root / identity.path, maximum_bytes=_MAX_SPEC_BYTES, no_follow=False)
    except (OSError, ValueError) as exc:
        raise BTSError(BTSRejectReason.REJECT_PROVENANCE_MISMATCH, "task candidate source cannot be read", detail_code="pipeline_cli_task_candidate_evidence_v1", cause=exc) from exc
    if hashlib.sha1(b"blob %d\0" % len(source) + source).hexdigest() != identity.blob_sha:
        raise BTSError(BTSRejectReason.REJECT_PROVENANCE_MISMATCH, "task candidate source does not match its pinned blob", detail_code="pipeline_cli_task_candidate_evidence_v1")
    license_value = _license_from_materialized_donor(source_root)
    if license_value is None:
        raise BTSError(BTSRejectReason.REJECT_HARD_GATE_FAILED, "task candidate license cannot be classified", detail_code="pipeline_cli_task_candidate_evidence_v1")
    # A materialized blob proves provenance and permits license classification;
    # it does not prove a behavior contract.  Behavior evidence must be
    # collected by an actual evaluator, not fabricated from blob existence.
    evidence = tuple(sorted((
        _evidence("language:python", source),
        _evidence("runtime:python>=3.11", source),
        _evidence("platform:any", source),
        _evidence(f"license:{license_value}", source),
    )))
    return CandidateProposal(
        identity.slug, identity.commit_sha, identity.path, identity.blob_sha,
        identity.start_line, 0, identity.end_line, 0, "function", identity.symbol,
        "materialized-python-source", "v1", "bts-task-candidate", "v1", evidence, (),
        (RetrievalProvenance(_digest(b"bts-task-candidate-search-v1")[7:], _digest(source), ("pinned-task-candidate",), float(0).hex()),),
    ), license_value


def _rank_materialized_candidates(task: BTSEvalTask, root: Path) -> tuple[tuple[CandidateIdentity, ...], str | None, bool]:
    """Run the C3a/C3b chain over the task's non-gold pinned candidates."""

    if task.observation is None:
        raise BTSError(BTSRejectReason.REJECT_HARD_GATE_FAILED, "BTS task has no observation plan", detail_code="pipeline_cli_task_observation_plan_v1")
    spec = _task_spec(task.observation.required_behaviors)
    profile = _task_profile()
    proposals_and_licenses = tuple(_materialized_candidate(identity, root, spec) for identity in task.observation.candidates)
    proposals = tuple(item[0] for item in proposals_and_licenses)
    licenses = {identity: value for identity, (_proposal, value) in zip(task.observation.candidates, proposals_and_licenses, strict=True)}
    report = compare_and_select(build_survivor_set(proposals, spec, profile), spec, profile)
    proposal_identities = {proposal.key(): identity for proposal, identity in zip(proposals, task.observation.candidates, strict=True)}
    selected = tuple(role.candidate_key for role in report.roles if role.candidate_key is not None)
    ranked = tuple(proposal_identities[key] for key in selected)
    # Do not append incomparable proposals as though identity order were a
    # behavioral ranking.  Publish their canonical order only as an explicitly
    # unranked set; benchmark conversion excludes rank-position metrics.
    unranked = tuple(sorted((item for item in task.observation.candidates if item not in ranked), key=lambda item: item.sort_key))
    return tuple((*ranked, *unranked)), licenses[task.observation.seed], bool(unranked)


def assemble_bts_task_request(task: BTSEvalTask, root: Path, *, contract_tests: tuple[ContractTest, ...] | None = None, baseline_sidecar: Path | None = None, resolution_policy_path: Path | None = None, substrate: BTSSubstratePins | None = None, execution_identity: CandidateIdentity | None = None) -> BTSTaskRequestAssembly:
    """Assemble one pinned bench task without executing donor or test bytes.

    Contract-test bytes and the recorded baseline are deliberately invoker-owned
    sidecars: neither is inferred from grading data or inserted into the
    materialized donor tree.  The non-gold task observation plan supplies every
    candidate and execution seed; all execution identity is supplied as measured
    substrate pins.
    """

    if not isinstance(task, BTSEvalTask) or not isinstance(root, Path):
        raise TypeError("task and root must be BTSEvalTask and Path")
    if substrate is None:
        raise BTSError(BTSRejectReason.REJECT_HARD_GATE_FAILED, "BTS task assembly requires measured containment substrate pins", detail_code="pipeline_cli_task_substrate_pins_v1")
    if contract_tests is None or baseline_sidecar is None:
        raise BTSError(BTSRejectReason.REJECT_HARD_GATE_FAILED, "BTS task assembly requires contract-test and baseline sidecars", detail_code="pipeline_cli_task_sidecars_v1")
    if not isinstance(baseline_sidecar, Path) or not isinstance(contract_tests, tuple) or not all(isinstance(item, ContractTest) for item in contract_tests):
        raise TypeError("task sidecars have invalid types")
    _require_substrate()
    observation = task.observation
    if observation is None:
        raise BTSError(BTSRejectReason.REJECT_HARD_GATE_FAILED, "BTS task assembly requires a non-gold observation plan", detail_code="pipeline_cli_task_observation_plan_v1")
    identity = observation.seed if execution_identity is None else execution_identity
    if identity not in observation.execution_candidates:
        raise BTSError(BTSRejectReason.REJECT_HARD_GATE_FAILED, "BTS task execution identity is not in the observation plan", detail_code="pipeline_cli_task_seed_pin_v1")
    owner, separator, repo = identity.slug.partition("/")
    if not owner or separator != "/" or not repo or "/" in repo:
        raise BTSError(BTSRejectReason.REJECT_HARD_GATE_FAILED, "BTS task donor slug is malformed", detail_code="pipeline_cli_task_seed_pin_v1")
    expected_paths = tuple(item.path for item in execution_contract_tests(task, identity, contract_tests))
    if tuple(item.path for item in contract_tests) != expected_paths:
        raise BTSError(BTSRejectReason.REJECT_HARD_GATE_FAILED, "contract-test sidecars do not exactly match the task manifest", detail_code="pipeline_cli_task_contract_sidecars_v1")
    snapshot = bts_cli.load_donor_snapshot(root, owner, repo, identity.commit_sha)
    module, _, _ = identity.symbol.rpartition(".")
    resolution, selected, preliminary = _prepared(snapshot, bts_cli.SeedSelector(module, identity.symbol), resolution_policy_path)
    if selected.module != module or selected.qualified_name != identity.symbol:
        raise BTSError(BTSRejectReason.REJECT_PROVENANCE_MISMATCH, "resolved seed differs from the task manifest", detail_code="pipeline_cli_task_seed_mismatch_v1")
    bts = _complete_bts(preliminary)
    member = next((item for item in bts.members if item.node == selected), None)
    if member is None or (
        member.source.slug,
        member.source.commit_sha,
        member.source.path,
        member.source.blob_sha,
        member.source.start_line,
        member.source.end_line,
    ) != (
        identity.slug,
        identity.commit_sha,
        identity.path,
        identity.blob_sha,
        identity.start_line,
        identity.end_line,
    ):
        raise BTSError(BTSRejectReason.REJECT_PROVENANCE_MISMATCH, "resolved seed source differs from the task manifest", detail_code="pipeline_cli_task_seed_mismatch_v1")
    package_suffix = identity.slug.replace("/", "_").replace("-", "_")
    package = f"transplant.{task.task_id.replace('-', '_')}.{package_suffix}"
    if not donor_execution_enabled():
        # The ordinary path above rejects before donor input when S2 is absent.
        # This narrow reviewed-fixture seam remains non-executable: it exists
        # solely for static request-shape tests that replace `_require_substrate`.
        # Its policy has no exact mounts and therefore cannot be promoted into
        # a runnable S2 request.
        baseline = _task_baseline_from_sidecar(baseline_sidecar, task, contract_test_paths=expected_paths)
        containment = build_containment_policy(
            nsjail_sha256=substrate.nsjail_sha256, nsjail_version=substrate.nsjail_version,
            nsjail_build_identity=substrate.nsjail_build_identity,
            config_schema_digest=substrate.config_schema_digest, rootfs_source=substrate.rootfs_source,
            rootfs_digest=substrate.rootfs_digest,
        )
        rerun_policy = RerunExecutionPolicy(
            RERUN_POLICY_SCHEMA_VERSION, containment,
            ("/usr/bin/python3", "-S", "-s", "-P", "/harness/runner.py"),
            _digest(b"pipeline-cli-runner-v1"), baseline.baseline_execution_policy_digest, ("/donor",),
        )
        request = _assemble_pipeline_request(
            snapshot, selected, resolution, preliminary, recipient_package=package,
            contract_tests=contract_tests, baseline=baseline, rerun_policy=rerun_policy,
            precomputed_relocation=None,
        )
        ranking, classified_license, ranking_unranked = _rank_materialized_candidates(task, root)
        return BTSTaskRequestAssembly(request, ranking, classified_license, ranking_unranked=ranking_unranked)
    relocation = _relocate_prepared(snapshot, preliminary, recipient_package=package, contract_tests=contract_tests)
    staging, staged = _prepare_shared_stage(
        root,
        {"kind": "task", "task_id": task.task_id, "identity": identity.to_dict(), "relocation_digest": relocation.relocation_digest},
        relocation,
    )
    try:
        specs = [ContractTestSpec(item.path, item.module, item.content) for item in contract_tests]
        baseline = record_baseline(
            snapshot.source_root,
            specs,
            substrate=substrate,
            contract_root=staged / "staging-v1" / "tests" / "original",
        )
        sidecar = _task_baseline_from_sidecar(baseline_sidecar, task, contract_test_paths=expected_paths)
        if (baseline.counts, baseline.selected_test_ids) != (sidecar.counts, sidecar.selected_test_ids):
            raise BTSError(
                BTSRejectReason.REJECT_PROVENANCE_MISMATCH,
                "contained task baseline does not match its publication sidecar cross-check",
                detail_code="pipeline_cli_task_baseline_mismatch_v1",
            )
        rerun_policy = _rerun_policy_for_relocation(relocation, staged, substrate=substrate, baseline=baseline)
        request = _assemble_pipeline_request(
            snapshot, selected, resolution, preliminary, recipient_package=package,
            contract_tests=contract_tests, baseline=baseline, rerun_policy=rerun_policy,
            precomputed_relocation=relocation,
        )
        ranking, classified_license, ranking_unranked = _rank_materialized_candidates(task, root)
        return BTSTaskRequestAssembly(request, ranking, classified_license, staging=staging, ranking_unranked=ranking_unranked)
    except BaseException:
        # The content-addressed stage may be concurrently consumed.  Leave an
        # incomplete stage for the next lock holder to rebuild and verify.
        raise


def _task_baseline_from_sidecar(
    path: Path, task: BTSEvalTask, *, contract_test_paths: tuple[str, ...] | None = None
) -> ContractBaselineEvidence:
    """Load the compact, publication-facing BTS task baseline sidecar.

    The sidecar records independently observed aggregate outcomes and selected
    test IDs.  Its construction intentionally consumes only the non-gold task
    observation plan; the grading oracle compares the resulting observation
    later.
    """

    data = _read_regular_json_bytes(path)
    raw = _parse_json_bytes(data)
    try:
        required = {
            "contract_test_count", "expected_pass", "expected_fail", "expected_skip",
            "selected_test_ids", "runner_convention",
        }
        if not isinstance(raw, dict) or set(raw) != required or data != _canonical(raw):
            raise ValueError("task baseline sidecar has an invalid envelope")
        count = raw["contract_test_count"]
        passed = raw["expected_pass"]
        failed = raw["expected_fail"]
        skipped = raw["expected_skip"]
        selected = raw["selected_test_ids"]
        convention = raw["runner_convention"]
        if (
            any(type(value) is not int or value < 0 for value in (count, passed, failed, skipped))
            or count != passed + failed + skipped
            or not isinstance(selected, list)
            or not all(isinstance(value, str) and value for value in selected)
            or selected != sorted(set(selected))
            or not isinstance(convention, str)
            or not convention.strip()
        ):
            raise ValueError("task baseline sidecar fields are malformed")
        observation = task.observation
        if observation is None:
            raise BTSError(
                BTSRejectReason.REJECT_PROVENANCE_MISMATCH,
                "baseline sidecar does not match the non-gold task observation plan",
                detail_code="pipeline_cli_task_baseline_mismatch_v1",
            )
        allowed_paths = observation.contract_tests if contract_test_paths is None else contract_test_paths
        selected = [identifier for identifier in selected if identifier.partition("::")[0] in {PurePosixPath(item).name for item in allowed_paths}]
        if count < len(selected) or len(selected) != sum(identifier.partition("::")[0] in {PurePosixPath(item).name for item in allowed_paths} for identifier in raw["selected_test_ids"]):
            raise BTSError(
                BTSRejectReason.REJECT_PROVENANCE_MISMATCH,
                "baseline sidecar does not match the non-gold task observation plan",
                detail_code="pipeline_cli_task_baseline_mismatch_v1",
            )
        outcomes_by_name = tuple((identifier, "pass") for identifier in selected)
        outcomes = tuple(
            TestOutcomeEvidence(
                identifier,
                TestOutcome(outcome),
                "pipeline_cli_task_baseline_v1",
                _digest(_canonical({"id": identifier, "outcome": outcome})),
            )
            for identifier, outcome in outcomes_by_name
        )
        return ContractBaselineEvidence.create(
            outcomes,
            baseline_mount_plan_digest=_digest(b"pipeline-cli-task-baseline-mount-v1"),
            baseline_execution_policy_digest=_digest(b"pipeline-cli-task-baseline-execution-v1"),
        )
    except BTSError:
        raise
    except (TypeError, UnicodeError, ValueError, KeyError) as exc:
        raise BTSError(
            BTSRejectReason.REJECT_HARD_GATE_FAILED,
            "task baseline sidecar is malformed",
            detail_code="pipeline_cli_task_baseline_sidecar_v1",
            cause=exc,
        ) from exc


def _write_atomic(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.tmp-", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def run_pipeline(root: Path, owner: str, repo: str, commit_sha: str, *, seed: bts_cli.SeedSelector, contract_tests_path: Path, out_dir: Path, recipient_package: str, nsjail_sha256: str, nsjail_version: str, nsjail_build_identity: str, config_schema_digest: str, rootfs_source: Path, rootfs_digest: str, policy_path: Path | None = None, emit_packets: PacketInputs | None = None) -> BTSPipelineResult:
    """Assemble and run one Python BTS pipeline through the real S2 rerun seam."""

    _require_substrate()
    snapshot = bts_cli.load_donor_snapshot(root, owner, repo, commit_sha)
    specs = load_contract_tests(contract_tests_path)
    resolution, selected, preliminary = _prepared(snapshot, seed, policy_path)
    tests = tuple(ContractTest(item.path, read_regular_file(snapshot.source_root / item.path, maximum_bytes=_MAX_SPEC_BYTES, no_follow=False), item.module) for item in specs)
    substrate = BTSSubstratePins(nsjail_sha256, nsjail_version, nsjail_build_identity, config_schema_digest, rootfs_source, rootfs_digest)
    # Phase 1 is entirely in-process.  Phase 2 persists precisely those E1
    # bytes, records the donor-present baseline against staged originals, then
    # binds one read-only S2 mount for every authorized relocated file.
    relocation = _relocate_prepared(snapshot, preliminary, recipient_package=recipient_package, contract_tests=tests)
    _stage, staged = _prepare_shared_stage(
        root,
        {"kind": "pipeline", "recipient_package": recipient_package, "commit_sha": commit_sha, "relocation_digest": relocation.relocation_digest},
        relocation,
    )
    baseline = record_baseline(
        snapshot.source_root,
        specs,
        substrate=substrate,
        contract_root=staged / "staging-v1" / "tests" / "original",
    )
    rerun_policy = _rerun_policy_for_relocation(relocation, staged, substrate=substrate, baseline=baseline)
    request = _assemble_pipeline_request(
        snapshot, selected, resolution, preliminary, recipient_package=recipient_package,
        contract_tests=tests, baseline=baseline, rerun_policy=rerun_policy,
        precomputed_relocation=relocation,
    )
    result = run_bts_pipeline(request)
    _write_atomic(out_dir / "pipeline-result.json", result.to_bytes())
    summary = {"schema_version": PIPELINE_CLI_SCHEMA_VERSION, "verdict": result.verdict.status.value, "bts_digest": result.verdict.bts_digest, "relocation_digest": result.verdict.relocation_digest, "rerun_report_digest": result.verdict.rerun_report_digest, "probe_report_digest": result.verdict.probe_report_digest}
    _write_atomic(out_dir / "summary.json", _canonical(summary))
    if emit_packets is not None:
        packet = build_reference_packet(result.bts, result.verdict, inputs=emit_packets)
        publish_packet(packet, out_dir / "reference.packet.tar")
    return result


def _baseline_from_sidecar(path: Path) -> ContractBaselineEvidence:
    """Load the canonical baseline artifact recorded beside one donor bundle."""

    data = _read_regular_json_bytes(path)
    raw = _parse_json_bytes(data)
    try:
        if not isinstance(raw, dict) or set(raw) != {
            "schema_version", "outcomes", "counts", "selected_test_ids", "baseline_mount_plan_digest",
            "baseline_execution_policy_digest", "baseline_digest",
        }:
            raise ValueError("baseline sidecar has an invalid envelope")
        if data != _canonical(raw):
            raise ValueError("baseline sidecar is noncanonical")
        counts = raw["counts"]
        if not isinstance(counts, dict) or set(counts) != {"passed", "failed", "skipped"}:
            raise ValueError("baseline counts are malformed")
        outcomes_raw = raw["outcomes"]
        if not isinstance(outcomes_raw, list):
            raise ValueError("baseline outcomes are malformed")
        outcomes: list[TestOutcomeEvidence] = []
        for item in outcomes_raw:
            if not isinstance(item, dict) or set(item) != {"canonical_test_id", "outcome", "detail_category", "detail_digest"}:
                raise ValueError("baseline outcome is malformed")
            outcomes.append(TestOutcomeEvidence(item["canonical_test_id"], TestOutcome(item["outcome"]), item["detail_category"], item["detail_digest"]))
        selected = raw["selected_test_ids"]
        if not isinstance(selected, list) or not all(isinstance(item, str) for item in selected):
            raise ValueError("baseline selected test IDs are malformed")
        return ContractBaselineEvidence(
            raw["schema_version"], tuple(outcomes), OutcomeCounts(counts["passed"], counts["failed"], counts["skipped"]),
            tuple(selected), raw["baseline_mount_plan_digest"], raw["baseline_execution_policy_digest"], raw["baseline_digest"],
        )
    except (TypeError, UnicodeError, ValueError, KeyError) as exc:
        raise BTSError(BTSRejectReason.REJECT_HARD_GATE_FAILED, "baseline sidecar is malformed", detail_code="pipeline_cli_exit_baseline_sidecar_v1", cause=exc) from exc


def _runnable_contract_tests(corpus_root: Path, items: object) -> tuple[ContractTest, ...]:
    if not isinstance(items, list):
        raise BTSError(BTSRejectReason.REJECT_HARD_GATE_FAILED, "runnable contract tests are malformed", detail_code="pipeline_cli_exit_runnable_v1")
    tests: list[ContractTest] = []
    for item in items:
        if not isinstance(item, dict) or not isinstance(item.get("path"), str) or not isinstance(item.get("module"), str):
            raise BTSError(BTSRejectReason.REJECT_HARD_GATE_FAILED, "runnable contract test is malformed", detail_code="pipeline_cli_exit_runnable_v1")
        try:
            path = confined_path(corpus_root, item["path"])
            content = read_regular_file(path, maximum_bytes=_MAX_SPEC_BYTES, no_follow=False)
        except (OSError, ValueError) as exc:
            raise BTSError(BTSRejectReason.REJECT_HARD_GATE_FAILED, "runnable contract test cannot be read", detail_code="pipeline_cli_exit_contract_read_v1", cause=exc) from exc
        tests.append(ContractTest(item["path"], content, item["module"]))
    return tuple(tests)


def _require_runtime_ratification(
    manifest: Mapping[str, object],
    *,
    corpus_manifest_digest: str,
    donors_dir: Path,
    trusted_keys_path: Path | None,
    ratification_sidecar: Path | None,
    default_sidecar: Path,
) -> None:
    """Require the L5 out-of-band authority for a recorded runtime digest."""

    raw_ratification = manifest.get("ratified_runtime_digest")
    if raw_ratification is None:
        return
    if not isinstance(raw_ratification, str):
        raise AssertionError("validated runtime ratification has invalid shape")
    if trusted_keys_path is None:
        raise BTSError(
            BTSRejectReason.REJECT_HARD_GATE_FAILED,
            "ratified runtime digest requires out-of-band trusted keys",
            detail_code="pipeline_cli_ratification_keys_required_v1",
        )
    try:
        from leitir.manifest_auth import ManifestAuthError, load_trusted_keys, require_detached_projection_auth

        require_detached_projection_auth(
            {
                "corpus_id": manifest["corpus_id"],
                "corpus_manifest_digest": corpus_manifest_digest,
                "ratified_runtime_digest": raw_ratification,
            },
            default_sidecar if ratification_sidecar is None else ratification_sidecar,
            trusted_keys=load_trusted_keys(trusted_keys_path, shelf_context=donors_dir),
        )
    except ManifestAuthError as exc:
        raise BTSError(
            BTSRejectReason.REJECT_PROVENANCE_MISMATCH,
            "runtime ratification signature is absent, malformed, or untrusted",
            detail_code="pipeline_cli_ratification_invalid_v1",
            cause=exc,
        ) from exc


def exit_gate_run(
    corpus_manifest_path: Path,
    donors_dir: Path,
    *,
    corpus_root: Path | None = None,
    out_dir: Path | None = None,
    nsjail_version: str | None = None,
    nsjail_build_identity: str | None = None,
    config_schema_digest: str | None = None,
    rootfs_source: Path | None = None,
    substrate_nsjail_sha256: str | None = None,
    substrate_rootfs_digest: str | None = None,
    trusted_keys_path: Path | None = None,
    ratification_sidecar: Path | None = None,
) -> dict[str, object]:
    """Build every v1.1 runnable case and run the non-compensating exit gate.

    The runnable section only describes execution inputs.  Corpus ratification
    remains pins-only authority; consequently an absent or nonmatching external
    ratification produces a rejected gate report rather than being synthesized.
    """

    # Reject locally before opening donor shelves or sidecars.  Phase A baseline
    # evidence is contained-only and has no host-recorded fallback.
    _require_substrate()
    manifest = load_corpus_manifest(corpus_manifest_path)
    raw_ratification = manifest.get("ratified_runtime_digest")
    runnable = manifest.get("runnable")
    if not isinstance(runnable, dict):
        raise BTSError(BTSRejectReason.REJECT_HARD_GATE_FAILED, "exit corpus has no runnable section", detail_code="pipeline_cli_exit_runnable_required_v1")
    root = (corpus_manifest_path.parent if corpus_root is None else corpus_root).resolve()
    per_case = runnable.get("per_case")
    if not isinstance(per_case, list):
        raise BTSError(BTSRejectReason.REJECT_HARD_GATE_FAILED, "exit corpus runnable cases are malformed", detail_code="pipeline_cli_exit_runnable_v1")
    cases_by_id: dict[str, dict[str, object]] = {
        cast(str, item["case_id"]): item for item in per_case if isinstance(item, dict) and isinstance(item.get("case_id"), str)
    }
    raw_cases = manifest["cases"]
    if not isinstance(raw_cases, list):
        raise AssertionError("validated corpus cases have invalid shape")
    for raw_case in raw_cases:
        if not isinstance(raw_case, dict) or not isinstance(raw_case.get("case_id"), str):
            raise AssertionError("validated corpus case has invalid shape")
        case_id = cast(str, raw_case["case_id"])
        runnable_case = cases_by_id.get(case_id)
        if runnable_case is None:
            raise AssertionError("validated runnable case alignment was lost")

    substrate = runnable["substrate"]
    if not isinstance(substrate, dict) or not isinstance(substrate.get("containment_template_version"), str):
        raise AssertionError("validated runnable substrate has invalid shape")
    manifest_nsjail_sha = substrate.get("nsjail_sha256")
    manifest_rootfs_digest = substrate.get("rootfs_digest")
    if manifest_nsjail_sha is not None and not isinstance(manifest_nsjail_sha, str):
        raise AssertionError("validated runnable nsjail pin has invalid shape")
    if manifest_rootfs_digest is not None and not isinstance(manifest_rootfs_digest, str):
        raise AssertionError("validated runnable rootfs pin has invalid shape")
    # The committed corpus is authoritative once its pins are populated. A null
    # pin is only permitted during the first measurement and still requires an
    # explicit measured input; any populated pin must match exactly.
    if not all(isinstance(item, str) and _SHA256_DIGEST_RE.fullmatch(item) for item in (substrate_nsjail_sha256, substrate_rootfs_digest)):
        raise BTSError(BTSRejectReason.REJECT_HARD_GATE_FAILED, "exit gate requires measured nsjail and rootfs digest pins", detail_code="pipeline_cli_exit_substrate_pins_v1")
    if (manifest_nsjail_sha is not None and manifest_nsjail_sha != substrate_nsjail_sha256) or (manifest_rootfs_digest is not None and manifest_rootfs_digest != substrate_rootfs_digest):
        raise BTSError(BTSRejectReason.REJECT_PROVENANCE_MISMATCH, "runtime substrate pins do not match the corpus pins", detail_code="pipeline_cli_exit_substrate_pin_mismatch_v1")
    if not all(isinstance(item, str) and item for item in (nsjail_version, nsjail_build_identity, config_schema_digest)) or not isinstance(rootfs_source, Path):
            raise BTSError(BTSRejectReason.REJECT_HARD_GATE_FAILED, "exit gate is missing containment identity pins", detail_code="pipeline_cli_exit_substrate_pins_v1")
    for field, measured in (("nsjail_version", nsjail_version), ("nsjail_build_identity", nsjail_build_identity), ("config_schema_digest", config_schema_digest)):
        pinned = substrate.get(field)
        if pinned is not None and pinned != measured:
            raise BTSError(BTSRejectReason.REJECT_PROVENANCE_MISMATCH, "runtime substrate pins do not match the corpus pins", detail_code="pipeline_cli_exit_substrate_pin_mismatch_v1")
    substrate_pins = BTSSubstratePins(
        cast(str, substrate_nsjail_sha256), cast(str, nsjail_version),
        cast(str, nsjail_build_identity), cast(str, config_schema_digest), rootfs_source,
        cast(str, substrate_rootfs_digest),
    )
    layout = runnable.get("donors_dir_layout")
    if not isinstance(layout, str):
        raise AssertionError("validated donor layout has invalid shape")
    shared_shelf_root = layout == "repos/github.com/{owner}/{repo}/{commit_sha}"
    exit_cases: list[ExitCorpusCase] = []
    preparation_reports = []
    # Keep each staged recipient alive until ``run_exit_gate`` consumes its
    # request.  The resulting S2 mount sources are exact E1 files, never the
    # donor shelf or a broad staging directory.
    with ExitStack():
      if not raw_cases:
       preparation_reports.append(
           rejected_preparation_report(
               "corpus", BTSRejectReason.REJECT_HARD_GATE_FAILED, "pipeline_cli_exit_empty_cases_v1",
           )
       )
      for case_index, raw_case in enumerate(raw_cases):
       case_id = f"case-index-{case_index:04d}"
       try:
        if not isinstance(raw_case, dict) or not isinstance(raw_case.get("case_id"), str):
            raise AssertionError("validated corpus case has invalid shape")
        case_id = cast(str, raw_case["case_id"])
        runnable_case = cases_by_id.get(case_id)
        if runnable_case is None:
            raise AssertionError("validated runnable case alignment was lost")
        tests = _runnable_contract_tests(root, runnable_case.get("contract_tests"))
        donor = raw_case["donor"]
        seed = raw_case["seed"]
        if not isinstance(donor, dict) or not isinstance(seed, dict):
            raise AssertionError("validated corpus donor or seed has invalid shape")
        if not all(isinstance(donor.get(name), str) for name in ("host", "owner", "repo", "commit_sha")) or not all(isinstance(seed.get(name), str) for name in ("module", "qualified_name")):
            raise AssertionError("validated corpus donor or seed values have invalid shape")
        snapshot_root = donors_dir if shared_shelf_root else donors_dir / case_id
        snapshot = bts_cli.load_donor_snapshot(snapshot_root, cast(str, donor["owner"]), cast(str, donor["repo"]), cast(str, donor["commit_sha"]), host=cast(str, donor["host"]))
        roots_raw = runnable_case.get("import_roots", ["."])
        if not isinstance(roots_raw, list) or not all(isinstance(import_root, str) for import_root in roots_raw):
            raise AssertionError("validated import roots have invalid shape")
        import_roots = tuple(cast(str, import_root) for import_root in roots_raw)
        policy_path = runnable_case.get("policy_path")
        if policy_path is not None and not isinstance(policy_path, str):
            raise AssertionError("validated policy path has invalid shape")
        seed_module = cast(str, seed["module"])
        seed_name = cast(str, seed["qualified_name"])
        resolution, selected, preliminary = _prepared(
            snapshot,
            bts_cli.SeedSelector(seed_module, seed_name if seed_name.startswith(seed_module + ".") else f"{seed_module}.{seed_name}"),
            None if policy_path is None else root / policy_path,
        )
        if preliminary.status is not BTSStatus.COMPLETE or preliminary.bts is None:
            raise BTSError(BTSRejectReason.REJECT_HARD_GATE_FAILED, "exit pipeline requires a complete static BTS", detail_code="pipeline_cli_non_complete_bts_v1")
        package = f"transplant.{raw_case['case_id']}"
        relocation = _relocate_prepared(snapshot, preliminary, recipient_package=package, contract_tests=tests)
        _stage, staged = _prepare_shared_stage(
            root,
            {"kind": "exit-corpus", "case_id": case_id, "relocation_digest": relocation.relocation_digest},
            relocation,
        )
        baseline = _record_runnable_baseline(
            snapshot.source_root, tests, substrate=substrate_pins,
            import_roots=import_roots,
            contract_root=staged / "staging-v1" / "tests" / "original",
        )
        baseline_counts = raw_case["baseline"]
        if not isinstance(baseline_counts, dict) or (
            len(baseline.outcomes), baseline.counts.passed, baseline.counts.failed, baseline.counts.skipped
        ) != (baseline_counts.get("contract_test_count"), baseline_counts.get("expected_pass"), baseline_counts.get("expected_fail"), baseline_counts.get("expected_skip")):
            raise BTSError(BTSRejectReason.REJECT_HARD_GATE_FAILED, "baseline evidence does not match corpus baseline pins", detail_code="pipeline_cli_exit_baseline_mismatch_v1")
        rerun_policy = _rerun_policy_for_relocation(relocation, staged, substrate=substrate_pins, baseline=baseline)
        request = _assemble_pipeline_request(
            snapshot, selected, resolution, preliminary, recipient_package=package,
            contract_tests=tests, baseline=baseline, rerun_policy=rerun_policy,
            precomputed_relocation=relocation,
        )
        exit_cases.append(ExitCorpusCase.pin(cast(str, raw_case["case_id"]), cast(str, raw_case["source_provenance"]), "sha256:" + cast(str, raw_case["review_receipt_digest"]), request))
       except BTSError as exc:
        preparation_reports.append(rejected_preparation_report(case_id, exc.reason, exc.evidence.detail_code))
       except Exception as exc:
        wrapped = BTSError(
            BTSRejectReason.REJECT_HARD_GATE_FAILED,
            "exit case preparation failed",
            detail_code="pipeline_cli_case_preparation_v1",
            cause=exc,
        )
        preparation_reports.append(rejected_preparation_report(case_id, wrapped.reason, wrapped.evidence.detail_code))
      if preparation_reports:
       prepared_reports = tuple(_run_case(case, run_bts_pipeline) for case in exit_cases)
       report = report_prepared_cases(
           corpus_manifest_digest="sha256:" + content_digest(manifest),
           ratified_manifest_digest=raw_ratification if isinstance(raw_ratification, str) else "sha256:" + "0" * 64,
           reports=(*prepared_reports, *preparation_reports),
       )
      else:
       ratification = raw_ratification if isinstance(raw_ratification, str) else "sha256:" + "0" * 64
       corpus = ExitCorpus.pin(str(manifest["corpus_id"]), str(manifest["created_for_milestone"]), tuple(sorted(exit_cases, key=lambda item: (item.case_id, item.source_provenance))), ratified_manifest_digest=ratification)
       _require_runtime_ratification(
           manifest,
           corpus_manifest_digest=corpus.corpus_manifest_digest,
           donors_dir=donors_dir,
           trusted_keys_path=trusted_keys_path,
           ratification_sidecar=ratification_sidecar,
           default_sidecar=corpus_manifest_path.parent / "ratification-v1.json",
       )
       report = run_exit_gate(corpus, run_bts_pipeline)
    destination = corpus_manifest_path.parent / "exit-gate-out" if out_dir is None else out_dir
    _write_atomic(destination / "exit-gate-report.json", report.to_bytes())
    summary: dict[str, object] = {"schema_version": PIPELINE_CLI_SCHEMA_VERSION, "status": report.status.value, "corpus_content_digest": content_digest(manifest), "corpus_manifest_digest": report.corpus_manifest_digest, "report_digest": report.report_digest}
    if raw_ratification is None:
        summary["ratification"] = "pending-out-of-band runtime digest (expected REJECT until recorded; see benchmarks/exit-corpus/README)"
    _write_atomic(destination / "summary.json", _canonical(summary))
    return summary


def _occupied_validate_typed(*, policy: OccupiedAttachmentPolicy, recipient_manifest: RecipientInputManifest, bts: BTS | BTSResult, module_map: ModuleMap, matrix: ConflictMatrix, recipient_subject: str, candidate: CompositionCandidateRef, baseline: RecipientBaselineEvidence, occupied_rerun: OccupiedRerunEvidence, test_set_digest: str, runner_closure_digest: str, config_closure_digest: str) -> dict[str, object]:
    """Run occupied attachment validation only; this function never executes bytes.

    This is the typed seam used after the closed artifact envelope has been
    reconstructed.  It never executes donor or recipient bytes.
    """

    inventory = derive_recipient_binding_inventory(recipient_manifest, policy)
    bts_digest = bts.bts_digest if isinstance(bts, BTS) else bts.bts.bts_digest if bts.bts is not None else ""
    emitted = validate_collisions(inventory, bts, module_map, recipient_manifest_digest=recipient_manifest.manifest_digest, bts_digest=bts_digest)
    validate_conflict_matrix(matrix, policy=policy, recipient_subject=recipient_subject, candidate=candidate)
    validate_recipient_parity(baseline, occupied_rerun, policy=policy, recipient_manifest_digest=recipient_manifest.manifest_digest, bts_digest=bts_digest, test_set_digest=test_set_digest, runner_closure_digest=runner_closure_digest, config_closure_digest=config_closure_digest)
    return {"schema_version": PIPELINE_CLI_SCHEMA_VERSION, "status": "complete", "inventory_digest": inventory.inventory_digest, "emitted_binding_count": len(emitted), "recipient_manifest_digest": recipient_manifest.manifest_digest}


_OCCUPIED_ARTIFACT_SCHEMA_VERSION = "leitir-occupied-validate-input-v1"


def _artifact_object(data: str | bytes) -> dict[str, object]:
    try:
        text = data.decode("utf-8", "strict") if isinstance(data, bytes) else data
        if not isinstance(text, str):
            raise TypeError("artifact must be text")
        value = json.loads(text, object_pairs_hook=_unique_object)
        if not isinstance(value, dict) or _canonical(value).decode("utf-8") != text:
            raise ValueError("artifact is not a canonical object")
        return value
    except (TypeError, UnicodeError, ValueError, json.JSONDecodeError) as exc:
        raise BTSError(BTSRejectReason.REJECT_HARD_GATE_FAILED, "occupied artifact is malformed", detail_code="pipeline_cli_occupied_artifact_v1", cause=exc) from exc


def _outcomes_from_json(value: object) -> tuple[TestOutcomeEvidence, ...]:
    if not isinstance(value, list):
        raise ValueError("outcomes must be an array")
    values: list[TestOutcomeEvidence] = []
    for item in value:
        if not isinstance(item, dict) or set(item) != {"canonical_test_id", "outcome", "detail_category", "detail_digest"}:
            raise ValueError("outcome has an invalid schema")
        values.append(TestOutcomeEvidence(item["canonical_test_id"], TestOutcome(item["outcome"]), item["detail_category"], item["detail_digest"]))
    return tuple(values)


def _candidate_from_json(value: object) -> CompositionCandidateRef:
    if not isinstance(value, dict) or set(value) != {"candidate_key", "bts_digest", "candidate_manifest_digest", "graph_digest"}:
        raise ValueError("candidate has an invalid schema")
    key = value["candidate_key"]
    if not isinstance(key, list) or not key or any(type(item) not in {str, int} for item in key):
        raise ValueError("candidate key is invalid")
    return CompositionCandidateRef(tuple(cast(str | int, item) for item in key), cast(str, value["bts_digest"]), cast(str, value["candidate_manifest_digest"]), cast(str, value["graph_digest"]))


def _matrix_from_json(value: object) -> ConflictMatrix:
    if not isinstance(value, dict) or set(value) != {"schema_version", "recipient_subject", "recipient", "candidates", "dependencies", "architecture", "duplicates", "conflicts", "policy_digest", "matrix_digest"}:
        raise ValueError("conflict matrix has an invalid schema")
    if value["schema_version"] != COMPOSITION_MATRIX_SCHEMA or not isinstance(value["recipient_subject"], str) or not isinstance(value["candidates"], list) or not isinstance(value["dependencies"], list) or not isinstance(value["architecture"], list) or not isinstance(value["duplicates"], list) or not isinstance(value["conflicts"], list) or not isinstance(value["policy_digest"], str) or not isinstance(value["matrix_digest"], str):
        raise ValueError("conflict matrix fields have invalid types")
    dependencies: list[CandidateDependencyEvidence] = []
    for item in value["dependencies"]:
        if not isinstance(item, dict) or set(item) != {"subject", "ecosystem", "name", "version", "resolved_sha", "completeness", "source_path", "source_digest"}:
            raise ValueError("dependency has an invalid schema")
        dependencies.append(CandidateDependencyEvidence(_candidate_from_json(item["subject"]), cast(str, item["ecosystem"]), cast(str, item["name"]), cast(str, item["version"]), cast(str | None, item["resolved_sha"]), ClosureCompleteness(item["completeness"]), cast(str, item["source_path"]), cast(str, item["source_digest"])))
    conflicts: list[ConflictRecord] = []
    for item in value["conflicts"]:
        if not isinstance(item, dict) or set(item) != {"left", "right", "kind", "status", "evidence_key", "evidence_digest", "detail_code"} or not isinstance(item["evidence_key"], list):
            raise ValueError("conflict has an invalid schema")
        conflicts.append(ConflictRecord(_candidate_from_json(item["left"]), _candidate_from_json(item["right"]), ConflictKind(item["kind"]), CompatibilityStatus(item["status"]), tuple(cast(str | int, part) for part in item["evidence_key"]), cast(str, item["evidence_digest"]), cast(str, item["detail_code"])))
    return ConflictMatrix(value["schema_version"], value["recipient_subject"], _candidate_from_json(value["recipient"]), tuple(_candidate_from_json(item) for item in value["candidates"]), tuple(dependencies), tuple(value["architecture"]), tuple(value["duplicates"]), tuple(conflicts), value["policy_digest"], value["matrix_digest"])


def occupied_validate_artifact(data: str | bytes) -> dict[str, object]:
    """Construct and validate the closed JSON occupied-attachment envelope."""

    raw = _artifact_object(data)
    required = {"schema_version", "policy", "recipient_manifest", "bts_report", "module_map", "matrix", "recipient_subject", "candidate", "baseline", "occupied_rerun", "test_set_digest", "runner_closure_digest", "config_closure_digest"}
    try:
        if set(raw) != required or raw["schema_version"] != _OCCUPIED_ARTIFACT_SCHEMA_VERSION:
            raise ValueError("occupied artifact envelope is unsupported")
        policy_raw = raw["policy"]
        if not isinstance(policy_raw, dict) or set(policy_raw) != set(OccupiedAttachmentPolicy.__dataclass_fields__):
            raise ValueError("policy has an invalid schema")
        policy_values = dict(policy_raw)
        policy_values["supported_languages"] = tuple(policy_values["supported_languages"])
        policy = OccupiedAttachmentPolicy(**policy_values)
        manifest_raw = raw["recipient_manifest"]
        if not isinstance(manifest_raw, dict) or set(manifest_raw) != {"project_root_identity", "manifest_version", "entries"} or not isinstance(manifest_raw["entries"], list):
            raise ValueError("recipient manifest has an invalid schema")
        entries: list[RecipientManifestEntry] = []
        for item in manifest_raw["entries"]:
            if not isinstance(item, dict) or set(item) != {"path", "role", "content"} or not all(isinstance(item[name], str) for name in ("path", "role", "content")):
                raise ValueError("recipient entry has an invalid schema")
            entries.append(RecipientManifestEntry.from_bytes(item["path"], item["role"], item["content"].encode("utf-8", "strict")))
        manifest = RecipientInputManifest.create(cast(str, manifest_raw["project_root_identity"]), tuple(entries), manifest_version=cast(str, manifest_raw["manifest_version"]))
        bts = load_bts_artifact(cast(str | bytes, raw["bts_report"]))
        map_raw = raw["module_map"]
        if not isinstance(map_raw, list) or not all(isinstance(item, list) and len(item) == 2 and all(isinstance(part, str) for part in item) for item in map_raw):
            raise ValueError("module map has an invalid schema")
        module_map = ModuleMap.from_pairs(*(tuple(item) for item in map_raw))
        matrix = _matrix_from_json(raw["matrix"])
        candidate = _candidate_from_json(raw["candidate"])
        baseline_raw = raw["baseline"]
        if not isinstance(baseline_raw, dict) or set(baseline_raw) != set(RecipientBaselineEvidence.__dataclass_fields__) or not isinstance(baseline_raw.get("canonical_test_ids"), list) or not isinstance(baseline_raw.get("counts"), dict):
            raise ValueError("baseline has an invalid schema")
        counts = baseline_raw["counts"]
        baseline = RecipientBaselineEvidence(cast(str, baseline_raw["schema_version"]), cast(str, baseline_raw["status"]), cast(str, baseline_raw["recipient_manifest_digest"]), cast(str, baseline_raw["test_set_digest"]), cast(str, baseline_raw["runner_closure_digest"]), cast(str, baseline_raw["config_closure_digest"]), cast(str, baseline_raw["mount_plan_digest"]), cast(str, baseline_raw["execution_policy_digest"]), tuple(cast(str, item) for item in baseline_raw["canonical_test_ids"]), _outcomes_from_json(baseline_raw["outcomes"]), OutcomeCounts(counts["passed"], counts["failed"], counts["skipped"]), cast(int, baseline_raw["qualification_runs"]), cast(str, baseline_raw["evidence_digest"]))
        rerun_raw = raw["occupied_rerun"]
        if not isinstance(rerun_raw, dict) or set(rerun_raw) != set(OccupiedRerunEvidence.__dataclass_fields__):
            raise ValueError("occupied rerun has an invalid schema")
        rerun = OccupiedRerunEvidence(cast(str, rerun_raw["schema_version"]), OccupiedRole(cast(str, rerun_raw["role"])), cast(str, rerun_raw["recipient_manifest_digest"]), cast(str, rerun_raw["bts_digest"]), cast(str, rerun_raw["test_set_digest"]), cast(str, rerun_raw["runner_closure_digest"]), cast(str, rerun_raw["config_closure_digest"]), cast(str, rerun_raw["mount_plan_digest"]), cast(str, rerun_raw["execution_policy_digest"]), _outcomes_from_json(rerun_raw["outcomes"]), cast(str, rerun_raw["evidence_digest"]))
        return _occupied_validate_typed(policy=policy, recipient_manifest=manifest, bts=bts, module_map=module_map, matrix=matrix, recipient_subject=cast(str, raw["recipient_subject"]), candidate=candidate, baseline=baseline, occupied_rerun=rerun, test_set_digest=cast(str, raw["test_set_digest"]), runner_closure_digest=cast(str, raw["runner_closure_digest"]), config_closure_digest=cast(str, raw["config_closure_digest"]))
    except BTSError:
        raise
    except (TypeError, UnicodeError, ValueError, KeyError) as exc:
        raise BTSError(BTSRejectReason.REJECT_HARD_GATE_FAILED, "occupied artifact is malformed", detail_code="pipeline_cli_occupied_artifact_v1", cause=exc) from exc


def occupied_validate(data: str | bytes) -> dict[str, object]:
    """Validate one canonical occupied-attachment artifact envelope."""

    return occupied_validate_artifact(data)


__all__ = ["CONTRACT_TESTS_SCHEMA_VERSION", "PIPELINE_CLI_SCHEMA_VERSION", "BTSSubstratePins", "BTSTaskRequestAssembly", "ContractTestSpec", "assemble_bts_task_request", "build_containment_policy", "exit_gate_run", "load_contract_tests", "occupied_validate", "occupied_validate_artifact", "record_baseline", "run_pipeline"]
