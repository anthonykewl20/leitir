"""Execute the pinned BTS agent-task corpus only through the integrated pipeline.

This tool owns corpus orchestration, not an alternate donor execution path.
``leitir.pipeline_cli`` supplies the reviewed request assembly once its delta is
integrated; absent or incompatible assembly is a typed, fail-closed error.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib
import json
import os
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, NoReturn

from leitir.bts_bench import (
    AdaptationProbeObs,
    BTSEvalBenchmark,
    BTSEvalManifest,
    BTSEvalTask,
    BTSTaskObservation,
    CandidateIdentity,
    coexisting_recipient_three_runs_observation,
    from_pipeline_result,
    load_manifest,
)
from leitir.bts_cli import load_donor_snapshot
from leitir.bts_errors import BTSError, BTSRejectReason
from leitir.bts_pipeline import BTSPipelineRequest, BTSPipelineResult, run_bts_pipeline
from leitir.materialize import materialize_github_repo
from leitir.relocate import ContractTest
from leitir.safeio import confined_path, read_regular_file

PLAN_SCHEMA_VERSION = "leitir-bts-task-plan-v1"
BENCHMARK_ID = "bts-v1-agent-tasks"
_TASK_FILENAMES = (
    "async-retry-backoff.json",
    "binary-wire-decode.json",
    "lru-ttl-decisions.json",
    "three-repo-combine.json",
    "url-normalization-compare.json",
    "worker-shutdown-predicate.json",
)


class BTSDriverError(RuntimeError):
    """Base error for deterministic, non-partial driver failures."""


class PipelineCliRequiredError(BTSDriverError):
    """Raised when the integrated request-assembly seam is unavailable."""


class PipelineAssemblyError(BTSDriverError):
    """Raised when pipeline_cli returns malformed task assembly evidence."""


class OutputConflictError(BTSDriverError):
    """Raised when a run artifact would overwrite pre-existing output."""


@dataclass(frozen=True, slots=True)
class TaskSidecars:
    """Committed test bytes and recorded donor-present baseline for one task."""

    contract_tests: tuple[ContractTest, ...]
    baseline_sidecar: Path
    policy_sidecar: Path


@dataclass(frozen=True, slots=True, order=True)
class DonorPin:
    slug: str
    commit_sha: str

    def __post_init__(self) -> None:
        owner, separator, repo = self.slug.partition("/")
        if not owner or separator != "/" or not repo or "/" in repo:
            raise ValueError("donor slug must be owner/repository")
        if len(self.commit_sha) != 40 or any(character not in "0123456789abcdef" for character in self.commit_sha):
            raise ValueError("donor commit must be a 40-character lowercase Git SHA")

    def to_dict(self) -> dict[str, str]:
        return {"commit_sha": self.commit_sha, "slug": self.slug}


@dataclass(frozen=True, slots=True)
class TaskPlan:
    schema_version: str
    benchmark_id: str
    tasks: tuple[tuple[str, str, tuple[DonorPin, ...], tuple[DonorPin, ...]], ...]

    def __post_init__(self) -> None:
        if self.schema_version != PLAN_SCHEMA_VERSION or self.benchmark_id != BENCHMARK_ID:
            raise ValueError("unsupported BTS task plan")
        identifiers = tuple(item[0] for item in self.tasks)
        if identifiers != tuple(sorted(identifiers)) or len(set(identifiers)) != len(identifiers):
            raise ValueError("task plan IDs must be sorted and unique")
        for task_id, task_digest, pins, requests in self.tasks:
            if not task_id or len(task_digest) != 64 or any(character not in "0123456789abcdef" for character in task_digest):
                raise ValueError("task plan has invalid task identity")
            if not pins or pins != tuple(sorted(set(pins))):
                raise ValueError("task plan pins must be sorted, unique, and non-empty")
            if not requests or requests != tuple(sorted(set(requests))) or not set(requests) <= set(pins):
                raise ValueError("task plan requests must be sorted, unique donor pins")

    def to_dict(self) -> dict[str, object]:
        return {
            "benchmark_id": self.benchmark_id,
            "schema_version": self.schema_version,
            "tasks": [
                {"donors": [pin.to_dict() for pin in pins], "requests": [pin.to_dict() for pin in requests], "task_digest": digest, "task_id": task_id}
                for task_id, digest, pins, requests in self.tasks
            ],
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), allow_nan=False, separators=(",", ":"), sort_keys=True)


def task_directory() -> Path:
    return Path(__file__).resolve().parents[1] / "benchmarks" / "bts-v1" / "tasks"


def discover_task_sidecars(tasks_directory: Path, task: BTSEvalTask) -> TaskSidecars:
    """Load exactly the committed sidecars without donor materialization.

    The published layout is ``tasks/<task-id>/contract_tests/<name>.py`` plus
    ``tasks/<task-id>/baseline.json``.  Sidecars are deliberately outside donor
    shelves and must exist before a non-dry run can materialize donor bytes.
    """

    directory = tasks_directory / task.task_id
    tests_root = directory / "contract_tests"
    baseline = directory / "baseline.json"
    policy = directory / "policy.json"
    if not tests_root.is_dir() or not baseline.is_file() or not policy.is_file():
        raise BTSError(
            BTSRejectReason.REJECT_HARD_GATE_FAILED,
            f"BTS task sidecars are missing for {task.task_id}",
            detail_code="pipeline_cli_task_sidecars_v1",
        )
    if task.observation is None:
        raise BTSDriverError(f"task has no non-gold observation plan: {task.task_id}")
    expected_paths = task.observation.contract_tests
    tests: list[ContractTest] = []
    for relative in expected_paths:
        path = confined_path(directory, relative)
        try:
            content = read_regular_file(path, maximum_bytes=1 << 20)
        except (OSError, ValueError) as exc:
            raise BTSError(
                BTSRejectReason.REJECT_HARD_GATE_FAILED,
                f"BTS task contract-test sidecar is missing: {relative}",
                detail_code="pipeline_cli_task_sidecars_v1",
                cause=exc,
            ) from exc
        tests.append(ContractTest(relative, content, Path(relative).stem))
    actual_paths = tuple(sorted(path.relative_to(directory).as_posix() for path in tests_root.rglob("*.py") if path.is_file() and not path.is_symlink()))
    if actual_paths != expected_paths:
        raise BTSError(
            BTSRejectReason.REJECT_HARD_GATE_FAILED,
            f"BTS task contract-test sidecars do not exactly match the manifest: {task.task_id}",
            detail_code="pipeline_cli_task_contract_sidecars_v1",
        )
    try:
        receipts = json.loads(read_regular_file(tasks_directory / "RECEIPTS.json", maximum_bytes=1 << 20))
        policy_receipt = receipts["policy_receipts"][task.task_id]
        policy_bytes = read_regular_file(policy, maximum_bytes=1 << 20)
        if policy_receipt != "sha256:" + hashlib.sha256(policy_bytes).hexdigest():
            raise ValueError("policy receipt mismatch")
    except (KeyError, OSError, TypeError, ValueError, json.JSONDecodeError) as exc:
        raise BTSError(
            BTSRejectReason.REJECT_HARD_GATE_FAILED,
            f"BTS task policy receipt is missing or invalid: {task.task_id}",
            detail_code="pipeline_cli_task_policy_receipt_v1",
            cause=exc,
        ) from exc
    return TaskSidecars(tuple(tests), baseline, policy)


def load_tasks(directory: Path | None = None) -> tuple[BTSEvalTask, ...]:
    """Load exactly the published six, refusing renamed or multi-task files."""

    base = task_directory() if directory is None else directory
    loaded: list[BTSEvalTask] = []
    for filename in _TASK_FILENAMES:
        path = base / filename
        manifest = load_manifest(path)
        if manifest.benchmark_id != BENCHMARK_ID or len(manifest.tasks) != 1:
            raise BTSDriverError(f"task manifest must contain one {BENCHMARK_ID} task: {path}")
        task = manifest.tasks[0]
        if task.task_id != path.stem:
            raise BTSDriverError(f"task manifest filename and task_id differ: {path}")
        loaded.append(task)
    tasks = tuple(sorted(loaded, key=lambda item: item.task_id))
    if tuple(item.task_id for item in tasks) != tuple(sorted(path.removesuffix(".json") for path in _TASK_FILENAMES)):
        raise BTSDriverError("published task IDs are incomplete")
    return tasks


def combined_manifest(tasks: tuple[BTSEvalTask, ...]) -> BTSEvalManifest:
    return BTSEvalManifest("leitir-bts-eval-manifest-v1", BENCHMARK_ID, tasks)


def build_plan(tasks: tuple[BTSEvalTask, ...]) -> TaskPlan:
    entries: list[tuple[str, str, tuple[DonorPin, ...], tuple[DonorPin, ...]]] = []
    for task in sorted(tasks, key=lambda item: item.task_id):
        if task.observation is None:
            raise BTSDriverError(f"task has no non-gold observation plan: {task.task_id}")
        pins = tuple(sorted({DonorPin(item.slug, item.commit_sha) for item in task.observation.candidates}))
        requests = tuple(sorted({DonorPin(item.slug, item.commit_sha) for item in task.observation.execution_candidates}))
        entries.append((task.task_id, task.digest(), pins, requests))
    return TaskPlan(PLAN_SCHEMA_VERSION, BENCHMARK_ID, tuple(entries))


def _split_pin(pin: DonorPin) -> tuple[str, str]:
    owner, _, repository = pin.slug.partition("/")
    return owner, repository


def validate_donor_pins(root: Path, plan: TaskPlan) -> None:
    """Require every already-materialized shelf to be an exact verified pin."""

    for pin in sorted({pin for _, _, pins, _ in plan.tasks for pin in pins}):
        owner, repository = _split_pin(pin)
        load_donor_snapshot(root, owner, repository, pin.commit_sha)


def materialize_donor_pins(root: Path, plan: TaskPlan) -> None:
    """Materialize exact Git pins, then re-open their verified shelves."""

    for pin in sorted({pin for _, _, pins, _ in plan.tasks for pin in pins}):
        owner, repository = _split_pin(pin)
        materialize_github_repo(root, f"github:{pin.slug}", owner, repository, pin.commit_sha)
    validate_donor_pins(root, plan)


def _pipeline_cli() -> Any:
    try:
        module = importlib.import_module("leitir.pipeline_cli")
    except ModuleNotFoundError as exc:
        if exc.name == "leitir.pipeline_cli":
            raise PipelineCliRequiredError("requires pipeline_cli: integrated task request assembly is unavailable") from exc
        raise
    if not callable(getattr(module, "assemble_bts_task_request", None)):
        raise PipelineCliRequiredError("requires pipeline_cli.assemble_bts_task_request(task, root)")
    return module


class _PipelineTaskRunner:
    """BTSRunner adapter; no donor code executes outside ``run_bts_pipeline``."""

    def __init__(self, root: Path, sidecars: dict[str, TaskSidecars] | None = None, substrate: object | None = None, task_digests: dict[str, str] | None = None) -> None:
        self.root = root
        self.sidecars = {} if sidecars is None else sidecars
        self.substrate = substrate
        # The benchmark identity is captured before observations begin.  This
        # lets grading bind the complete manifest while the observation chain
        # consumes only ``task.observation``.
        self.task_digests = {} if task_digests is None else task_digests

    def run(self, task: BTSEvalTask) -> BTSTaskObservation:
        module = _pipeline_cli()
        if self.substrate is None:
            # Preserve the assembler's typed substrate-first fail-closed seam.
            module.assemble_bts_task_request(task, self.root)
        sidecars = self.sidecars.get(task.task_id)
        if sidecars is None:
            raise BTSError(
                BTSRejectReason.REJECT_HARD_GATE_FAILED,
                f"BTS task sidecars are missing for {task.task_id}",
                detail_code="pipeline_cli_task_sidecars_v1",
            )
        if task.observation is None:
            raise PipelineAssemblyError("task has no non-gold observation plan")
        primary_tests = module.execution_contract_tests(task, task.observation.seed, sidecars.contract_tests)
        assembly = module.assemble_bts_task_request(
            task,
            self.root,
            contract_tests=primary_tests,
            baseline_sidecar=sidecars.baseline_sidecar,
            resolution_policy_path=sidecars.policy_sidecar,
            substrate=self.substrate,
        )
        request = getattr(assembly, "request", None)
        ranking = getattr(assembly, "candidate_ranking", None)
        if not isinstance(request, BTSPipelineRequest):
            raise PipelineAssemblyError("pipeline_cli assembly.request must be BTSPipelineRequest")
        if not isinstance(ranking, tuple) or not all(isinstance(item, CandidateIdentity) for item in ranking):
            raise PipelineAssemblyError("pipeline_cli assembly.candidate_ranking must be CandidateIdentity tuple")
        license_value = getattr(assembly, "classified_license", None)
        examples = getattr(assembly, "relocated_examples", ())
        probes = getattr(assembly, "adaptation_probes", ())
        ranking_unranked = getattr(assembly, "ranking_unranked", False)
        if license_value is not None and not isinstance(license_value, str):
            raise PipelineAssemblyError("pipeline_cli assembly.classified_license must be text or None")
        if not isinstance(examples, tuple) or not all(isinstance(item, str) for item in examples):
            raise PipelineAssemblyError("pipeline_cli assembly.relocated_examples must be string tuple")
        if not isinstance(probes, tuple) or not all(isinstance(item, AdaptationProbeObs) for item in probes):
            raise PipelineAssemblyError("pipeline_cli assembly.adaptation_probes must be AdaptationProbeObs tuple")
        if not isinstance(ranking_unranked, bool):
            raise PipelineAssemblyError("pipeline_cli assembly.ranking_unranked must be bool")
        try:
            primary_result = run_bts_pipeline(request)
        finally:
            close = getattr(assembly, "close", None)
            if callable(close):
                close()
        # t6 executes each explicitly pinned donor into a sibling recipient
        # namespace.  The shared recipient root is conceptual at this request
        # seam: ``transplant.<task>.<owner_repo>`` avoids module collisions, so
        # no conflict record is required for these disjoint modules.
        composition_runs: list[tuple[CandidateIdentity, BTSPipelineResult]] = [(task.observation.seed, primary_result)]
        for identity in task.observation.execution_candidates:
            if identity == task.observation.seed:
                continue
            extra_tests = module.execution_contract_tests(task, identity, sidecars.contract_tests)
            extra = module.assemble_bts_task_request(
                task,
                self.root,
                contract_tests=extra_tests,
                baseline_sidecar=sidecars.baseline_sidecar,
                resolution_policy_path=sidecars.policy_sidecar,
                substrate=self.substrate,
                execution_identity=identity,
            )
            if not isinstance(getattr(extra, "request", None), BTSPipelineRequest):
                raise PipelineAssemblyError("pipeline_cli assembly.request must be BTSPipelineRequest")
            try:
                composition_runs.append((identity, run_bts_pipeline(extra.request)))
            finally:
                close = getattr(extra, "close", None)
                if callable(close):
                    close()
        if task.task_id == "three-repo-combine":
            return coexisting_recipient_three_runs_observation(
                task,
                ranking,
                tuple(composition_runs),
                task_digest=self.task_digests[task.task_id] if task.task_id in self.task_digests else task.digest(),
                classified_license=license_value,
                relocated_examples=examples,
                adaptation_probes=probes,
                ranking_unranked=ranking_unranked,
            )
        return from_pipeline_result(
            task,
            ranking,
            primary_result,
            task_digest=self.task_digests[task.task_id] if task.task_id in self.task_digests else task.digest(),
            classified_license=license_value,
            relocated_examples=examples,
            adaptation_probes=probes,
            ranking_unranked=ranking_unranked,
            normalize_staging_test_paths=True,
        )


def _atomic_write(path: Path, data: bytes) -> None:
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.tmp-", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        if os.name != "nt":
            directory = os.open(path.parent, os.O_RDONLY)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
    finally:
        temporary.unlink(missing_ok=True)


def write_run(out: Path, data: bytes) -> Path:
    if out.exists() and (out.is_symlink() or not out.is_dir() or any(out.iterdir())):
        raise OutputConflictError("output directory must be new or empty")
    out.mkdir(parents=True, exist_ok=True)
    destination = out / "bts-eval-run-v1.json"
    _atomic_write(destination, data)
    return destination


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="run the six pinned BTS v1 agent tasks")
    parser.add_argument("--tasks", type=Path, help="published BTS task-manifest directory")
    parser.add_argument("--root", type=Path, help="verified donor-shelf root")
    parser.add_argument("--out", type=Path, help="empty destination directory for canonical run JSON")
    parser.add_argument("--substrate-nsjail-sha", help="measured sha256:<hex> of /usr/bin/nsjail")
    parser.add_argument("--substrate-rootfs-digest", help="measured sha256:<hex> canonical rootfs tree digest")
    parser.add_argument("--nsjail-version", help="measured nsjail version text")
    parser.add_argument("--nsjail-build-identity", help="measured sha256:<hex> nsjail build identity")
    parser.add_argument("--config-schema-digest", help="sha256:<hex> containment policy-schema digest")
    parser.add_argument("--rootfs-source", type=Path, help="prepared rootfs directory whose digest was measured")
    parser.add_argument("--dry-run", action="store_true", help="emit only the deterministic materialization plan")
    return parser


def _error(message: str) -> NoReturn:
    raise BTSDriverError(message)


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    tasks = load_tasks(args.tasks)
    plan = build_plan(tasks)
    if args.dry_run:
        print(plan.to_json())
        return 0
    if args.root is None or args.out is None:
        _error("--root and --out are required unless --dry-run is used")
    values = (
        args.substrate_nsjail_sha,
        args.substrate_rootfs_digest,
        args.nsjail_version,
        args.nsjail_build_identity,
        args.config_schema_digest,
    )
    if args.rootfs_source is None or not all(isinstance(item, str) and item for item in values):
        raise BTSError(
            BTSRejectReason.REJECT_HARD_GATE_FAILED,
            "non-dry BTS task runs require measured containment substrate pins",
            detail_code="pipeline_cli_task_substrate_pins_v1",
        )
    # A missing or malformed published sidecar must not fetch/open donor bytes.
    sidecars = {
        task.task_id: discover_task_sidecars(args.tasks or task_directory(), task)
        for task in tasks
    }
    module = _pipeline_cli()
    substrate_type = getattr(module, "BTSSubstratePins", None)
    if substrate_type is None:
        raise PipelineCliRequiredError("requires pipeline_cli.BTSSubstratePins")
    substrate = substrate_type(
        args.substrate_nsjail_sha,
        args.nsjail_version,
        args.nsjail_build_identity,
        args.config_schema_digest,
        args.rootfs_source,
        args.substrate_rootfs_digest,
    )
    materialize_donor_pins(args.root, plan)
    task_digests = {task.task_id: task.digest() for task in tasks}
    run = BTSEvalBenchmark().execute(combined_manifest(tasks), _PipelineTaskRunner(args.root, sidecars, substrate, task_digests))
    write_run(args.out, run.to_json().encode("utf-8"))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except BTSDriverError as exc:
        raise SystemExit(f"run_bts_tasks: {exc}") from exc
