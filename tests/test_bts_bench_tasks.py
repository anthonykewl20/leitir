"""Publication-target and anti-gaming tests for the BTS reference fixture."""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import pytest

from leitir.bts_bench import (
    AdaptationProbeObs,
    BTSEvalBenchmark,
    BTSEvalRun,
    BTSEvalTask,
    BTSTaskObservation,
    CandidateIdentity,
    CandidateJudgment,
    MemberObs,
    SeedSpan,
    TaskExecutionFailure,
    _normalize_staging_test_path,
    load_manifest,
)
from leitir.bts_errors import BTSError
from leitir.exit_corpus import load_corpus_manifest
from leitir.materialize import manifest_digest_fields, target_path
from leitir.pipeline_cli import (
    BTSSubstratePins,
    BTSTaskRequestAssembly,
    _seed_source_identity_matches,
    _task_baseline_from_sidecar,
    _test_functions,
    assemble_bts_task_request,
)
from leitir.relocate import ContractTest, ModuleMap, SourceFile, relocate_tests
from leitir.rerun import canonical_test_id
from leitir.treehash import SAMPLED, compute_materialized_tree_hash
from tests.test_relocate import _bts, _relocate
from tools.export_bts_eval import export, load_run, metrics_markdown
from tools.run_bts_tasks import (
    _ContinuingTaskRunner,
    _PipelineTaskRunner,
    build_plan,
    combined_manifest,
    discover_task_sidecars,
    load_tasks,
    validate_donor_pins,
    validate_task_snapshot_pins,
    write_run,
)

ROOT = Path(__file__).resolve().parents[1]
REFERENCE_MANIFEST = ROOT / "benchmarks" / "bts-v1" / "tasks" / "reference-synthetic-v1.json"
# Regenerate with _reference_run().digest() after an intentional fixture change.
PINNED_RUN_DIGEST = "d6a6b4f29dd86fc277a9c7b9a9fb0725ad1fdca9882e704f09143173dc0bb196"
TASK_DIRECTORY = ROOT / "benchmarks" / "bts-v1" / "tasks"
RECEIPTS = TASK_DIRECTORY / "RECEIPTS.json"
GOLD_REVIEW_RECORD = ROOT / "benchmarks" / "bts-v1" / "gold-review-record-v1.md"
TASK_FILENAMES = (
    "async-retry-backoff.json",
    "binary-wire-decode.json",
    "lru-ttl-decisions.json",
    "three-repo-combine.json",
    "url-normalization-compare.json",
    "worker-shutdown-predicate.json",
)
TASK_BASELINE_COUNTS = {
    "async-retry-backoff": (9, 0, 0),
    "binary-wire-decode": (11, 0, 0),
    "lru-ttl-decisions": (6, 0, 0),
    "three-repo-combine": (9, 0, 0),
    "url-normalization-compare": (9, 0, 0),
    "worker-shutdown-predicate": (3, 0, 0),
}
PINNED_TASK_PLAN_SHA256 = "e89e9b3c074657fee906b89a09404367e3fdebc4001d06ff66271d71e0fc8e2c"


class GoldDerivedSyntheticRunner:
    """A deterministic observation whose expected evidence comes from the gold."""

    def run(self, task: BTSEvalTask) -> BTSTaskObservation:
        gold = task.gold
        qrels = tuple(sorted(gold.candidate_qrels, key=lambda item: item.identity.sort_key))
        seed = gold.seed_span.identity if gold.seed_span is not None else qrels[0].identity
        members = [MemberObs(seed.symbol, seed, "include")]
        for helper in sorted(gold.required_helpers):
            members.append(MemberObs(helper, replace(seed, symbol=helper), "include"))
        return BTSTaskObservation(
            task.task_id,
            task.digest(),
            tuple(item.identity for item in qrels[:1]),
            tuple(members),
            tuple(sorted(gold.required_tests)),
            tuple(sorted(gold.required_examples)),
            "complete",
            gold.expected_counts,
            gold.expected_outcome_vector,
            gold.expected_baseline_digest,
            False,
            gold.expected_license,
            tuple(AdaptationProbeObs(node, True) for node in sorted(gold.expected_adaptations)),
            tuple(sorted(gold.expected_probe_ids)),
            len(gold.expected_probe_ids),
            len(gold.expected_probe_ids),
        )


def _reference_run() -> BTSEvalRun:
    return BTSEvalBenchmark().execute(load_manifest(REFERENCE_MANIFEST), GoldDerivedSyntheticRunner())


def test_reference_synthetic_manifest_is_valid() -> None:
    manifest = load_manifest(REFERENCE_MANIFEST)
    assert manifest.benchmark_id == "bts-reference-synthetic-v1"
    assert tuple(task.task_id for task in manifest.tasks) == ("reference-synthetic-v1",)


def test_real_agent_task_manifests_are_complete_and_internally_consistent() -> None:
    tasks = load_tasks(TASK_DIRECTORY)

    assert tuple(task.task_id for task in tasks) == tuple(sorted(TASK_BASELINE_COUNTS))
    assert tuple(path.name for path in sorted(TASK_DIRECTORY.glob("*.json")) if path.name != "RECEIPTS.json") == tuple(
        sorted((*TASK_FILENAMES, "reference-synthetic-v1.json"))
    )
    for task in tasks:
        assert task.gold.expected_counts == TASK_BASELINE_COUNTS[task.task_id]
        assert sum(item.grade == 2 for item in task.gold.candidate_qrels) == 1
        assert task.gold.seed_span is not None
        assert any(item.identity == task.gold.seed_span.identity and item.grade == 2 for item in task.gold.candidate_qrels)
        assert all(len(item.identity.blob_sha) == 40 for item in task.gold.candidate_qrels)
        assert all(set(item.identity.blob_sha) <= set("0123456789abcdef") for item in task.gold.candidate_qrels)


def test_real_task_baseline_sidecars_are_canonical_and_match_manifest_baselines() -> None:
    required = {
        "contract_test_count", "expected_pass", "expected_fail", "expected_skip",
        "selected_test_ids", "runner_convention",
    }
    for task in load_tasks(TASK_DIRECTORY):
        sidecar = TASK_DIRECTORY / task.task_id / "baseline.json"
        raw = json.loads(sidecar.read_text(encoding="utf-8"))
        assert set(raw) == required
        assert sidecar.read_bytes() == (
            json.dumps(raw, allow_nan=False, ensure_ascii=False, separators=(",", ":"), sort_keys=True) + "\n"
        ).encode("utf-8")
        assert raw["contract_test_count"] == sum(task.gold.expected_counts or ())
        assert (raw["expected_pass"], raw["expected_fail"], raw["expected_skip"]) == task.gold.expected_counts
        assert raw["selected_test_ids"] == list(task.gold.expected_selected_test_ids or ())
        assert raw["selected_test_ids"] == sorted(raw["selected_test_ids"])
        assert isinstance(raw["runner_convention"], str) and raw["runner_convention"]


def test_url_task_span_sidecars_are_canonical_and_receipted() -> None:
    receipts = json.loads(RECEIPTS.read_text(encoding="utf-8"))["seed_span_receipts"]
    for task_id in ("three-repo-combine", "url-normalization-compare"):
        path = TASK_DIRECTORY / task_id / "span.json"
        data = json.loads(path.read_text(encoding="utf-8"))
        assert data == {"end_line": 27, "start_line": 1}
        assert path.read_bytes() == b'{"end_line":27,"start_line":1}\n'
        assert receipts[task_id] == "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()


def test_canonical_test_id_consistency_matrix_for_tasks_and_exit_corpus() -> None:
    """Every offline baseline, sidecar, and runner frame uses filename IDs."""

    for task in load_tasks(TASK_DIRECTORY):
        sidecars = discover_task_sidecars(TASK_DIRECTORY, task)
        sidecar_ids = tuple(sorted(
            canonical_test_id(test.path, function)
            for test in sidecars.contract_tests
            for function in _test_functions(test.content)
        ))
        baseline = json.loads(sidecars.baseline_sidecar.read_text(encoding="utf-8"))
        # Baseline assembly and the contained runner both project the same
        # sidecar path/function pair; neither sees staging or Python modules.
        baseline_ids = tuple(baseline["selected_test_ids"])
        rerun_frame_ids = tuple(sorted(
            canonical_test_id(Path(test.path).name, function)
            for test in sidecars.contract_tests
            for function in _test_functions(test.content)
        ))
        assert baseline_ids == sidecar_ids == rerun_frame_ids

    corpus_path = ROOT / "benchmarks" / "exit-corpus" / "corpus-v1.1.json"
    corpus = load_corpus_manifest(corpus_path)
    runnable = corpus["runnable"]
    assert isinstance(runnable, dict)
    cases = runnable["per_case"]
    assert isinstance(cases, list) and len(cases) == 5
    for case in cases:
        assert isinstance(case, dict)
        tests = case["contract_tests"]
        assert isinstance(tests, list)
        sidecar_ids: list[str] = []
        for test in tests:
            assert isinstance(test, dict)
            path = ROOT / "benchmarks" / "exit-corpus" / test["path"]
            source = path.read_bytes()
            sidecar_ids.extend(canonical_test_id(str(test["path"]), function) for function in _test_functions(source))
        baseline_ids = tuple(sorted(sidecar_ids))
        rerun_frame_ids = tuple(sorted(
            canonical_test_id(identifier.partition("::")[0], identifier.split("::")[1])
            for identifier in baseline_ids
        ))
        assert tuple(sorted(sidecar_ids)) == baseline_ids == rerun_frame_ids


def test_staging_normalization_preserves_real_relocation_contract_prefix() -> None:
    relocation = relocate_tests(
        _bts(b"def f():\n    return 3\n"),
        module_map=ModuleMap.from_pairs(("donor.mod", "transplant.core")),
        source_files=(SourceFile("donor/mod.py", b"def f():\n    return 3\n"),),
        tests=(ContractTest("contract_tests/test_contract.py", b"from donor.mod import f\n\ndef test_f():\n    assert f() == 3\n", "test_contract"),),
    )
    emitted = next(item.path for item in relocation.files if item.path.endswith("contract_tests/test_contract.py") and "rewritten" in item.path)
    assert emitted == "staging-v1/tests/rewritten/contract_tests/test_contract.py"
    assert _normalize_staging_test_path(emitted) == "contract_tests/test_contract.py"


def test_task_sidecars_assemble_one_nonexecuting_driver_request(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    task = next(item for item in load_tasks(TASK_DIRECTORY) if item.task_id == "async-retry-backoff")
    identity = CandidateIdentity("owner/donor", "a" * 40, "package/policy.py", "d3400504c93fd42b1fd39d180e08940d2443bf63", "package.policy.normalize_contract", 5, 6)
    task = replace(
        task,
        gold=replace(
            task.gold,
            candidate_qrels=tuple(replace(item, identity=identity) if item.grade == 2 else item for item in task.gold.candidate_qrels),
            seed_span=SeedSpan(identity),
        ),
        observation=replace(task.observation, candidates=(identity,), execution_candidates=(identity,), seed=identity),
    )
    shelf = target_path(tmp_path, "owner", "donor", identity.commit_sha)
    shutil.copytree(ROOT / "tests" / "fixtures" / "bts_cli" / "donor", shelf)
    (shelf / "LICENSE").write_text("MIT License\nPermission is hereby granted, free of charge\n", encoding="utf-8")
    tree_hash, scope = compute_materialized_tree_hash(shelf)
    manifest = {
        "commit_sha": identity.commit_sha, "fetch_method": "codeload-tarball", "fetched_at": "2026-08-15T00:00:00Z",
        "host": "github.com", "owner": "owner", "repo": "donor", "repo_url": "https://github.com/owner/donor",
        "source": "git-commit", "parity": "exact", "spec": "github:owner/donor", "tag": None,
        "verified": True, "verified_at": "2026-08-15T00:00:00Z",
    }
    manifest.update(manifest_digest_fields(tree_hash, scope=scope))
    (shelf / "leitir-manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    sidecars = discover_task_sidecars(TASK_DIRECTORY, task)
    monkeypatch.setattr("leitir.pipeline_cli._require_substrate", lambda: None)

    assembly = assemble_bts_task_request(
        task,
        tmp_path,
        contract_tests=sidecars.contract_tests,
        baseline_sidecar=sidecars.baseline_sidecar,
        substrate=BTSSubstratePins("sha256:" + "1" * 64, "fixture", "sha256:" + "1" * 64, "sha256:" + "1" * 64, tmp_path, "sha256:" + "1" * 64),
    )

    assert assembly.request.contract_tests == sidecars.contract_tests
    assert assembly.request.baseline.selected_test_ids == task.gold.expected_selected_test_ids


def test_task_seed_source_identity_ignores_reviewed_span_widening() -> None:
    """The S4 enclosing span is evidence; the donor blob remains the seed ID."""

    identity = CandidateIdentity(
        "niksite/url-normalize", "9a9a3214c2b3bdab09ba7b19c8f9d22aa4cfee31",
        "url_normalize/normalize_fragment.py", "3111ed7c4e35e2a5f945c989ed1028a701a4c8f1",
        "url_normalize.normalize_fragment.normalize_fragment", 1, 27,
    )
    resolved = SimpleNamespace(source=SimpleNamespace(
        slug=identity.slug, commit_sha=identity.commit_sha, path=identity.path,
        blob_sha=identity.blob_sha, start_line=8, end_line=27,
    ))
    assert _seed_source_identity_matches(resolved, identity)


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="shared staging requires Linux fcntl locking")
def test_repeated_live_task_assembly_has_a_deterministic_mount_plan_digest(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """E1 staging roots are stable, so identical S2 authority bytes are stable."""

    task = next(item for item in load_tasks(TASK_DIRECTORY) if item.task_id == "async-retry-backoff")
    identity = CandidateIdentity("owner/donor", "a" * 40, "package/policy.py", "d3400504c93fd42b1fd39d180e08940d2443bf63", "package.policy.normalize_contract", 5, 6)
    task = replace(
        task,
        gold=replace(task.gold, candidate_qrels=tuple(replace(item, identity=identity) if item.grade == 2 else item for item in task.gold.candidate_qrels), seed_span=SeedSpan(identity)),
        observation=replace(task.observation, candidates=(identity,), execution_candidates=(identity,), seed=identity),
    )
    shelf = target_path(tmp_path, "owner", "donor", identity.commit_sha)
    shutil.copytree(ROOT / "tests" / "fixtures" / "bts_cli" / "donor", shelf)
    (shelf / "LICENSE").write_text("MIT License\nPermission is hereby granted, free of charge\n", encoding="utf-8")
    tree_hash, scope = compute_materialized_tree_hash(shelf)
    manifest = {"commit_sha": identity.commit_sha, "fetch_method": "codeload-tarball", "fetched_at": "2026-08-15T00:00:00Z", "host": "github.com", "owner": "owner", "repo": "donor", "repo_url": "https://github.com/owner/donor", "source": "git-commit", "parity": "exact", "spec": "github:owner/donor", "tag": None, "verified": True, "verified_at": "2026-08-15T00:00:00Z"}
    manifest.update(manifest_digest_fields(tree_hash, scope=scope))
    (shelf / "leitir-manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    sidecars = discover_task_sidecars(TASK_DIRECTORY, task)
    substrate = BTSSubstratePins("sha256:" + "1" * 64, "fixture", "sha256:" + "1" * 64, "sha256:" + "1" * 64, tmp_path, "sha256:" + "1" * 64)
    baseline = _task_baseline_from_sidecar(sidecars.baseline_sidecar, task)
    monkeypatch.setattr("leitir.pipeline_cli._require_substrate", lambda: None)
    monkeypatch.setattr("leitir.pipeline_cli.donor_execution_enabled", lambda: True)
    monkeypatch.setattr("leitir.pipeline_cli.record_baseline", lambda *args, **kwargs: baseline)
    monkeypatch.setattr("leitir.pipeline_cli._relocate_prepared", lambda *args, **kwargs: _relocate(b"def f():\n    return 3\n"))

    first = assemble_bts_task_request(task, tmp_path, contract_tests=sidecars.contract_tests, baseline_sidecar=sidecars.baseline_sidecar, resolution_policy_path=sidecars.policy_sidecar, substrate=substrate)
    second = assemble_bts_task_request(task, tmp_path, contract_tests=sidecars.contract_tests, baseline_sidecar=sidecars.baseline_sidecar, resolution_policy_path=sidecars.policy_sidecar, substrate=substrate)
    try:
        assert first.request.rerun_execution_policy.containment.mount_plan_digest == second.request.rerun_execution_policy.containment.mount_plan_digest
        assert first.to_bytes() == second.to_bytes()
    finally:
        first.close()
        second.close()


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="shared staging requires Linux fcntl locking")
def test_concurrent_live_task_assemblies_reuse_complete_stage(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Concurrent E1 assemblies share one verified content-addressed stage."""

    task = next(item for item in load_tasks(TASK_DIRECTORY) if item.task_id == "async-retry-backoff")
    identity = CandidateIdentity("owner/donor", "a" * 40, "package/policy.py", "d3400504c93fd42b1fd39d180e08940d2443bf63", "package.policy.normalize_contract", 5, 6)
    task = replace(
        task,
        gold=replace(task.gold, candidate_qrels=tuple(replace(item, identity=identity) if item.grade == 2 else item for item in task.gold.candidate_qrels), seed_span=SeedSpan(identity)),
        observation=replace(task.observation, candidates=(identity,), execution_candidates=(identity,), seed=identity),
    )
    shelf = target_path(tmp_path, "owner", "donor", identity.commit_sha)
    shutil.copytree(ROOT / "tests" / "fixtures" / "bts_cli" / "donor", shelf)
    (shelf / "LICENSE").write_text("MIT License\nPermission is hereby granted, free of charge\n", encoding="utf-8")
    tree_hash, scope = compute_materialized_tree_hash(shelf)
    manifest = {"commit_sha": identity.commit_sha, "fetch_method": "codeload-tarball", "fetched_at": "2026-08-15T00:00:00Z", "host": "github.com", "owner": "owner", "repo": "donor", "repo_url": "https://github.com/owner/donor", "source": "git-commit", "parity": "exact", "spec": "github:owner/donor", "tag": None, "verified": True, "verified_at": "2026-08-15T00:00:00Z"}
    manifest.update(manifest_digest_fields(tree_hash, scope=scope))
    (shelf / "leitir-manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    sidecars = discover_task_sidecars(TASK_DIRECTORY, task)
    substrate = BTSSubstratePins("sha256:" + "1" * 64, "fixture", "sha256:" + "1" * 64, "sha256:" + "1" * 64, tmp_path, "sha256:" + "1" * 64)
    baseline = _task_baseline_from_sidecar(sidecars.baseline_sidecar, task)
    monkeypatch.setattr("leitir.pipeline_cli._require_substrate", lambda: None)
    monkeypatch.setattr("leitir.pipeline_cli.donor_execution_enabled", lambda: True)
    monkeypatch.setattr("leitir.pipeline_cli.record_baseline", lambda *args, **kwargs: baseline)
    monkeypatch.setattr("leitir.pipeline_cli._relocate_prepared", lambda *args, **kwargs: _relocate(b"def f():\n    return 3\n"))

    def assemble() -> BTSTaskRequestAssembly:
        return assemble_bts_task_request(task, tmp_path, contract_tests=sidecars.contract_tests, baseline_sidecar=sidecars.baseline_sidecar, resolution_policy_path=sidecars.policy_sidecar, substrate=substrate)

    with ThreadPoolExecutor(max_workers=2) as executor:
        first, second = tuple(executor.map(lambda _unused: assemble(), range(2)))
    try:
        assert first.to_bytes() == second.to_bytes()
        assert first.staging == second.staging
        assert first.staging is not None
        assert first.request.precomputed_relocation is not None
        assert (first.staging / "COMPLETE").read_text(encoding="ascii") == first.request.precomputed_relocation.relocation_digest + "\n"
    finally:
        first.close()
        second.close()


def test_gold_review_receipts_bind_all_real_task_digests() -> None:
    receipts = json.loads(RECEIPTS.read_text(encoding="utf-8"))
    record = GOLD_REVIEW_RECORD.read_bytes()
    assert receipts["schema_version"] == "leitir-bts-gold-receipts-v1"
    assert receipts["record_sha256"] == "sha256:" + hashlib.sha256(record).hexdigest()
    task_receipts = receipts["task_receipts"]
    assert set(task_receipts) == set(TASK_BASELINE_COUNTS)
    for task in load_tasks(TASK_DIRECTORY):
        expected = hashlib.sha256(record + b"\n" + task.task_id.encode() + b"\n" + task.digest().encode()).hexdigest()
        assert task_receipts[task.task_id] == "sha256:" + expected


def test_url_gold_mutation_changes_digest_and_candidate_metric() -> None:
    task = next(item for item in load_tasks(TASK_DIRECTORY) if item.task_id == "url-normalization-compare")
    selected = next(item for item in task.gold.candidate_qrels if item.grade == 2)
    replacement = next(item for item in task.gold.candidate_qrels if item.grade == 1)
    altered = tuple(
        CandidateJudgment(item.identity, 2 if item.identity == replacement.identity else 1 if item.identity == selected.identity else item.grade)
        for item in task.gold.candidate_qrels
    )
    changed = replace(task, gold=replace(task.gold, candidate_qrels=altered))

    class OriginalGoldRunner(GoldDerivedSyntheticRunner):
        def run(self, current: BTSEvalTask) -> BTSTaskObservation:
            observation = super().run(current)
            return replace(observation, candidate_ranking=(selected.identity,))

    original_run = BTSEvalBenchmark().execute(combined_manifest((task,)), OriginalGoldRunner())
    altered_run = BTSEvalBenchmark().execute(combined_manifest((changed,)), OriginalGoldRunner())
    original_candidate = next(item for item in original_run.tasks[0].metrics if item.metric == "candidate_top1")
    altered_candidate = next(item for item in altered_run.tasks[0].metrics if item.metric == "candidate_top1")

    assert changed.digest() != task.digest()
    assert original_run.digest() != altered_run.digest()
    assert (original_candidate.numerator, altered_candidate.numerator) == (1, 0)


def test_task_driver_dry_run_plan_is_pinned_and_runner_seam_is_fail_closed(tmp_path: Path) -> None:
    tasks = load_tasks(TASK_DIRECTORY)
    plan = build_plan(tasks)
    assert hashlib.sha256(plan.to_json().encode("utf-8")).hexdigest() == PINNED_TASK_PLAN_SHA256
    with pytest.raises(BTSError):
        validate_donor_pins(tmp_path, plan)
    with pytest.raises(BTSError) as caught:
        _PipelineTaskRunner(tmp_path).run(tasks[0])
    assert caught.value.evidence.detail_code == "pipeline_cli_task_substrate_pins_v1"

    command = (sys.executable, "tools/run_bts_tasks.py", "--dry-run")
    first = subprocess.check_output(command, cwd=ROOT, env=dict(os.environ, PYTHONPATH=os.pathsep.join(("src", "."))), text=True)
    second = subprocess.check_output(command, cwd=ROOT, env=dict(os.environ, PYTHONHASHSEED="42", PYTHONPATH=os.pathsep.join(("src", "."))), text=True)
    assert first == second
    assert first == plan.to_json() + "\n"
    assert hashlib.sha256(first.rstrip("\n").encode("utf-8")).hexdigest() == PINNED_TASK_PLAN_SHA256
    assert json.loads(first)["schema_version"] == "leitir-bts-task-plan-v1"
    assert "timestamp" not in first
    three_repo = next(item for item in json.loads(first)["tasks"] if item["task_id"] == "three-repo-combine")
    assert len(three_repo["requests"]) == 3


def test_candidate_pin_validation_is_structural_but_selected_snapshot_stays_exact(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """A sampled candidate can be ranked but can never reach transplant execution."""

    task = next(item for item in load_tasks(TASK_DIRECTORY) if item.task_id == "async-retry-backoff")
    identity = CandidateIdentity("owner/donor", "a" * 40, "package/policy.py", "d3400504c93fd42b1fd39d180e08940d2443bf63", "package.policy.normalize_contract", 5, 6)
    task = replace(task, observation=replace(task.observation, candidates=(identity,), execution_candidates=(identity,), seed=identity))
    shelf = target_path(tmp_path, "owner", "donor", identity.commit_sha)
    shutil.copytree(ROOT / "tests" / "fixtures" / "bts_cli" / "donor", shelf)
    (shelf / "additional.py").write_text("pass\n", encoding="utf-8")
    monkeypatch.setattr("leitir.treehash.MAX_FILES", 1)
    tree_hash, scope = compute_materialized_tree_hash(shelf)
    assert scope == SAMPLED
    manifest = {
        "commit_sha": identity.commit_sha, "fetch_method": "codeload-tarball", "fetched_at": "2026-08-15T00:00:00Z",
        "host": "github.com", "owner": "owner", "repo": "donor", "repo_url": "https://github.com/owner/donor",
        "source": "git-commit", "parity": "unknown", "spec": "github:owner/donor", "tag": None,
        "verified": "sampled", "verified_at": "2026-08-15T00:00:00Z", "verification_notes": [],
    }
    manifest.update(manifest_digest_fields(tree_hash, scope=scope))
    (shelf / "leitir-manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    plan = build_plan((task,))

    validate_donor_pins(tmp_path, plan)
    with pytest.raises(BTSError) as caught:
        validate_task_snapshot_pins(tmp_path, task)
    assert caught.value.evidence.detail_code == "bts_cli_parity_v1"


def test_sampled_selected_donor_records_typed_na_and_other_tasks_continue(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    task = next(item for item in load_tasks(TASK_DIRECTORY) if item.task_id == "async-retry-backoff")
    identity = CandidateIdentity("owner/donor", "a" * 40, "package/policy.py", "d3400504c93fd42b1fd39d180e08940d2443bf63", "package.policy.normalize_contract", 5, 6)
    task = replace(task, observation=replace(task.observation, candidates=(identity,), execution_candidates=(identity,), seed=identity))
    shelf = target_path(tmp_path, "owner", "donor", identity.commit_sha)
    shutil.copytree(ROOT / "tests" / "fixtures" / "bts_cli" / "donor", shelf)
    tree_hash, scope = compute_materialized_tree_hash(shelf)
    manifest = {
        "commit_sha": identity.commit_sha, "fetch_method": "codeload-tarball", "fetched_at": "2026-08-15T00:00:00Z",
        "host": "github.com", "owner": "owner", "repo": "donor", "repo_url": "https://github.com/owner/donor",
        "source": "git-commit", "parity": "unknown", "spec": "github:owner/donor", "tag": None,
        "verified": "sampled", "verified_at": "2026-08-15T00:00:00Z", "verification_notes": [],
    }
    manifest.update(manifest_digest_fields(tree_hash, scope=scope))
    (shelf / "leitir-manifest.json").write_text(json.dumps(manifest), encoding="utf-8")

    class DiscoveryOnlyModule:
        @staticmethod
        def _rank_materialized_candidates(current: BTSEvalTask, _root: Path):
            assert current == task
            return (identity,), "MIT", False

    monkeypatch.setattr("tools.run_bts_tasks._pipeline_cli", lambda: DiscoveryOnlyModule)
    failed = _PipelineTaskRunner(tmp_path, substrate=object()).run(task)
    assert failed.candidate_ranking == (identity,)
    assert failed.classified_license == "MIT"
    assert "integration_success" in failed.not_applicable_metrics
    assert failed.not_applicable_reason == f"snapshot_validation:reject_provenance_mismatch:bts_cli_parity_v1:owner/donor@{identity.commit_sha}"
    assert failed.execution_failure is not None
    assert failed.execution_failure.to_dict() == {
        "detail_code": "bts_cli_parity_v1",
        "identities": [f"owner/donor@{identity.commit_sha}"],
        "message": "donor parity is not exact",
        "reason": "reject_provenance_mismatch",
    }

    other = replace(task, task_id="other-task")

    class ContinuingRunner:
        def run(self, current: BTSEvalTask) -> BTSTaskObservation:
            return failed if current.task_id == task.task_id else GoldDerivedSyntheticRunner().run(current)

    run = BTSEvalBenchmark().execute(combined_manifest((task, other)), ContinuingRunner())
    failed_run = next(item for item in run.tasks if item.task_id == task.task_id)
    integration = next(item for item in failed_run.metrics if item.metric == "integration_success")
    candidate = next(item for item in failed_run.metrics if item.metric == "candidate_top1")
    assert failed_run.execution_failure == failed.execution_failure
    assert integration.score_bps is None
    assert integration.exclusions[0].reason == failed.not_applicable_reason
    assert candidate.denominator == 1
    assert tuple(item.task_id for item in run.tasks) == (task.task_id, other.task_id)
    artifact = json.loads(run.to_json())
    failed_artifact = next(item for item in artifact["tasks"] if item["task_id"] == task.task_id)
    assert failed_artifact["execution_failure"] == failed.execution_failure.to_dict()


def test_driver_records_unexpected_task_failure_and_continues_all_six_tasks(tmp_path: Path) -> None:
    tasks = load_tasks(TASK_DIRECTORY)
    failing_task = "lru-ttl-decisions"

    class FailingRunner(GoldDerivedSyntheticRunner):
        def run(self, task: BTSEvalTask) -> BTSTaskObservation:
            if task.task_id == failing_task:
                raise RuntimeError("simulated pipeline assembly failure")
            return super().run(task)

    manifest = combined_manifest(tasks)
    first = BTSEvalBenchmark().execute(manifest, _ContinuingTaskRunner(FailingRunner()))
    second = BTSEvalBenchmark().execute(manifest, _ContinuingTaskRunner(FailingRunner()))

    assert tuple(item.task_id for item in first.tasks) == tuple(item.task_id for item in tasks)
    failed = next(item for item in first.tasks if item.task_id == failing_task)
    assert failed.execution_failure is not None
    assert failed.execution_failure.to_dict() == {
        "detail_code": "bts_task_execution_error_v1",
        "identities": [
            f"{identity.slug}@{identity.commit_sha}"
            for identity in tasks[2].observation.execution_candidates
        ],
        "message": "BTS task execution failed",
        "reason": "reject_hard_gate_failed",
    }
    assert all(record.score_bps is None for record in failed.metrics)
    assert first.digest() == second.digest()
    artifact = write_run(tmp_path / "run", first.to_json().encode("utf-8"))
    artifact_tasks = json.loads(artifact.read_text(encoding="utf-8"))["tasks"]
    assert [item["task_id"] for item in artifact_tasks] == [item.task_id for item in tasks]
    assert sum("execution_failure" in item for item in artifact_tasks) == 1


def test_metrics_markdown_lists_execution_failures() -> None:
    run = _reference_run()
    failed_task = replace(
        run.tasks[0],
        execution_failure=TaskExecutionFailure(
            "reject_hard_gate_failed",
            "bts_task_execution_error_v1",
            "BTS task execution failed",
            ("owner/donor@" + "a" * 40,),
        ),
    )
    failed_run = replace(run, tasks=(failed_task,), timing=None)

    metrics = metrics_markdown(failed_run)

    assert "## Execution failures" in metrics
    assert "| reference-synthetic-v1 | owner/donor@" + "a" * 40 + " | reject_hard_gate_failed | bts_task_execution_error_v1 |" in metrics


def test_task_sidecar_discovery_rejects_missing_sidecars_before_materialization(tmp_path: Path) -> None:
    task = load_tasks(TASK_DIRECTORY)[0]
    task_dir = tmp_path / task.task_id
    shutil.copytree(TASK_DIRECTORY / task.task_id / "contract_tests", task_dir / "contract_tests")

    with pytest.raises(BTSError) as caught:
        discover_task_sidecars(tmp_path, task)

    assert caught.value.evidence.detail_code == "pipeline_cli_task_sidecars_v1"


def test_task_sidecar_discovery_normalizes_backslash_layout_inputs(monkeypatch: pytest.MonkeyPatch) -> None:
    task = load_tasks(TASK_DIRECTORY)[0]
    assert task.observation is not None
    windows_spelling = tuple(path.replace("/", "\\") for path in task.observation.contract_tests)
    windows_task = replace(task, observation=replace(task.observation, contract_tests=windows_spelling))
    monkeypatch.delattr(os, "O_NOFOLLOW", raising=False)

    sidecars = discover_task_sidecars(TASK_DIRECTORY, windows_task)

    assert tuple(test.path for test in sidecars.contract_tests) == task.observation.contract_tests


def test_pinned_gold_binds_the_reference_run_and_metrics() -> None:
    manifest = load_manifest(REFERENCE_MANIFEST)
    run = BTSEvalBenchmark().execute(manifest, GoldDerivedSyntheticRunner())
    assert run.digest() == PINNED_RUN_DIGEST

    task = manifest.tasks[0]
    altered_qrels = tuple(
        CandidateJudgment(item.identity, 2 if item.grade == 1 else item.grade) for item in task.gold.candidate_qrels
    )
    altered_task = replace(task, gold=replace(task.gold, candidate_qrels=altered_qrels))
    altered_manifest = replace(manifest, tasks=(altered_task,))
    altered_run = BTSEvalBenchmark().execute(altered_manifest, GoldDerivedSyntheticRunner())

    assert altered_run.digest() != run.digest()
    assert any(
        (before.metric, before.score_bps) != (after.metric, after.score_bps)
        for before, after in zip(run.aggregate.metrics, altered_run.aggregate.metrics, strict=True)
    )


def test_pinned_gold_digest_is_pythonhashseed_independent() -> None:
    script = """
from tests.test_bts_bench_tasks import _reference_run
print(_reference_run().digest())
"""
    outputs = []
    for seed in ("0", "1", "42"):
        environment = dict(os.environ, PYTHONHASHSEED=seed, PYTHONPATH=os.pathsep.join(("src", ".")))
        outputs.append(subprocess.check_output((sys.executable, "-c", script), cwd=ROOT, env=environment, text=True))
    assert outputs == [f"{PINNED_RUN_DIGEST}\n"] * 3


def test_export_writes_canonical_run_and_pinned_metrics(tmp_path: Path) -> None:
    run = _reference_run()
    canonical = run.to_json().encode("utf-8")
    input_path = tmp_path / "input-run.json"
    input_path.write_bytes(canonical)

    destination = export(input_path, tmp_path / "published")

    assert (destination / "run.json").read_bytes() == canonical
    metrics = (destination / "METRICS.md").read_text(encoding="utf-8")
    assert metrics == """# BTS evaluation metrics

- Run digest: `d6a6b4f29dd86fc277a9c7b9a9fb0725ad1fdca9882e704f09143173dc0bb196`
- Manifest digest: `055c6e9a8c0fa42139d636c7b13dab2dc70e8b836c0f5d7fcd62e4e87a28788d`
- Task count: 1

| Metric | Value | Status |
| --- | --- | --- |
| adaptation_integrity | 10000 bps (1/1) | applicable |
| candidate_top1 | 0 bps (0/1) | applicable |
| candidate_top10 | 0 bps (0/1) | applicable |
| candidate_top3 | 0 bps (0/1) | applicable |
| donor_import_free | 10000 bps (1/1) | applicable |
| example_recall | 10000 bps (1/1) | applicable |
| hallucinated_dependency_rate | 0 bps (0/2) | applicable |
| helper_recall | 10000 bps (1/1) | applicable |
| integration_success | 10000 bps (1/1) | applicable |
| license_accuracy | 10000 bps (1/1) | applicable |
| missing_dependency_rate | 0 bps (0/1) | applicable |
| probe_success | 10000 bps (1/1) | applicable |
| seed_symbol_exact | 10000 bps (1/1) | applicable |
| seed_symbol_line_overlap | 10000 bps (3/3) | applicable |
| test_recall | 10000 bps (1/1) | applicable |
| time_saved | — | excluded: advisory_timing_in_envelope (1) |
"""
    assert "generated-at" not in metrics.lower()


def test_export_rejects_digest_tampered_run(tmp_path: Path) -> None:
    run = _reference_run()
    raw = json.loads(run.to_json())
    assert isinstance(raw, dict)
    timing = raw["timing"]
    assert isinstance(timing, dict)
    timing["run_digest"] = "0" * 64
    input_path = tmp_path / "tampered-run.json"
    input_path.write_text(json.dumps(raw, sort_keys=True, separators=(",", ":")), encoding="utf-8")

    result = subprocess.run(
        (sys.executable, "tools/export_bts_eval.py", str(input_path), "--output-dir", str(tmp_path / "published")),
        cwd=ROOT,
        env=dict(os.environ, PYTHONPATH=os.pathsep.join(("src", "."))),
        text=True,
        capture_output=True,
        check=False,
    )

    assert result.returncode != 0
    assert "digest" in result.stderr.lower()


def test_export_rejects_input_larger_than_the_bounded_reader(tmp_path: Path, monkeypatch) -> None:
    input_path = tmp_path / "oversized.json"
    input_path.write_bytes(b"x" * 5)
    monkeypatch.setattr("tools.export_bts_eval.MAX_RUN_BYTES", 4)
    with pytest.raises(ValueError, match="maximum accepted size"):
        load_run(input_path)

    script = """
import sys
from pathlib import Path
import tools.export_bts_eval as exporter
exporter.MAX_RUN_BYTES = 4
sys.argv = ['export_bts_eval.py', sys.argv[1], '--output-dir', sys.argv[2]]
raise SystemExit(exporter.main())
"""
    result = subprocess.run(
        (sys.executable, "-c", script, str(input_path), str(tmp_path / "published")),
        cwd=ROOT,
        env=dict(os.environ, PYTHONPATH=os.pathsep.join(("src", "."))),
        text=True,
        capture_output=True,
        check=False,
    )
    assert result.returncode != 0
    assert "maximum accepted size" in result.stderr
