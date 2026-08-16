"""E4b's ratified N-donor, empty-project milestone exit gate.

The five offline variants are committed Leitir-authored fixture donors in the
same narrow trusted-fixture exception documented by E4a.  External donor bytes
remain gated on both live/donor opt-ins and the release-pinned nsjail job.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from dataclasses import replace
from pathlib import Path

import pytest

import leitir.rerun as rerun_module
from leitir.bts import BTSStatus, compute_bts
from leitir.bts_exit_gate import ExitCorpus, ExitCorpusCase, _run_case, run_exit_gate
from leitir.bts_pipeline import BTSPipelineRequest, BTSPipelineResult, run_bts_pipeline
from leitir.probes import ProbeSet
from leitir.relocate import relocate_tests
from leitir.rerun import ContractBaselineEvidence, ValidationStatus
from leitir.rerun import TestOutcome as Outcome
from tests.test_bts_skeleton import (
    BASELINE_OUTCOMES,
    FIXTURE,
    PASS_IDS,
    REPO_ROOT,
    TrustedFixtureExecution,
    _digest,
    _request,
    _rerun_policy,
)


def _prepared_request(root: Path, *, failing_baseline: bool = False) -> BTSPipelineRequest:
    request = _request(root)
    static = compute_bts(request.snapshot, request.seed, request.graph, request.budget, request.resolution_policy)
    assert static.status is BTSStatus.COMPLETE and static.bts is not None
    probes = ProbeSet.pin(
        bts_digest=static.bts.bts_digest,
        seed=request.seed,
        bts_members=tuple(member.node for member in static.bts.members),
        catalog_edges=(),
        probes=(),
    )
    if not failing_baseline:
        return replace(request, probe_set=probes)
    outcomes = tuple(
        sorted(
            replace(item, outcome=Outcome.FAIL, detail_digest=_digest((item.canonical_test_id + "fail").encode()))
            if item.canonical_test_id == PASS_IDS[1]
            else item
            for item in BASELINE_OUTCOMES
        )
    )
    baseline = ContractBaselineEvidence.create(
        outcomes,
        baseline_mount_plan_digest=request.baseline.baseline_mount_plan_digest,
        baseline_execution_policy_digest=request.baseline.baseline_execution_policy_digest,
    )
    return replace(request, baseline=baseline, probe_set=probes)


class TrustedCorpusPipeline:
    """Runs each reviewed fixture in a real child with its donor path removed."""

    def __init__(self, *, break_donor: str | None = None) -> None:
        self.break_donor = break_donor
        self.ran: list[str] = []

    def __call__(self, request: BTSPipelineRequest) -> BTSPipelineResult:
        donor = request.snapshot.source_root.name
        self.ran.append(donor)
        static = compute_bts(request.snapshot, request.seed, request.graph, request.budget, request.resolution_policy)
        assert static.status is BTSStatus.COMPLETE and static.bts is not None
        relocation = relocate_tests(
            static,
            module_map=request.module_map,
            source_files=request.source_files,
            tests=request.contract_tests,
        )
        request = replace(request, rerun_execution_policy=_rerun_policy(relocation))
        execution = TrustedFixtureExecution(relocation, request.snapshot.source_root, remove_helper=donor == self.break_donor)
        original_prepare = rerun_module.prepare_execution
        original_run = rerun_module.run_contained
        try:
            rerun_module.prepare_execution = lambda containment: object()  # type: ignore[assignment]
            rerun_module.run_contained = lambda plan, argv: execution.run()  # type: ignore[assignment]
            return run_bts_pipeline(request)
        finally:
            rerun_module.prepare_execution = original_prepare
            rerun_module.run_contained = original_run


def _fixture_roots(parent: Path, count: int = 5) -> tuple[Path, ...]:
    roots = []
    for number in range(count):
        root = parent / f"donor-{number}"
        shutil.copytree(FIXTURE, root)
        # Content-pin each authored fixture variant without changing behavior.
        policy = root / "skeleton_donor" / "policy.py"
        policy.write_bytes(policy.read_bytes() + f"# E4b fixture donor {number}\n".encode())
        roots.append(root)
    return tuple(roots)


def _corpus(
    roots: tuple[Path, ...],
    *,
    failing_baseline: int | None = None,
    ratified_digest: str | None = None,
) -> ExitCorpus:
    cases = []
    for number, root in enumerate(roots):
        if number == failing_baseline:
            test = root / "test_contract.py"
            test.write_text(test.read_text().replace("== 5", "== 999"))
        request = _prepared_request(root, failing_baseline=number == failing_baseline)
        cases.append(
            ExitCorpusCase.pin(
                f"leitir-fixture-{number}",
                f"leitir-authored://tests/fixtures/bts-e4b/donor-{number}@v1",
                _digest(f"independent-review-{number}".encode()),
                request,
            )
        )
    pinned = tuple(cases)
    computed = ExitCorpus.compute_manifest_digest("leitir-maintainers", "v0.1.2", pinned)
    return ExitCorpus.pin(
        "leitir-maintainers",
        "v0.1.2",
        pinned,
        ratified_manifest_digest=computed if ratified_digest is None else ratified_digest,
    )


def test_five_donor_exit_corpus_passes_every_non_compensating_gate(tmp_path: Path) -> None:
    corpus = _corpus(_fixture_roots(tmp_path))
    pipeline = TrustedCorpusPipeline()

    report = run_exit_gate(corpus, pipeline)

    assert report.status is ValidationStatus.COMPLETE
    assert report.authority_digest_matches
    assert len(report.donors) == 5
    assert pipeline.ran == [f"donor-{number}" for number in range(5)]
    assert all(
        donor.complete_bts
        and donor.exact_rerun_parity
        and donor.donor_ban_proved
        and donor.no_observed_donor_import
        and donor.probes_complete
        and donor.zero_failure_baseline
        for donor in report.donors
    )


def test_exit_gate_is_an_and_and_still_runs_every_donor(tmp_path: Path) -> None:
    corpus = _corpus(_fixture_roots(tmp_path))
    pipeline = TrustedCorpusPipeline(break_donor="donor-2")

    report = run_exit_gate(corpus, pipeline)

    assert report.status is ValidationStatus.REJECT
    assert [item.status for item in report.donors].count(ValidationStatus.REJECT) == 1
    assert pipeline.ran == [f"donor-{number}" for number in range(5)]
    rejected = next(item for item in report.donors if item.status is ValidationStatus.REJECT)
    expected = report.donors[0].expected_outcome_vector
    expected_counts = report.donors[0].expected_counts
    assert expected is not None
    assert expected_counts is not None
    assert rejected.expected_outcome_vector == expected
    assert rejected.expected_counts == expected_counts
    assert rejected.recorded_outcome_vector is not None
    assert rejected.recorded_counts is not None


def test_exit_gate_rejects_nonzero_failure_baseline_even_with_exact_parity(tmp_path: Path) -> None:
    corpus = _corpus(_fixture_roots(tmp_path), failing_baseline=3)

    report = run_exit_gate(corpus, TrustedCorpusPipeline())

    failed = report.donors[3]
    assert failed.exact_rerun_parity
    assert not failed.zero_failure_baseline
    assert failed.status is ValidationStatus.REJECT
    assert report.status is ValidationStatus.REJECT


def test_exit_gate_ignores_executor_specific_outcome_evidence_for_parity(tmp_path: Path) -> None:
    case = _corpus(_fixture_roots(tmp_path)).cases[0]
    trusted = TrustedCorpusPipeline()

    def pipeline(request: BTSPipelineRequest) -> BTSPipelineResult:
        result = trusted(request)
        assert result.bts.bts is not None
        assert isinstance(result.rerun, rerun_module.RerunReport)
        outcomes = tuple(
            replace(
                item,
                detail_category="independent_rerun_evidence_v1",
                detail_digest=_digest((item.canonical_test_id + item.outcome.value + "rerun").encode()),
            )
            for item in result.rerun.outcomes
        )
        rerun = rerun_module._report(
            status=ValidationStatus.COMPLETE,
            reason=None,
            details=(),
            artifact=result.bts.bts,
            relocation=result.relocation,
            baseline=request.baseline,
            policy=request.rerun_execution_policy,
            outcomes=outcomes,
            runtime_digest=result.rerun.runtime_observation_digest,
        )
        return replace(result, rerun=rerun)

    report = _run_case(case, pipeline)

    assert report.exact_rerun_parity
    assert report.status is ValidationStatus.COMPLETE


def test_additive_expansion_changes_digest_and_old_ratification_rejects_swap(tmp_path: Path) -> None:
    roots = _fixture_roots(tmp_path, count=6)
    original = _corpus(roots[:5])
    expanded = _corpus(roots, ratified_digest=original.ratified_manifest_digest)

    assert expanded.corpus_manifest_digest != original.corpus_manifest_digest
    report = run_exit_gate(expanded, TrustedCorpusPipeline())
    assert not report.authority_digest_matches
    assert report.status is ValidationStatus.REJECT
    assert len(report.donors) == 6


def test_exit_corpus_requires_at_least_five_donors(tmp_path: Path) -> None:
    roots = _fixture_roots(tmp_path, count=4)
    requests = tuple(_prepared_request(root) for root in roots)
    cases = tuple(
        ExitCorpusCase.pin(f"case-{number}", f"fixture://{number}", _digest(f"review-{number}".encode()), request)
        for number, request in enumerate(requests)
    )
    digest = ExitCorpus.compute_manifest_digest("leitir-maintainers", "v0.1.2", cases)
    with pytest.raises(ValueError, match="at least 5"):
        ExitCorpus.pin("leitir-maintainers", "v0.1.2", cases, ratified_manifest_digest=digest)


def test_gate_report_is_pythonhashseed_independent() -> None:
    script = r'''
import tempfile
from pathlib import Path
from tests.test_bts_e4b import TrustedCorpusPipeline, _corpus, _fixture_roots
from leitir.bts_exit_gate import run_exit_gate
with tempfile.TemporaryDirectory() as value:
    corpus = _corpus(_fixture_roots(Path(value)))
    print(run_exit_gate(corpus, TrustedCorpusPipeline()).to_bytes().hex())
'''
    outputs = []
    for seed in ("0", "1", "42"):
        environment = dict(
            os.environ,
            PYTHONHASHSEED=seed,
            PYTHONPATH=os.pathsep.join((str((REPO_ROOT / "src").resolve()), str(REPO_ROOT.resolve()))),
        )
        outputs.append(subprocess.check_output((sys.executable, "-c", script), env=environment))
    assert outputs[0] == outputs[1] == outputs[2]


@pytest.mark.skipif(
    os.environ.get("LEITIR_ENABLE_LIVE_E2E") != "1"
    or os.environ.get("LEITIR_ENABLE_DONOR_EXECUTION") != "1"
    or shutil.which("nsjail") is None,
    reason="real E4b donors require live opt-in, donor opt-in, and nsjail",
)
def test_live_ratified_external_corpus_requires_release_artifacts() -> None:
    pytest.skip("the release-pinned donor manifest, nsjail rootfs, and runner are supplied by the containment job")
