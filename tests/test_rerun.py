from __future__ import annotations

import hashlib
import json
import os
import platform
import subprocess
import sys
from dataclasses import replace
from pathlib import Path

import pytest

from leitir.bts import BTS, BTSDisposition, MemberEvidence, RequiredFileEvidence, RequiredSymbolEvidence
from leitir.bts import _digest as _bts_digest
from leitir.bts_errors import BTSRejectReason, TransplantError
from leitir.exec_sandbox import (
    POLICY_SCHEMA,
    ContainmentPolicy,
    ExecutionResult,
    ReadOnlyMount,
    ValidationAbortEnvelope,
)
from leitir.graph.model import NodeId, NodeKind, NodeOrigin, SourceRef
from leitir.relocate import ContractTest, ModuleMap, Relocation, SourceFile, relocate_tests
from leitir.rerun import (
    RERUN_MOUNT_ROOT,
    RERUN_POLICY_SCHEMA_VERSION,
    RUNNER_FRAME_SCHEMA_VERSION,
    ContractBaselineEvidence,
    RerunExecutionPolicy,
    RerunReport,
    ValidationStatus,
    rerun_transplant,
)
from leitir.rerun import TestOutcome as Outcome
from leitir.rerun import TestOutcomeEvidence as OutcomeEvidence


def _digest(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _json_digest(value: object) -> str:
    data = (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n").encode()
    return _digest(data)


def _outcome(test_id: str, outcome: Outcome) -> OutcomeEvidence:
    return OutcomeEvidence(test_id, outcome, "runner_result_v1", _digest((test_id + outcome.value).encode()))


def _fixture() -> tuple[BTS, object]:
    source = b"def f():\n    return 3\n"
    node = NodeId(NodeOrigin.DONOR, NodeKind.FUNCTION, "donor.mod", "f", "donor/mod.py:1")
    reference = SourceRef("owner/repo", "1" * 40, "donor/mod.py", "2" * 40, 1, 0, 2, 12)
    member = MemberEvidence(node, reference, _digest(source[:-1]), BTSDisposition.INCLUDE)
    draft = BTS(
        "leitir-bts-v1",
        node,
        (member,),
        (),
        (RequiredFileEvidence(reference.path, reference.blob_sha, member.source_bytes_sha256),),
        (RequiredSymbolEvidence(node, reference),),
        "sha256:" + "3" * 64,
        "sha256:" + "4" * 64,
    )
    bts = replace(
        draft,
        member_equivalence_digest=_bts_digest(
            draft, omit=frozenset({"bts_digest", "member_equivalence_digest"})
        ),
    )
    relocation = relocate_tests(
        bts,
        module_map=ModuleMap.from_pairs(("donor.mod", "recipient.core")),
        source_files=(SourceFile("donor/mod.py", source),),
        tests=(ContractTest("test_contract.py", b"from donor.mod import f\n\ndef test_f():\n    assert f() == 3\n", "donor.tests.test_contract"),),
    )
    return bts, relocation


def _containment(relocation: Relocation, *, donor_mounted: bool = False) -> ContainmentPolicy:
    root_digest = _digest(b"rootfs")
    mounts = [ReadOnlyMount("/", "/pinned/rootfs", root_digest)]
    files = {item.path: item for item in relocation.files}
    for authorization in relocation.rerun_mounts:
        logical = authorization.logical_path
        mounts.append(ReadOnlyMount(f"{RERUN_MOUNT_ROOT}/{logical}", f"/relocated/{logical}", files[logical].sha256))
    if donor_mounted:
        mounts.append(ReadOnlyMount("/donor", "/snapshots/donor", _digest(b"donor")))
    ordered = tuple(sorted(mounts))
    mount_payload = {
        "readonly_mounts": [
            {"destination": item.destination, "source": item.source, "source_digest": item.source_digest}
            for item in ordered
        ],
        "rootfs_digest": root_digest,
        "scratch_dir": "/scratch",
        "writable_tmpfs": "/work",
        "writable_tmpfs_bytes": 1_048_576,
        "writable_tmpfs_inodes": 128,
    }
    return ContainmentPolicy(
        POLICY_SCHEMA,
        "/usr/bin/nsjail",
        _digest(b"nsjail"),
        "nsjail pinned",
        _digest(b"build"),
        _digest(b"schema"),
        platform.machine(),
        root_digest,
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


def _policy(relocation: Relocation, *, donor_mounted: bool = False) -> RerunExecutionPolicy:
    return RerunExecutionPolicy(
        RERUN_POLICY_SCHEMA_VERSION,
        _containment(relocation, donor_mounted=donor_mounted),
        ("/usr/bin/python3", "-S", "-s", "-P", "/harness/runner.py"),
        _digest(b"runner-closure"),
        _digest(b"baseline-policy"),
        ("/donor", "/snapshots/donor"),
    )


def _baseline(outcomes: tuple[OutcomeEvidence, ...]) -> ContractBaselineEvidence:
    return ContractBaselineEvidence.create(
        outcomes,
        baseline_mount_plan_digest=_digest(b"baseline-mount-plan"),
        baseline_execution_policy_digest=_digest(b"baseline-policy"),
    )


def _frame(outcomes: tuple[OutcomeEvidence, ...], *, donor: bool = False, recorder: bool = True, attestation: bool = True) -> bytes:
    startup_attestation = {
        "namespace_mismatch": True,
        "no_new_privs": True,
        "pid_namespace_init": True,
        "schema_version": "leitir-contained-startup-attestation-v1",
        "seccomp_mode": 2,
    }
    payload = {
        "containment_attestation": startup_attestation,
        "donor_import_observed": donor,
        "outcomes": [
            {
                "canonical_test_id": item.canonical_test_id,
                "detail_category": item.detail_category,
                "detail_digest": item.detail_digest,
                "outcome": item.outcome.value,
            }
            for item in outcomes
        ],
        "recorder_complete": recorder,
        "runtime_observation_digest": _digest(b"runtime-observation"),
        "schema_version": RUNNER_FRAME_SCHEMA_VERSION,
        "teardown_complete": True,
    }
    if not attestation:
        del payload["containment_attestation"]
        return (json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n").encode()
    return (
        json.dumps(startup_attestation, sort_keys=True, separators=(",", ":"))
        + "\n"
        + json.dumps(payload, sort_keys=True, separators=(",", ":"))
        + "\n"
    ).encode()


def _result(frame: bytes) -> ExecutionResult:
    return ExecutionResult(True, _digest(b"plan"), 0, frame, b"", _digest(frame), _digest(b""), _digest(b"result"), None)


def _run(monkeypatch: pytest.MonkeyPatch, rerun_outcomes: tuple[OutcomeEvidence, ...], baseline_outcomes: tuple[OutcomeEvidence, ...], **frame_options: bool):
    bts, relocation = _fixture()
    policy = _policy(relocation)
    monkeypatch.setattr("leitir.rerun.prepare_execution", lambda containment: object())
    monkeypatch.setattr("leitir.rerun.run_contained", lambda plan, argv: _result(_frame(rerun_outcomes, **frame_options)))
    return rerun_transplant(relocation, bts, _baseline(baseline_outcomes), execution_policy=policy)


def test_exact_count_ids_and_outcomes_complete(monkeypatch: pytest.MonkeyPatch) -> None:
    outcomes = (_outcome("tests/test_contract.py::test_f::-", Outcome.PASS),)
    report = _run(monkeypatch, outcomes, outcomes)
    assert isinstance(report, RerunReport)
    assert report.status is ValidationStatus.COMPLETE
    assert (report.counts.passed, report.counts.failed, report.counts.skipped) == (1, 0, 0)
    assert report.to_bytes() == report.to_bytes()


def test_missing_startup_containment_attestation_is_a_hard_gate_abort(monkeypatch: pytest.MonkeyPatch) -> None:
    outcomes = (_outcome("tests/test_contract.py::test_f::-", Outcome.PASS),)
    report = _run(monkeypatch, outcomes, outcomes, attestation=False)
    assert isinstance(report, ValidationAbortEnvelope)
    assert report.detail_category == "rerun_malformed_runner_frame_v1"


def test_count_delta_is_coverage_miscount(monkeypatch: pytest.MonkeyPatch) -> None:
    baseline = (_outcome("tests/t.py::test_a::-", Outcome.PASS),)
    report = _run(monkeypatch, (), baseline)
    assert isinstance(report, RerunReport)
    assert report.reason is BTSRejectReason.REJECT_COVERAGE_MISCOUNT


def test_same_id_transition_with_matching_counts_is_semantic_degradation(monkeypatch: pytest.MonkeyPatch) -> None:
    baseline = (
        _outcome("tests/t.py::test_a::-", Outcome.PASS),
        _outcome("tests/t.py::test_b::-", Outcome.FAIL),
    )
    rerun = (
        _outcome("tests/t.py::test_a::-", Outcome.FAIL),
        _outcome("tests/t.py::test_b::-", Outcome.PASS),
    )
    report = _run(monkeypatch, rerun, baseline)
    assert isinstance(report, RerunReport)
    assert report.reason is BTSRejectReason.REJECT_SEMANTIC_DEGRADATION


def test_runner_failure_is_hard_gate_abort(monkeypatch: pytest.MonkeyPatch) -> None:
    bts, relocation = _fixture()
    policy = _policy(relocation)
    monkeypatch.setattr("leitir.rerun.prepare_execution", lambda containment: object())
    abort = ValidationAbortEnvelope(
        "leitir-validation-abort-v1", "execution", "donor", BTSRejectReason.REJECT_HARD_GATE_FAILED,
        "child_crash", _digest(b"plan"), 0, 0,
    )
    failed = ExecutionResult(False, _digest(b"plan"), None, b"", b"", None, None, None, abort)
    monkeypatch.setattr("leitir.rerun.run_contained", lambda plan, argv: failed)
    result = rerun_transplant(relocation, bts, _baseline(()), execution_policy=policy)
    assert isinstance(result, ValidationAbortEnvelope)
    assert result.reason is BTSRejectReason.REJECT_HARD_GATE_FAILED


def test_observed_donor_import_is_terminal(monkeypatch: pytest.MonkeyPatch) -> None:
    outcomes = (_outcome("tests/t.py::test_a::-", Outcome.PASS),)
    report = _run(monkeypatch, outcomes, outcomes, donor=True)
    assert isinstance(report, RerunReport)
    assert report.reason is BTSRejectReason.REJECT_DONOR_IMPORT_OBSERVED


def test_donor_importable_mount_plan_is_terminal_without_launch(monkeypatch: pytest.MonkeyPatch) -> None:
    bts, relocation = _fixture()
    monkeypatch.setattr("leitir.rerun.prepare_execution", lambda containment: pytest.fail("must reject before launch"))
    with pytest.raises(TransplantError) as caught:
        rerun_transplant(relocation, bts, _baseline(()), execution_policy=_policy(relocation, donor_mounted=True))
    assert caught.value.reason is BTSRejectReason.REJECT_EXECUTION_THREAT
    assert caught.value.evidence.detail_code == "rerun_relocation_mount_missing_v1"


def test_rerun_rejects_mount_digest_not_bound_to_relocated_file(monkeypatch: pytest.MonkeyPatch) -> None:
    bts, relocation = _fixture()
    policy = _policy(relocation)
    target = next(mount for mount in policy.containment.readonly_mounts if mount.destination != "/")
    mounts = tuple(
        replace(mount, source_digest=_digest(b"wrong-relocated-bytes")) if mount == target else mount
        for mount in policy.containment.readonly_mounts
    )
    policy = replace(policy, containment=replace(policy.containment, readonly_mounts=mounts))
    monkeypatch.setattr("leitir.rerun.prepare_execution", lambda containment: pytest.fail("must reject before launch"))
    with pytest.raises(TransplantError) as caught:
        rerun_transplant(relocation, bts, _baseline(()), execution_policy=policy)
    assert caught.value.evidence.detail_code == "rerun_relocation_mount_missing_v1"


def test_rerun_rejects_extra_mount_even_when_all_relocated_files_are_present(monkeypatch: pytest.MonkeyPatch) -> None:
    bts, relocation = _fixture()
    policy = _policy(relocation)
    extra = ReadOnlyMount("/ambient-extra", "/host/ambient-extra", _digest(b"extra"))
    containment = replace(policy.containment, readonly_mounts=tuple(sorted((*policy.containment.readonly_mounts, extra))))
    monkeypatch.setattr("leitir.rerun.prepare_execution", lambda containment: pytest.fail("must reject before launch"))
    with pytest.raises(TransplantError) as caught:
        rerun_transplant(relocation, bts, _baseline(()), execution_policy=replace(policy, containment=containment))
    assert caught.value.evidence.detail_code == "rerun_relocation_mount_missing_v1"


def test_rerun_rejects_forged_relocation_digest_before_launch(monkeypatch: pytest.MonkeyPatch) -> None:
    bts, relocation = _fixture()
    forged = replace(relocation, relocation_digest=_digest(b"forged-relocation"))
    monkeypatch.setattr("leitir.rerun.prepare_execution", lambda containment: pytest.fail("must reject before launch"))
    with pytest.raises(TransplantError) as caught:
        rerun_transplant(forged, bts, _baseline(()), execution_policy=_policy(relocation))
    assert caught.value.evidence.detail_code == "rerun_relocation_digest_v1"


def test_rerun_rejects_forged_bare_bts_identity() -> None:
    bts, relocation = _fixture()
    forged = replace(bts, member_equivalence_digest="sha256:" + "f" * 64)
    with pytest.raises(TransplantError) as caught:
        rerun_transplant(relocation, forged, _baseline(()), execution_policy=_policy(relocation))
    assert caught.value.evidence.detail_code == "rerun_bts_identity_v1"


def test_recorder_failure_is_hard_gate_abort(monkeypatch: pytest.MonkeyPatch) -> None:
    result = _run(monkeypatch, (), (), recorder=False)
    assert isinstance(result, ValidationAbortEnvelope)
    assert result.reason is BTSRejectReason.REJECT_HARD_GATE_FAILED


def test_policy_rejects_isolated_mode() -> None:
    with pytest.raises(ValueError, match="isolated mode"):
        bts, relocation = _fixture()
        replace(_policy(relocation), runner_argv=("/usr/bin/python3", "-I", "/harness/runner.py"))


def test_baseline_digest_tamper_rejects() -> None:
    baseline = _baseline(())
    with pytest.raises(ValueError, match="baseline digest"):
        replace(baseline, baseline_digest=_digest(b"tampered"))


def test_report_is_pythonhashseed_independent() -> None:
    script = """
import runpy
import leitir.rerun as rerun
fixtures=runpy.run_path('tests/test_rerun.py')
outcomes=(fixtures['_outcome']('tests/t.py::test_a::-',rerun.TestOutcome.PASS),)
bts, relocation=fixtures['_fixture']()
policy=fixtures['_policy'](relocation)
rerun.prepare_execution=lambda containment: object()
rerun.run_contained=lambda plan, argv: fixtures['_result'](fixtures['_frame'](outcomes))
report=rerun.rerun_transplant(relocation,bts,fixtures['_baseline'](outcomes),execution_policy=policy)
assert isinstance(report,rerun.RerunReport)
print(report.to_json(),end='')
"""
    outputs = []
    root = Path(__file__).parents[1]
    for seed in ("0", "1", "42"):
        environment = dict(os.environ, PYTHONHASHSEED=seed, PYTHONPATH="src")
        outputs.append(subprocess.check_output((sys.executable, "-c", script), cwd=root, env=environment))
    assert outputs[0] == outputs[1] == outputs[2]


@pytest.mark.skipif(
    os.environ.get("LEITIR_ENABLE_DONOR_EXECUTION") != "1" or not Path("/usr/bin/nsjail").exists(),
    reason="live rerun requires exact donor opt-in and nsjail",
)
def test_live_rerun_requires_release_pinned_runner_and_rootfs() -> None:
    pytest.skip("release-pinned runner/rootfs artifact is not available in the source tree")
