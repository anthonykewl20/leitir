from __future__ import annotations

import hashlib
import os
import subprocess
import sys
from dataclasses import replace

from leitir.bts_errors import BTSError, BTSRejectReason
from leitir.graph.model import Edge, EdgeKind, EdgeProvenance, NodeId, NodeKind, NodeOrigin, SourceRef
from leitir.probes import (
    PinnedProbe,
    ProbeExecutionRequest,
    ProbeExecutionResult,
    ProbeOutcome,
    ProbeRuntimeEvidence,
    ProbeSet,
    ProbeStatus,
    run_probes,
)
from leitir.relocate import ModuleMap, MountAuthorization, Relocation

_BTS_DIGEST = "sha256:" + "1" * 64
_RELOCATION_DIGEST = "sha256:" + "2" * 64
_POLICY_DIGEST = "sha256:" + "3" * 64
_REVIEW_DIGEST = "sha256:" + "4" * 64


def _digest(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def _source(path: str, line: int = 1) -> SourceRef:
    return SourceRef("owner/repo", "a" * 40, path, "b" * 40, line, 0, line, 8)


def _edge(name: str = "contract") -> Edge:
    production = NodeId(NodeOrigin.DONOR, NodeKind.FUNCTION, "donor.mod", "subject", "donor/mod.py:1")
    test = NodeId(NodeOrigin.TEST, NodeKind.TEST, "donor.tests", name, f"tests/test_mod.py:{name}")
    return Edge(
        EdgeKind.TESTED_BY,
        production,
        test,
        EdgeProvenance(_source("tests/test_mod.py"), None, "PinnedProbe", "reviewed_probe_catalog_v1"),
    )


def _relocation() -> Relocation:
    rerun = tuple(
        sorted(
            (
                MountAuthorization("staging-v1/manifests", True, False),
                MountAuthorization("staging-v1/probes", True, False),
                MountAuthorization("staging-v1/src", True, False),
            )
        )
    )
    return Relocation(
        "leitir-bts-relocation-v1",
        _BTS_DIGEST,
        ModuleMap.from_pairs(("donor.mod", "transplant.core")),
        (),
        (),
        rerun,
        _RELOCATION_DIGEST,
    )


def _probe(edge: Edge, *, source: bytes = b"assert subject() == 3\n", probe_id: str = "returns-three") -> PinnedProbe:
    return PinnedProbe.pin(probe_id, edge, f"{probe_id}.py", source, ProbeOutcome.PASS, _REVIEW_DIGEST)


def _set(*probes: PinnedProbe, edges: tuple[Edge, ...] | None = None) -> ProbeSet:
    catalog = tuple(probe.edge for probe in probes) if edges is None else edges
    seed = probes[0].edge.source if probes else NodeId(
        NodeOrigin.DONOR,
        NodeKind.FUNCTION,
        "donor.mod",
        "subject",
        "donor/mod.py:1",
    )
    return ProbeSet.pin(
        bts_digest=_BTS_DIGEST,
        seed=seed,
        bts_members=(seed,),
        catalog_edges=catalog,
        probes=probes,
    )


class StubExecutionPolicy:
    execution_policy_digest = _POLICY_DIGEST

    def __init__(self, outcomes: tuple[ProbeOutcome, ...] = ()) -> None:
        self.outcomes = outcomes
        self.requests: list[ProbeExecutionRequest] = []

    def execute_probe(self, request: ProbeExecutionRequest, relocation: Relocation) -> ProbeExecutionResult:
        assert relocation.bts_digest == request.bts_digest
        self.requests.append(request)
        index = len(self.requests) - 1
        observed = self.outcomes[index] if index < len(self.outcomes) else ProbeOutcome.PASS
        receipt = _digest(f"fresh-child-{index}".encode())
        runtime = ProbeRuntimeEvidence(_digest(f"runtime-{index}".encode()), True, False)
        return ProbeExecutionResult(True, observed, True, True, receipt, runtime)


def test_pinned_probes_run_in_distinct_fresh_children_and_report() -> None:
    first_edge = _edge("contract_a")
    second_edge = _edge("contract_b")
    probe_set = _set(_probe(first_edge, probe_id="a"), _probe(second_edge, probe_id="b"))
    policy = StubExecutionPolicy()

    report = run_probes(probe_set, _relocation(), execution_policy=policy)

    assert report.status is ProbeStatus.COMPLETE
    assert report.report_digest is not None
    assert len(report.outcomes) == 2
    assert [request.sequence for request in policy.requests] == [0, 1]
    assert len({outcome.execution_receipt_digest for outcome in report.outcomes}) == 2


def test_probe_failure_is_an_independent_noncompensating_reject() -> None:
    first_edge = _edge("contract_a")
    second_edge = _edge("contract_b")
    probe_set = _set(_probe(first_edge, probe_id="a"), _probe(second_edge, probe_id="b"))

    report = run_probes(
        probe_set,
        _relocation(),
        execution_policy=StubExecutionPolicy((ProbeOutcome.FAIL, ProbeOutcome.PASS)),
    )

    assert report.status is ProbeStatus.REJECT
    assert len(report.outcomes) == 2
    assert [item.reason for item in report.blockers] == [BTSRejectReason.REJECT_SEMANTIC_DEGRADATION]


def test_probe_set_is_required_and_empty_requires_derivably_no_applicable_edge() -> None:
    policy = StubExecutionPolicy()
    missing = run_probes(None, _relocation(), execution_policy=policy)
    assert missing.status is ProbeStatus.REJECT
    assert missing.blockers[0].detail_code == "probe_set_required_v1"

    explicit_empty = _set(edges=())
    accepted = run_probes(explicit_empty, _relocation(), execution_policy=policy)
    assert accepted.status is ProbeStatus.COMPLETE
    assert accepted.outcomes == ()

    edge = _edge()
    missing_required = _set(edges=(edge,))
    rejected = run_probes(missing_required, _relocation(), execution_policy=policy)
    assert rejected.status is ProbeStatus.REJECT
    assert rejected.blockers[0].detail_code == "probe_input_integrity_v1"


def test_probe_source_is_content_pinned_and_changes_set_digest() -> None:
    edge = _edge()
    original_probe = _probe(edge)
    changed_probe = _probe(edge, source=b"assert subject() == 4\n")
    assert _set(original_probe).probe_set_digest != _set(changed_probe).probe_set_digest

    tampered_probe = replace(original_probe, source_bytes=b"assert True\n")
    tampered_set = replace(_set(original_probe), probes=(tampered_probe,))
    report = run_probes(tampered_set, _relocation(), execution_policy=StubExecutionPolicy())
    assert report.status is ProbeStatus.REJECT
    assert report.blockers[0].detail_code == "probe_input_integrity_v1"


def test_observed_donor_import_rejects_even_when_probe_passes() -> None:
    class DonorPolicy(StubExecutionPolicy):
        def execute_probe(self, request: ProbeExecutionRequest, relocation: Relocation) -> ProbeExecutionResult:
            result = super().execute_probe(request, relocation)
            return replace(result, runtime=ProbeRuntimeEvidence(_digest(b"donor-runtime"), True, True))

    report = run_probes(_set(_probe(_edge())), _relocation(), execution_policy=DonorPolicy())
    assert report.status is ProbeStatus.REJECT
    assert report.blockers[0].reason is BTSRejectReason.REJECT_DONOR_IMPORT_OBSERVED


def test_probe_receipt_attestations_are_independent_fail_closed_blockers() -> None:
    class UnattestedPolicy(StubExecutionPolicy):
        def execute_probe(self, request: ProbeExecutionRequest, relocation: Relocation) -> ProbeExecutionResult:
            result = super().execute_probe(request, relocation)
            return replace(
                result,
                fresh_child_attested=False,
                donor_absent_attested=False,
                runtime=ProbeRuntimeEvidence(_digest(b"incomplete-runtime"), False, False),
            )

    report = run_probes(_set(_probe(_edge())), _relocation(), execution_policy=UnattestedPolicy())

    assert report.status is ProbeStatus.REJECT
    assert [(item.reason, item.detail_code) for item in report.blockers] == [
        (BTSRejectReason.REJECT_EXECUTION_THREAT, "probe_donor_absence_v1"),
        (BTSRejectReason.REJECT_HARD_GATE_FAILED, "probe_fresh_child_v1"),
        (BTSRejectReason.REJECT_HARD_GATE_FAILED, "probe_runtime_recorder_v1"),
    ]


def test_probe_policy_rejection_becomes_bounded_abort() -> None:
    class RejectingPolicy(StubExecutionPolicy):
        def execute_probe(self, request: ProbeExecutionRequest, relocation: Relocation) -> ProbeExecutionResult:
            raise BTSError(BTSRejectReason.REJECT_DONOR_IMPORT_OBSERVED, "donor import")

    report = run_probes(_set(_probe(_edge())), _relocation(), execution_policy=RejectingPolicy())

    assert report.status is ProbeStatus.ABORT
    assert report.abort is not None
    assert report.abort.reason is BTSRejectReason.REJECT_DONOR_IMPORT_OBSERVED
    assert report.abort.detail_category == "probe_donor_import_observed"
    assert report.abort.completed_probes == 0


def test_probe_relocation_rejects_donor_present_mount() -> None:
    relocation = _relocation()
    mounts = (*relocation.rerun_mounts, MountAuthorization("donor", True, True))

    report = run_probes(
        _set(_probe(_edge())),
        replace(relocation, rerun_mounts=tuple(sorted(mounts))),
        execution_policy=StubExecutionPolicy(),
    )

    assert report.status is ProbeStatus.REJECT
    assert report.blockers[0].detail_code == "probe_input_integrity_v1"


def test_probe_set_rejects_tampered_applicability_digest() -> None:
    probe_set = _set(_probe(_edge()))

    report = run_probes(
        replace(probe_set, applicability_digest=_digest(b"forged-applicability")),
        _relocation(),
        execution_policy=StubExecutionPolicy(),
    )

    assert report.status is ProbeStatus.REJECT
    assert report.blockers[0].detail_code == "probe_input_integrity_v1"


def test_operational_abort_is_bounded_and_nonauthorizing() -> None:
    class AbortPolicy(StubExecutionPolicy):
        def execute_probe(self, request: ProbeExecutionRequest, relocation: Relocation) -> ProbeExecutionResult:
            return ProbeExecutionResult(
                False,
                None,
                True,
                True,
                None,
                None,
                BTSRejectReason.REJECT_EXECUTION_THREAT,
                "wall_time_limit",
            )

    report = run_probes(_set(_probe(_edge())), _relocation(), execution_policy=AbortPolicy())
    assert report.status is ProbeStatus.ABORT
    assert report.report_digest is None
    assert report.abort is not None
    assert report.abort.reason is BTSRejectReason.REJECT_EXECUTION_THREAT
    assert len(report.to_bytes()) < 1024


def test_probe_report_is_pythonhashseed_independent() -> None:
    script = r'''
from tests.test_probes import StubExecutionPolicy, _edge, _probe, _relocation, _set
from leitir.probes import run_probes
print(run_probes(_set(_probe(_edge())), _relocation(), execution_policy=StubExecutionPolicy()).to_json(), end="")
'''
    outputs = []
    for seed in ("0", "1", "42"):
        environment = os.environ.copy()
        environment["PYTHONHASHSEED"] = seed
        environment["PYTHONPATH"] = os.pathsep.join(("src", "."))
        outputs.append(subprocess.check_output([sys.executable, "-c", script], env=environment))
    assert outputs[0] == outputs[1] == outputs[2]
