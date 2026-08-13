from __future__ import annotations

import hashlib
import os
import subprocess
import sys
from pathlib import Path

import pytest

from leitir.bts import (
    BTS,
    AnalysisInputs,
    BTSBudget,
    BTSDisposition,
    BTSReport,
    BTSResult,
    BTSStatus,
    BudgetCounters,
    MemberEvidence,
)
from leitir.bts_errors import BTSError, BTSRejectReason
from leitir.graph.model import EdgeKind, EdgeProvenance, NodeId, NodeKind, NodeOrigin, SourceRef, UnresolvedEdge
from leitir.graph.runtime import (
    RUNTIME_SCHEMA_VERSION,
    DonorAbsenceAuthority,
    RuntimeAugmentationMode,
    RuntimeEvidenceRole,
    RuntimeImportClassification,
    RuntimeImportPolicy,
    RuntimeLoaderKind,
    RuntimeModuleManifestEntry,
    augment_static_analysis,
    record_imports,
)


def _digest(value: str) -> str:
    return f"sha256:{hashlib.sha256(value.encode()).hexdigest()}"


def _source(module: str) -> SourceRef:
    return SourceRef("owner/repo", "a" * 40, f"{module}.py", "b" * 40, 1, 0, 1, 1)


def _bts(*modules: str) -> BTS:
    members = tuple(
        MemberEvidence(
            NodeId(NodeOrigin.DONOR, NodeKind.MODULE, module, module, f"{module}.py:1"),
            _source(module),
            _digest(f"span:{module}"),
            BTSDisposition.INCLUDE,
        )
        for module in modules
    )
    seed = NodeId(NodeOrigin.DONOR, NodeKind.FUNCTION, "seed", "seed.function", "seed.py:1")
    return BTS("leitir-bts-v1", seed, members, (), (), (), _digest("bts"), _digest("equivalent"))


def _policy(
    *members: str,
    donor_modules: tuple[str, ...] = ("forbidden_donor",),
    donor_roots: tuple[Path, ...] = (),
) -> RuntimeImportPolicy:
    interpreter = _digest("interpreter")
    stdlib = tuple(
        RuntimeModuleManifestEntry(
            module,
            RuntimeImportClassification.STDLIB,
            RuntimeLoaderKind.BUILTIN,
            interpreter,
            _digest(f"stdlib:{module}"),
        )
        for module in ("_io", "errno")
    )
    return RuntimeImportPolicy(
        RUNTIME_SCHEMA_VERSION,
        _bts(*members),
        stdlib,
        (),
        donor_modules,
        donor_roots,
        _digest("donor-tree"),
        _digest("relocated-tree"),
        _digest("tests-and-probes"),
        interpreter,
        _digest("stdlib-rootfs"),
        _digest("environment"),
        _digest("execution"),
        _digest("mounts"),
        32,
        64_000,
    )


def _write_module(root: Path, module: str) -> None:
    root.joinpath(f"{module}.py").write_text("VALUE = 1\n", encoding="utf-8")


def _forget(module: str) -> None:
    sys.modules.pop(module, None)


def test_records_bts_member_and_stdlib_as_diagnostic_only(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    module = "runtime_fixture_member"
    _write_module(tmp_path, module)
    monkeypatch.syspath_prepend(str(tmp_path))
    _forget(module)

    def imports() -> None:
        __import__(module)
        __import__("errno")

    try:
        report = record_imports(imports, _policy(module))
    finally:
        _forget(module)

    assert {event.classification for event in report.events} == {
        RuntimeImportClassification.BTS_MEMBER,
        RuntimeImportClassification.STDLIB,
    }
    assert report.evidence_role is RuntimeEvidenceRole.DIAGNOSTIC_ONLY
    assert report.trusted is False
    assert report.donor_absence_authority is DonorAbsenceAuthority.FILESYSTEM_MOUNT_BOUNDARY
    assert report.augmentation_mode is RuntimeAugmentationMode.ADDITIVE_FRESH_COMPUTE_BTS_ONLY
    assert b"runtime_fixture_member" not in report.to_bytes()


@pytest.mark.parametrize("caught", [False, True])
def test_observed_donor_import_is_terminal_even_when_caught(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    caught: bool,
) -> None:
    module = "forbidden_donor"
    _write_module(tmp_path, module)
    monkeypatch.syspath_prepend(str(tmp_path))
    _forget(module)

    def imports() -> None:
        if not caught:
            __import__(module)
            return
        try:
            __import__(module)
        except BTSError:
            pass

    try:
        with pytest.raises(BTSError) as raised:
            record_imports(imports, _policy(donor_roots=(tmp_path.absolute(),)))
    finally:
        _forget(module)
    assert raised.value.reason is BTSRejectReason.REJECT_DONOR_IMPORT_OBSERVED
    assert raised.value.evidence.detail_code == "runtime_donor_import_v1"


def test_unknown_import_is_terminal(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    module = "runtime_fixture_unknown"
    _write_module(tmp_path, module)
    monkeypatch.syspath_prepend(str(tmp_path))
    _forget(module)
    try:
        with pytest.raises(BTSError) as raised:
            record_imports(lambda: __import__(module), _policy())
    finally:
        _forget(module)
    assert raised.value.reason is BTSRejectReason.REJECT_UNRESOLVED_EDGE
    assert raised.value.evidence.detail_code == "runtime_unknown_import_v1"


def _static_reject() -> BTSResult:
    source = _source("seed")
    seed = NodeId(NodeOrigin.DONOR, NodeKind.FUNCTION, "seed", "seed.function", "seed.py:1")
    unresolved = UnresolvedEdge(
        EdgeKind.CALLS,
        seed,
        "receiver.dynamic()",
        EdgeProvenance(source, None, "Call", "unsupported_receiver_v1"),
        BTSRejectReason.REJECT_UNRESOLVED_EDGE,
        "receiver_dispatch_v1",
    )
    budget = BTSBudget(1, 1, 1, 1, 1, 1, 1, 0, 1, 1, 1, 1, 1)
    inputs = AnalysisInputs(
        seed,
        "owner/repo",
        "a" * 40,
        _digest("tree"),
        "git-tree-sha1-v1",
        "leitir-bts-graph-v1",
        _digest("graph"),
        "leitir-bts-walk-v1",
        budget,
        "policy",
        _digest("policy"),
        _digest("policy-envelope"),
        _digest("stdlib"),
        _digest("adapters"),
    )
    report = BTSReport(
        "leitir-bts-v1",
        BTSStatus.REJECT,
        inputs,
        (),
        (),
        (),
        (unresolved,),
        (unresolved,),
        (),
        BudgetCounters(),
        _digest("analysis"),
    )
    return BTSResult(BTSStatus.REJECT, report, None)


def test_runtime_augmentation_is_additive_and_cannot_resolve_static_edge() -> None:
    report = record_imports(lambda: __import__("errno"), _policy())
    static = _static_reject()
    augmentation = augment_static_analysis(static, report)

    assert augmentation.static_result is static
    assert augmentation.static_result.status is BTSStatus.REJECT
    assert augmentation.static_result.report.unresolved == static.report.unresolved
    assert augmentation.static_result.report.blockers == static.report.blockers
    assert augmentation.trigger.mode is RuntimeAugmentationMode.ADDITIVE_FRESH_COMPUTE_BTS_ONLY
    assert augmentation.trigger.retained_static_blocker_digests


_HASH_SEED_SCRIPT = r'''
import hashlib
from leitir.bts import BTS
from leitir.graph.model import NodeId, NodeKind, NodeOrigin
from leitir.graph.runtime import *
d = lambda value: "sha256:" + hashlib.sha256(value.encode()).hexdigest()
seed = NodeId(NodeOrigin.DONOR, NodeKind.FUNCTION, "seed", "seed.function", "seed.py:1")
bts = BTS("leitir-bts-v1", seed, (), (), (), (), d("bts"), d("equivalent"))
interpreter = d("interpreter")
entry = RuntimeModuleManifestEntry("errno", RuntimeImportClassification.STDLIB, RuntimeLoaderKind.BUILTIN, interpreter, d("errno"))
policy = RuntimeImportPolicy(RUNTIME_SCHEMA_VERSION, bts, (entry,), (), ("donor",), (), d("tree"), d("relocated"), d("tests"), interpreter, d("rootfs"), d("env"), d("execution"), d("mount"), 8, 64000)
sys.stdout.buffer.write(record_imports(lambda: __import__("errno"), policy).to_bytes())
'''


@pytest.mark.parametrize("seed", ["0", "1", "42"])
def test_observation_rendering_is_pythonhashseed_independent(seed: str) -> None:
    environment = dict(os.environ, PYTHONHASHSEED=seed, PYTHONPATH="src")
    run = subprocess.run(
        [sys.executable, "-c", "import sys\n" + _HASH_SEED_SCRIPT],
        cwd=Path(__file__).parents[1],
        env=environment,
        check=True,
        capture_output=True,
    )
    baseline_environment = dict(environment, PYTHONHASHSEED="0")
    baseline = subprocess.run(
        [sys.executable, "-c", "import sys\n" + _HASH_SEED_SCRIPT],
        cwd=Path(__file__).parents[1],
        env=baseline_environment,
        check=True,
        capture_output=True,
    )
    assert run.stdout == baseline.stdout
