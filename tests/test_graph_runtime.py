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


def test_nested_path_shim_import_is_interpreter_infrastructure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Issue audit 2026-08-23 P1(a): interpreter-internal path shims are not
    environment imports.

    On CPython 3.12.3-era builds ``pathlib`` (and import hooks such as pytest's
    assertion rewriting) lazily imports ``ntpath`` on POSIX from inside import
    machinery.  A shim imported by another module's import — the only shape the
    interpreter itself produces — is classified STDLIB infrastructure instead
    of false-rejecting as an undeclared environment import, even when the
    policy manifest does not declare it.
    """

    module = "runtime_fixture_shim_trigger"
    tmp_path.joinpath(f"{module}.py").write_text(
        "import ntpath\nVALUE = ntpath.__name__\n", encoding="utf-8"
    )
    monkeypatch.syspath_prepend(str(tmp_path))
    _forget(module)
    # Load the shim before the window: the interpreter-internal shape is a
    # nested cache-hit re-import (pathlib on 3.12.3-era builds re-fires
    # ``import ntpath`` on every PurePath construction), not a fresh load.
    import ntpath  # noqa: F401 - preload outside the recorded window

    def imports() -> None:
        __import__(module)

    try:
        report = record_imports(imports, _policy(module))
    finally:
        _forget(module)

    shim_events = [
        event
        for event in report.events
        if event.detail_code == "runtime_path_shim_v1"
    ]
    assert {event.classification for event in report.events} == {
        RuntimeImportClassification.BTS_MEMBER,
        RuntimeImportClassification.STDLIB,
    }
    # At least one shim event fires (the fixture module body import); builds
    # whose import machinery lazily imports the shim again (CPython 3.12.3-era
    # pathlib inside pytest's rewrite hook) may contribute more, each with its
    # own source provenance digest.
    assert shim_events
    import leitir.graph.runtime as runtime_module

    for shim in shim_events:
        assert shim.classification is RuntimeImportClassification.STDLIB
        assert shim.module_identity_digest == runtime_module._identity_digest("ntpath")
        assert shim.manifest_binding_digest == runtime_module._identity_digest(
            "runtime-path-shim-v1:ntpath"
        )
    # The evidence records the real interpreter shim bytes: the actual file
    # digest on source-shim builds, or the pinned interpreter build digest on
    # frozen-shim builds.
    import ntpath as real_ntpath

    if shim_events[0].loader_kind is runtime_module.RuntimeLoaderKind.SOURCE:
        assert shim_events[0].loaded_bytes_digest == runtime_module._loaded_bytes_digest(
            real_ntpath,
            runtime_module.RuntimeLoaderKind.SOURCE,
            "sha256:" + "0" * 64,
        )
    else:
        assert shim_events[0].loader_kind is runtime_module.RuntimeLoaderKind.FROZEN
        assert shim_events[0].loaded_bytes_digest == _digest("interpreter")


def test_direct_path_shim_import_stays_terminal(monkeypatch: pytest.MonkeyPatch) -> None:
    """A top-level shim import by the observed code is still undeclared.

    Only imports nested inside another in-flight import are infrastructure;
    observed code importing ``ntpath`` directly still fails closed when the
    policy does not declare it.
    """

    def imports() -> None:
        __import__("ntpath")

    with pytest.raises(BTSError) as raised:
        record_imports(imports, _policy())
    assert raised.value.reason is BTSRejectReason.REJECT_UNRESOLVED_EDGE
    assert raised.value.evidence.detail_code == "runtime_unknown_import_v1"


def test_shadowed_path_shim_stays_terminal(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A path shim shadowed on ``sys.path`` never authorizes itself.

    The infrastructure classification is origin-pinned to the running
    interpreter's own path-module directory; an ``ntpath.py`` planted earlier
    on ``sys.path`` keeps the fail-closed UNKNOWN verdict.  The shadow is
    installed as a loaded module with a source spec pointing at the planted
    file — exactly the ``sys.modules`` state a successful ``sys.path`` shadow
    leaves behind — because driving the real import machinery through a
    freshly-loading shadowed shim recurses inside pytest's assertion-rewrite
    hook on 3.12.3-era builds (an environmental pathology independent of the
    recorder).
    """

    import importlib.util

    module = "runtime_fixture_shim_shadow_trigger"
    fake_path = tmp_path / "ntpath.py"
    fake_path.write_text("VALUE = 1\n", encoding="utf-8")
    tmp_path.joinpath(f"{module}.py").write_text(
        "import ntpath\nVALUE = ntpath.VALUE\n", encoding="utf-8"
    )
    monkeypatch.syspath_prepend(str(tmp_path))
    _forget(module)
    saved = sys.modules.get("ntpath")
    spec = importlib.util.spec_from_file_location("ntpath", fake_path)
    assert spec is not None and spec.loader is not None
    fake = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(fake)
    sys.modules["ntpath"] = fake

    def imports() -> None:
        __import__(module)

    try:
        with pytest.raises(BTSError) as raised:
            record_imports(imports, _policy(module))
    finally:
        _forget(module)
        if saved is not None:
            sys.modules["ntpath"] = saved
        else:
            sys.modules.pop("ntpath", None)
    assert raised.value.reason is BTSRejectReason.REJECT_UNRESOLVED_EDGE
    assert raised.value.evidence.detail_code == "runtime_unknown_import_v1"


def test_recorder_lock_is_released_when_the_inventory_digest_fails(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Issue #205 C-1/AC-1/SP-1: no stranded process-global recorder lock.

    An exception between the lock acquire and the try whose finally releases
    it used to strand ``_ACTIVE_LOCK`` process-globally, turning one transient
    failure into ``runtime_recorder_concurrency_v1`` for every later recorder.
    The acquire now sits adjacent to its try, so any failure in between —
    here, the initial module-inventory digest — still releases the lock.
    """

    from leitir.graph import runtime as runtime_module

    def failing_digest() -> str:
        raise OSError("inventory digest failed")

    monkeypatch.setattr(runtime_module, "_module_inventory_digest", failing_digest)
    with pytest.raises(OSError, match="inventory digest failed"):
        record_imports(lambda: None, _policy())

    monkeypatch.undo()
    report = record_imports(lambda: __import__("errno"), _policy())
    assert report.initial_module_inventory_digest
