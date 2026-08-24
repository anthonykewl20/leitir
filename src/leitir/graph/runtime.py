"""Bounded, diagnostic-only runtime import observations for BTS validation.

This module is deliberately **not a sandbox** and its reports are untrusted,
supplementary evidence.  Python-installed import machinery can be bypassed or
disabled by code executing in the same process; consequently, an import which
is not observed proves nothing.  The authoritative proof that donor bytes are
absent is the S2/E1 OS/filesystem mount boundary described by ADR-0009.

An observation is still useful in the fail-closed direction: an observed donor
or undeclared import is terminal.  A conforming report can only request a fresh
static ``compute_bts`` analysis.  It cannot add a BTS member, resolve an edge,
change a static status, or remove an ADR-0008 blocker.

One bounded class of imports is classified as interpreter infrastructure
rather than an environment import: the platform path-shim modules
(``genericpath``, ``ntpath``, ``posixpath``).  CPython may import these
lazily from inside import machinery — notably ``pathlib`` on 3.12.3-era
builds, whose ``PurePath.__init__`` imports :mod:`ntpath` on POSIX, and
import hooks such as pytest's assertion rewriting — at arbitrary points
during any in-flight import.  Such an import is authorized only when it is
nested inside another import (never a top-level import by the observed
code), the module is a member of ``sys.stdlib_module_names``, and the
loader is the interpreter's own frozen finder or the plain source loader
with bytes from the interpreter's own path-module directory.  Anything
else — a direct shim
import by observed code, or a shim shadowed on ``sys.path`` — keeps the
fail-closed UNKNOWN verdict.  See ADR-0009 section 7.
"""

from __future__ import annotations

import builtins
import hashlib
import importlib.util
import inspect
import json
import os
import sys
import threading
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, fields, is_dataclass, replace
from enum import Enum
from itertools import pairwise
from pathlib import Path
from types import ModuleType
from typing import TypeAlias

from leitir.bts import BTS, BTSResult, BTSStatus, MemberEvidence
from leitir.bts_errors import BTSError, BTSRejectReason

RUNTIME_SCHEMA_VERSION = "leitir-runtime-observation-v1"
_MAX_TEXT_BYTES = 512
_MAX_COUNTER = 1_000_000
_SHA256_LENGTH = 71
_ACTIVE_LOCK = threading.Lock()
# The interpreter's platform path shims: ``os.path`` is one of these on every
# supported platform, and CPython may import the pair (plus their shared
# ``genericpath`` dependency) lazily from inside import machinery — notably
# ``pathlib`` on 3.12.3-era builds and import hooks such as pytest's
# assertion rewriting.  Bounded infrastructure, never donor code.
_PATH_SHIM_MODULES = frozenset({"genericpath", "ntpath", "posixpath"})


class RuntimeImportClassification(str, Enum):  # noqa: UP042 - closed ADR schema
    BTS_MEMBER = "bts_member"
    STDLIB = "stdlib"
    DECLARED_EXTERNAL = "declared_external"
    DONOR = "donor"
    UNKNOWN = "unknown"


class RuntimeLoaderKind(str, Enum):  # noqa: UP042 - CPython loader contract
    BUILTIN = "BuiltinImporter"
    FROZEN = "FrozenImporter"
    EXTENSION = "ExtensionFileLoader"
    SOURCE = "SourceFileLoader"


class RuntimeImportProvenance(str, Enum):  # noqa: UP042 - closed ADR schema
    SOURCE_IMPORT_HOOK = "source_import_hook"
    CPYTHON_AUDIT_EVENT = "cpython_audit_event"


class RuntimeImportResult(str, Enum):  # noqa: UP042 - closed ADR schema
    SUCCESS = "success"
    ATTEMPTED = "attempted"


class RuntimeOriginRole(str, Enum):  # noqa: UP042 - closed ADR schema
    BTS_SOURCE = "bts_source"
    STDLIB_MANIFEST = "stdlib_manifest"
    EXTERNAL_MANIFEST = "external_manifest"
    DONOR_SOURCE = "donor_source"
    UNKNOWN = "unknown"


class RuntimeEvidenceRole(str, Enum):  # noqa: UP042 - closed ADR schema
    DIAGNOSTIC_ONLY = "diagnostic_only_untrusted"


class DonorAbsenceAuthority(str, Enum):  # noqa: UP042 - closed ADR schema
    FILESYSTEM_MOUNT_BOUNDARY = "filesystem_mount_boundary"


class RuntimeAugmentationMode(str, Enum):  # noqa: UP042 - closed ADR schema
    ADDITIVE_FRESH_COMPUTE_BTS_ONLY = "additive_fresh_compute_bts_only"


def _text(value: object, name: str, *, maximum: int = _MAX_TEXT_BYTES) -> None:
    if not isinstance(value, str) or not value:
        raise ValueError(f"{name} must be a non-empty string")
    try:
        encoded = value.encode("utf-8", errors="strict")
    except UnicodeEncodeError as exc:
        raise ValueError(f"{name} must be strict UTF-8") from exc
    if len(encoded) > maximum or "\x00" in value:
        raise ValueError(f"{name} exceeds its bounded text contract")


def _digest(value: object, name: str) -> None:
    if (
        not isinstance(value, str)
        or len(value) != _SHA256_LENGTH
        or not value.startswith("sha256:")
        or value[7:] != value[7:].lower()
    ):
        raise ValueError(f"{name} must be a lowercase sha256 digest")
    try:
        decoded = bytes.fromhex(value[7:])
    except ValueError as exc:
        raise ValueError(f"{name} must be a lowercase sha256 digest") from exc
    if len(decoded) != 32:
        raise ValueError(f"{name} must be a lowercase sha256 digest")


def _counter(value: object, name: str, *, positive: bool = False) -> None:
    minimum = 1 if positive else 0
    if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= _MAX_COUNTER:
        raise ValueError(f"{name} must be a bounded integer >= {minimum}")


def _module_name(value: object, name: str = "module") -> None:
    _text(value, name, maximum=256)
    assert isinstance(value, str)
    if any(not part or not part.isidentifier() for part in value.split(".")):
        raise ValueError(f"{name} must be a dotted Python module identity")


def _json_value(value: object, *, omit: frozenset[str] = frozenset()) -> object:
    if isinstance(value, Enum):
        return value.value
    if is_dataclass(value) and not isinstance(value, type):
        return {
            item.name: _json_value(getattr(value, item.name), omit=omit)
            for item in fields(value)
            if item.name not in omit
        }
    if isinstance(value, tuple):
        return [_json_value(item, omit=omit) for item in value]
    if value is None or isinstance(value, (str, bool)) or (isinstance(value, int) and not isinstance(value, bool)):
        return value
    raise TypeError(f"unsupported canonical runtime value: {type(value).__name__}")


def _canonical_bytes(value: object, *, omit: frozenset[str] = frozenset()) -> bytes:
    return (
        json.dumps(
            _json_value(value, omit=omit),
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        )
        + "\n"
    ).encode("utf-8", errors="strict")


def _canonical_digest(value: object, *, omit: frozenset[str] = frozenset()) -> str:
    return f"sha256:{hashlib.sha256(_canonical_bytes(value, omit=omit)).hexdigest()}"


def _identity_digest(value: str) -> str:
    return f"sha256:{hashlib.sha256(value.encode('utf-8', errors='strict')).hexdigest()}"


@dataclass(frozen=True, slots=True, order=True)
class RuntimeModuleManifestEntry:
    """One exact stdlib or declared-external import authorization."""

    module: str
    classification: RuntimeImportClassification
    loader_kind: RuntimeLoaderKind
    loaded_bytes_digest: str
    manifest_entry_digest: str

    def __post_init__(self) -> None:
        _module_name(self.module)
        if self.classification not in {
            RuntimeImportClassification.STDLIB,
            RuntimeImportClassification.DECLARED_EXTERNAL,
        }:
            raise ValueError("allowlist classification must be stdlib or declared_external")
        if not isinstance(self.loader_kind, RuntimeLoaderKind):
            raise ValueError("loader_kind must be a RuntimeLoaderKind")
        _digest(self.loaded_bytes_digest, "loaded_bytes_digest")
        _digest(self.manifest_entry_digest, "manifest_entry_digest")


@dataclass(frozen=True, slots=True)
class RuntimeImportPolicy:
    """Pinned classification inputs for one already-contained execution."""

    schema_version: str
    bts: BTS
    stdlib: tuple[RuntimeModuleManifestEntry, ...]
    declared_externals: tuple[RuntimeModuleManifestEntry, ...]
    donor_module_identities: tuple[str, ...]
    donor_path_roots: tuple[Path, ...]
    donor_tree_digest: str
    relocated_tree_digest: str
    test_probe_set_digest: str
    interpreter_build_digest: str
    stdlib_rootfs_digest: str
    environment_digest: str
    execution_policy_digest: str
    mount_policy_digest: str
    max_events: int
    max_evidence_bytes: int

    def __post_init__(self) -> None:
        if self.schema_version != RUNTIME_SCHEMA_VERSION:
            raise ValueError(f"schema_version must be {RUNTIME_SCHEMA_VERSION!r}")
        if not isinstance(self.bts, BTS):
            raise ValueError("bts must be a validated BTS")
        _digest(self.bts.bts_digest, "bts.bts_digest")
        for name in (
            "donor_tree_digest",
            "relocated_tree_digest",
            "test_probe_set_digest",
            "interpreter_build_digest",
            "stdlib_rootfs_digest",
            "environment_digest",
            "execution_policy_digest",
            "mount_policy_digest",
        ):
            _digest(getattr(self, name), name)
        _counter(self.max_events, "max_events", positive=True)
        _counter(self.max_evidence_bytes, "max_evidence_bytes", positive=True)
        stdlib = _manifest_entries(self.stdlib, RuntimeImportClassification.STDLIB, "stdlib")
        external = _manifest_entries(
            self.declared_externals,
            RuntimeImportClassification.DECLARED_EXTERNAL,
            "declared_externals",
        )
        if {item.module for item in stdlib} & {item.module for item in external}:
            raise ValueError("a module cannot be both stdlib and declared external")
        if not isinstance(self.donor_module_identities, tuple):
            raise ValueError("donor_module_identities must be a tuple")
        donor_modules = tuple(sorted(self.donor_module_identities))
        for module in donor_modules:
            _module_name(module, "donor module identity")
        if any(left == right for left, right in pairwise(donor_modules)):
            raise ValueError("duplicate donor module identity")
        if not isinstance(self.donor_path_roots, tuple) or not all(
            isinstance(item, Path) and item.is_absolute() for item in self.donor_path_roots
        ):
            raise ValueError("donor_path_roots must contain absolute pathlib.Path values")
        roots = tuple(sorted((Path(os.path.realpath(item)) for item in self.donor_path_roots), key=os.fspath))
        if any(left == right for left, right in pairwise(roots)):
            raise ValueError("duplicate donor path root")
        object.__setattr__(self, "stdlib", stdlib)
        object.__setattr__(self, "declared_externals", external)
        object.__setattr__(self, "donor_module_identities", donor_modules)
        object.__setattr__(self, "donor_path_roots", roots)


def _manifest_entries(
    entries: object,
    classification: RuntimeImportClassification,
    name: str,
) -> tuple[RuntimeModuleManifestEntry, ...]:
    if not isinstance(entries, tuple) or not all(isinstance(item, RuntimeModuleManifestEntry) for item in entries):
        raise ValueError(f"{name} must be a tuple of RuntimeModuleManifestEntry values")
    ordered = tuple(sorted(entries))
    for item in ordered:
        if item.classification is not classification:
            raise ValueError(f"{name} contains a mismatched classification")
    if any(left.module == right.module for left, right in pairwise(ordered)):
        raise ValueError(f"duplicate {name} module")
    return ordered


@dataclass(frozen=True, slots=True, order=True)
class RuntimeObservation:
    """One bounded event; attacker-controlled names and paths are digest-only."""

    classification: RuntimeImportClassification
    result: RuntimeImportResult
    module_identity_digest: str
    manifest_binding_digest: str
    provenance: RuntimeImportProvenance
    provenance_digest: str
    loader_kind: RuntimeLoaderKind
    loaded_bytes_digest: str
    origin_role: RuntimeOriginRole
    detail_code: str

    def __post_init__(self) -> None:
        if not isinstance(self.classification, RuntimeImportClassification):
            raise ValueError("classification must be a RuntimeImportClassification")
        if not isinstance(self.result, RuntimeImportResult):
            raise ValueError("result must be a RuntimeImportResult")
        if not isinstance(self.provenance, RuntimeImportProvenance):
            raise ValueError("provenance must be a RuntimeImportProvenance")
        if not isinstance(self.loader_kind, RuntimeLoaderKind):
            raise ValueError("loader_kind must be a RuntimeLoaderKind")
        if not isinstance(self.origin_role, RuntimeOriginRole):
            raise ValueError("origin_role must be a RuntimeOriginRole")
        for name in (
            "module_identity_digest",
            "manifest_binding_digest",
            "provenance_digest",
            "loaded_bytes_digest",
        ):
            _digest(getattr(self, name), name)
        _text(self.detail_code, "detail_code", maximum=96)


@dataclass(frozen=True, slots=True)
class RuntimeObservationReport:
    """Canonical untrusted diagnostics; non-observation is never absence proof."""

    schema_version: str
    evidence_role: RuntimeEvidenceRole
    trusted: bool
    donor_absence_authority: DonorAbsenceAuthority
    augmentation_mode: RuntimeAugmentationMode
    bts_digest: str
    donor_tree_digest: str
    relocated_tree_digest: str
    test_probe_set_digest: str
    interpreter_build_digest: str
    stdlib_rootfs_digest: str
    environment_digest: str
    execution_policy_digest: str
    mount_policy_digest: str
    initial_module_inventory_digest: str
    final_module_inventory_digest: str
    prospective_event_count: int
    retained_event_count: int
    prospective_evidence_bytes: int
    retained_evidence_bytes: int
    events: tuple[RuntimeObservation, ...]
    observation_digest: str

    def __post_init__(self) -> None:
        if self.schema_version != RUNTIME_SCHEMA_VERSION:
            raise ValueError(f"schema_version must be {RUNTIME_SCHEMA_VERSION!r}")
        if self.evidence_role is not RuntimeEvidenceRole.DIAGNOSTIC_ONLY or self.trusted is not False:
            raise ValueError("runtime evidence must remain untrusted and diagnostic-only")
        if self.donor_absence_authority is not DonorAbsenceAuthority.FILESYSTEM_MOUNT_BOUNDARY:
            raise ValueError("donor absence authority must remain the filesystem mount boundary")
        if self.augmentation_mode is not RuntimeAugmentationMode.ADDITIVE_FRESH_COMPUTE_BTS_ONLY:
            raise ValueError("runtime augmentation must remain additive-only")
        for name in (
            "bts_digest",
            "donor_tree_digest",
            "relocated_tree_digest",
            "test_probe_set_digest",
            "interpreter_build_digest",
            "stdlib_rootfs_digest",
            "environment_digest",
            "execution_policy_digest",
            "mount_policy_digest",
            "initial_module_inventory_digest",
            "final_module_inventory_digest",
            "observation_digest",
        ):
            _digest(getattr(self, name), name)
        for name in (
            "prospective_event_count",
            "retained_event_count",
            "prospective_evidence_bytes",
            "retained_evidence_bytes",
        ):
            _counter(getattr(self, name), name)
        if not isinstance(self.events, tuple) or not all(isinstance(item, RuntimeObservation) for item in self.events):
            raise ValueError("events must be a tuple of RuntimeObservation values")
        ordered = tuple(sorted(self.events))
        if ordered != self.events or any(left == right for left, right in pairwise(ordered)):
            raise ValueError("runtime events must have unique canonical ordering")
        if self.retained_event_count != len(self.events) or self.prospective_event_count != len(self.events):
            raise ValueError("runtime event counters do not match retained evidence")
        actual_bytes = sum(len(_canonical_bytes(item)) for item in self.events)
        if self.retained_evidence_bytes != actual_bytes or self.prospective_evidence_bytes != actual_bytes:
            raise ValueError("runtime byte counters do not match retained evidence")

    def to_bytes(self) -> bytes:
        return _canonical_bytes(self)

    def to_json(self) -> str:
        return self.to_bytes().decode("utf-8", errors="strict")


@dataclass(frozen=True, slots=True)
class FreshBTSAnalysisTrigger:
    """Additive request for a new static analysis, never a binding decision."""

    schema_version: str
    mode: RuntimeAugmentationMode
    prior_static_status: BTSStatus
    prior_analysis_digest: str
    runtime_observation_digest: str
    retained_static_blocker_digests: tuple[str, ...]
    candidate_static_scope_digests: tuple[str, ...]

    def __post_init__(self) -> None:
        if self.schema_version != RUNTIME_SCHEMA_VERSION:
            raise ValueError(f"schema_version must be {RUNTIME_SCHEMA_VERSION!r}")
        if self.mode is not RuntimeAugmentationMode.ADDITIVE_FRESH_COMPUTE_BTS_ONLY:
            raise ValueError("fresh BTS trigger must be additive-only")
        if not isinstance(self.prior_static_status, BTSStatus):
            raise ValueError("prior_static_status must be a BTSStatus")
        for name in ("prior_analysis_digest", "runtime_observation_digest"):
            _digest(getattr(self, name), name)
        for name in ("retained_static_blocker_digests", "candidate_static_scope_digests"):
            values = getattr(self, name)
            if not isinstance(values, tuple):
                raise ValueError(f"{name} must be a tuple")
            for value in values:
                _digest(value, name)
            if values != tuple(sorted(values)) or any(left == right for left, right in pairwise(values)):
                raise ValueError(f"{name} must have unique canonical ordering")


@dataclass(frozen=True, slots=True)
class RuntimeAnalysisAugmentation:
    """The original static result plus a non-mutating fresh-analysis request."""

    static_result: BTSResult
    trigger: FreshBTSAnalysisTrigger

    def __post_init__(self) -> None:
        if not isinstance(self.static_result, BTSResult) or not isinstance(self.trigger, FreshBTSAnalysisTrigger):
            raise ValueError("runtime augmentation has invalid closed-schema values")
        if self.trigger.prior_static_status is not self.static_result.status:
            raise ValueError("runtime augmentation cannot change the static status")
        blockers = tuple(sorted(_canonical_digest(item) for item in self.static_result.report.blockers))
        if blockers != self.trigger.retained_static_blocker_digests:
            raise ValueError("runtime augmentation cannot remove or alter a static blocker")


def augment_static_analysis(result: BTSResult, report: RuntimeObservationReport) -> RuntimeAnalysisAugmentation:
    """Return an additive-only fresh-analysis trigger while retaining ``result``."""

    if not isinstance(result, BTSResult) or not isinstance(report, RuntimeObservationReport):
        raise TypeError("augment_static_analysis requires BTSResult and RuntimeObservationReport values")
    blockers = tuple(sorted(_canonical_digest(item) for item in result.report.blockers))
    candidates = tuple(sorted({item.module_identity_digest for item in report.events}))
    trigger = FreshBTSAnalysisTrigger(
        RUNTIME_SCHEMA_VERSION,
        RuntimeAugmentationMode.ADDITIVE_FRESH_COMPUTE_BTS_ONLY,
        result.status,
        result.report.analysis_digest,
        report.observation_digest,
        blockers,
        candidates,
    )
    return RuntimeAnalysisAugmentation(result, trigger)


def _module_inventory_digest() -> str:
    records: list[tuple[str, str]] = []
    for name, module in tuple(sys.modules.items()):
        spec = getattr(module, "__spec__", None)
        loader = getattr(spec, "loader", None)
        loader_name = getattr(loader, "__name__", None) if isinstance(loader, type) else type(loader).__name__
        records.append((_identity_digest(name), _identity_digest(loader_name or "unknown")))
    return _canonical_digest(tuple(sorted(records)))


def _loader_kind(module: ModuleType) -> RuntimeLoaderKind:
    spec = getattr(module, "__spec__", None)
    loader = getattr(spec, "loader", None)
    name = getattr(loader, "__name__", None) if isinstance(loader, type) else type(loader).__name__
    try:
        return RuntimeLoaderKind(name)
    except ValueError as exc:
        raise BTSError(
            BTSRejectReason.REJECT_UNRESOLVED_EDGE,
            "observed import used an undeclared loader kind",
            detail_code="runtime_loader_kind_v1",
            cause=exc,
        ) from exc


def _loaded_bytes_digest(module: ModuleType, loader_kind: RuntimeLoaderKind, interpreter_digest: str) -> str:
    if loader_kind in {RuntimeLoaderKind.BUILTIN, RuntimeLoaderKind.FROZEN}:
        return interpreter_digest
    spec = getattr(module, "__spec__", None)
    origin = getattr(spec, "origin", None)
    if not isinstance(origin, str) or not origin:
        raise BTSError(
            BTSRejectReason.REJECT_PROVENANCE_MISMATCH,
            "observed source or extension import has no exact origin",
            detail_code="runtime_origin_missing_v1",
        )
    try:
        with open(origin, "rb") as handle:
            digest = hashlib.sha256()
            while chunk := handle.read(64 * 1024):
                digest.update(chunk)
    except OSError as exc:
        raise BTSError(
            BTSRejectReason.REJECT_PROVENANCE_MISMATCH,
            "observed import bytes could not be read",
            detail_code="runtime_loaded_bytes_v1",
            cause=exc,
        ) from exc
    return f"sha256:{digest.hexdigest()}"


def _origin_realpath(module: ModuleType) -> str | None:
    """Return ``os.path.realpath`` of a module origin, or ``None`` if absent.

    Deliberately avoids ``pathlib``: on CPython 3.12.3-era builds
    ``PurePath.__init__`` itself lazily imports :mod:`ntpath`, and the
    recorder must never trigger imports from its own classification path.
    """

    spec = getattr(module, "__spec__", None)
    origin = getattr(spec, "origin", None)
    if not isinstance(origin, str) or not origin or origin in {"built-in", "frozen"}:
        return None
    return os.path.realpath(origin)


def _path_is_under(candidate: str, roots: Sequence[str]) -> bool:
    """Pure-string containment so classification stays import-free."""

    return any(
        candidate == root
        or candidate.startswith(root if root.endswith(os.sep) else root + os.sep)
        for root in roots
    )


def _matches_identity(module: str, identities: Sequence[str]) -> bool:
    return any(module == identity or module.startswith(f"{identity}.") for identity in identities)


def _source_provenance_digest() -> str:
    frame = inspect.currentframe()
    try:
        while frame is not None:
            filename = frame.f_code.co_filename
            if filename != __file__:
                bounded = filename.encode("utf-8", errors="backslashreplace")[-512:]
                payload = (hashlib.sha256(bounded).hexdigest(), frame.f_code.co_name[:128], frame.f_lineno)
                return _canonical_digest(payload)
            frame = frame.f_back
    finally:
        del frame
    return _identity_digest("runtime-provenance-unavailable-v1")


def _member_bindings(bts: BTS) -> dict[str, str]:
    by_module: dict[str, list[MemberEvidence]] = {}
    for member in bts.members:
        by_module.setdefault(member.node.module, []).append(member)
    return {
        module: _canonical_digest(tuple(sorted(members)))
        for module, members in sorted(by_module.items())
    }


class RuntimeImportRecorder:
    """Process-global import wrapper scoped to one synchronous execution window."""

    def __init__(self, policy: RuntimeImportPolicy) -> None:
        if not isinstance(policy, RuntimeImportPolicy):
            raise TypeError("policy must be a RuntimeImportPolicy")
        self._policy = policy
        self._members = _member_bindings(policy.bts)
        self._allowed = {item.module: item for item in (*policy.stdlib, *policy.declared_externals)}
        self._donor_roots = tuple(
            os.fspath(os.path.realpath(item)) for item in policy.donor_path_roots
        )
        self._stdlib_path_dir = os.path.dirname(os.path.abspath(os.path.__file__))
        self._events: dict[RuntimeObservation, RuntimeObservation] = {}
        self._evidence_bytes = 0
        self._terminal: BTSError | None = None
        self._armed = False
        self._used = False
        self._import_depth = 0

    def _remember(self, event: RuntimeObservation) -> None:
        if event in self._events:
            return
        prospective_events = len(self._events) + 1
        event_bytes = len(_canonical_bytes(event))
        prospective_bytes = self._evidence_bytes + event_bytes
        if prospective_events > self._policy.max_events or prospective_bytes > self._policy.max_evidence_bytes:
            error = BTSError(
                BTSRejectReason.REJECT_BUDGET_EXCEEDED,
                "runtime observation evidence exceeded its prospective bound",
                detail_code="runtime_evidence_budget_v1",
            )
            self._terminal = error
            raise error
        self._events[event] = event
        self._evidence_bytes = prospective_bytes

    def _path_shim_event(
        self,
        name: str,
        origin: str | None,
        loader: RuntimeLoaderKind,
        loaded_digest: str,
        provenance_digest: str,
    ) -> RuntimeObservation | None:
        """Classify one interpreter-internal platform path-shim import.

        Returns ``None`` (falling through to the fail-closed UNKNOWN
        verdict) unless every bound holds: the import is nested inside
        another in-flight import rather than a top-level import by the
        observed code; the module is one of the three platform path shims
        and a member of ``sys.stdlib_module_names``; and the loader is one
        the interpreter itself uses for its shims — the frozen finder
        (whose table is compiled into the binary and cannot be shadowed
        from ``sys.path``; the bytes bind to the pinned interpreter build
        digest) or the plain source loader with bytes from the running
        interpreter's own path-module directory.  A shim shadowed on
        ``sys.path`` therefore never authorizes itself.
        """

        if self._import_depth < 2 or name not in _PATH_SHIM_MODULES:
            return None
        if name not in sys.stdlib_module_names:
            return None
        if loader is RuntimeLoaderKind.FROZEN:
            pass
        elif loader is RuntimeLoaderKind.SOURCE:
            if origin is None or os.path.dirname(os.path.abspath(origin)) != self._stdlib_path_dir:
                return None
        else:
            return None
        return RuntimeObservation(
            RuntimeImportClassification.STDLIB,
            RuntimeImportResult.SUCCESS,
            _identity_digest(name),
            _identity_digest(f"runtime-path-shim-v1:{name}"),
            RuntimeImportProvenance.SOURCE_IMPORT_HOOK,
            provenance_digest,
            loader,
            loaded_digest,
            RuntimeOriginRole.STDLIB_MANIFEST,
            "runtime_path_shim_v1",
        )

    def _classify(self, name: str, module: ModuleType) -> RuntimeObservation:
        origin = _origin_realpath(module)
        donor = _matches_identity(name, self._policy.donor_module_identities) or (
            origin is not None and _path_is_under(origin, self._donor_roots)
        )
        try:
            loader = _loader_kind(module)
            loaded_digest = _loaded_bytes_digest(module, loader, self._policy.interpreter_build_digest)
        except BTSError as exc:
            if donor:
                raise BTSError(
                    BTSRejectReason.REJECT_DONOR_IMPORT_OBSERVED,
                    "a donor import with an unclassifiable loader was observed",
                    detail_code="runtime_donor_import_v1",
                    cause=exc,
                ) from exc
            raise
        provenance_digest = _source_provenance_digest()
        module_digest = _identity_digest(name)
        if donor:
            return RuntimeObservation(
                RuntimeImportClassification.DONOR,
                RuntimeImportResult.SUCCESS,
                module_digest,
                self._policy.donor_tree_digest,
                RuntimeImportProvenance.SOURCE_IMPORT_HOOK,
                provenance_digest,
                loader,
                loaded_digest,
                RuntimeOriginRole.DONOR_SOURCE,
                "runtime_donor_import_v1",
            )
        member_binding = self._members.get(name)
        if member_binding is not None:
            return RuntimeObservation(
                RuntimeImportClassification.BTS_MEMBER,
                RuntimeImportResult.SUCCESS,
                module_digest,
                member_binding,
                RuntimeImportProvenance.SOURCE_IMPORT_HOOK,
                provenance_digest,
                loader,
                loaded_digest,
                RuntimeOriginRole.BTS_SOURCE,
                "runtime_bts_member_v1",
            )
        entry = self._allowed.get(name)
        if entry is not None:
            if loader is not entry.loader_kind or loaded_digest != entry.loaded_bytes_digest:
                raise BTSError(
                    BTSRejectReason.REJECT_PROVENANCE_MISMATCH,
                    "observed import does not match its pinned manifest entry",
                    detail_code="runtime_manifest_binding_v1",
                )
            role = (
                RuntimeOriginRole.STDLIB_MANIFEST
                if entry.classification is RuntimeImportClassification.STDLIB
                else RuntimeOriginRole.EXTERNAL_MANIFEST
            )
            return RuntimeObservation(
                entry.classification,
                RuntimeImportResult.SUCCESS,
                module_digest,
                entry.manifest_entry_digest,
                RuntimeImportProvenance.SOURCE_IMPORT_HOOK,
                provenance_digest,
                loader,
                loaded_digest,
                role,
                "runtime_allowlist_entry_v1",
            )
        shim = self._path_shim_event(name, origin, loader, loaded_digest, provenance_digest)
        if shim is not None:
            return shim
        return RuntimeObservation(
            RuntimeImportClassification.UNKNOWN,
            RuntimeImportResult.SUCCESS,
            module_digest,
            _identity_digest("runtime-unknown-binding-v1"),
            RuntimeImportProvenance.SOURCE_IMPORT_HOOK,
            provenance_digest,
            loader,
            loaded_digest,
            RuntimeOriginRole.UNKNOWN,
            "runtime_unknown_import_v1",
        )

    def _observe(self, name: str) -> None:
        module = sys.modules.get(name)
        if not isinstance(module, ModuleType):
            error = BTSError(
                BTSRejectReason.REJECT_UNRESOLVED_EDGE,
                "import attempt did not produce a classifiable module",
                detail_code="runtime_import_attempt_v1",
            )
            self._terminal = error
            raise error
        try:
            event = self._classify(name, module)
            self._remember(event)
        except BTSError as exc:
            self._terminal = exc
            raise
        if event.classification is RuntimeImportClassification.DONOR:
            error = BTSError(
                BTSRejectReason.REJECT_DONOR_IMPORT_OBSERVED,
                "a donor import was observed by the diagnostic recorder",
                detail_code="runtime_donor_import_v1",
            )
            self._terminal = error
            raise error
        if event.classification is RuntimeImportClassification.UNKNOWN:
            error = BTSError(
                BTSRejectReason.REJECT_UNRESOLVED_EDGE,
                "an undeclared environment import was observed",
                detail_code="runtime_unknown_import_v1",
            )
            self._terminal = error
            raise error

    @staticmethod
    def _absolute_name(name: str, globals_value: Mapping[str, object] | None, level: int) -> str:
        if level == 0:
            return name
        package: object = None if globals_value is None else globals_value.get("__package__")
        if not isinstance(package, str) or not package:
            return name
        try:
            return importlib.util.resolve_name(f"{'.' * level}{name}", package)
        except (ImportError, ValueError):
            return name

    def record(self, function: Callable[[], object]) -> RuntimeObservationReport:
        """Run ``function`` while armed and return canonical supplementary evidence."""

        if not callable(function):
            raise TypeError("function must be callable")
        if self._used:
            raise BTSError(
                BTSRejectReason.REJECT_HARD_GATE_FAILED,
                "a runtime recorder cannot be reused across execution windows",
                detail_code="runtime_recorder_reuse_v1",
            )
        original_import = builtins.__import__
        if not _ACTIVE_LOCK.acquire(blocking=False):
            raise BTSError(
                BTSRejectReason.REJECT_HARD_GATE_FAILED,
                "another process-global runtime recorder is active",
                detail_code="runtime_recorder_concurrency_v1",
            )
        try:
            initial = _module_inventory_digest()
            self._used = True
            self._armed = True

            def observed_import(
                name: str,
                globals: Mapping[str, object] | None = None,
                locals: Mapping[str, object] | None = None,
                fromlist: Sequence[str] | None = (),
                level: int = 0,
            ) -> ModuleType:
                if not self._armed:
                    error = BTSError(
                        BTSRejectReason.REJECT_HARD_GATE_FAILED,
                        "runtime import hook was invoked outside its armed window",
                        detail_code="runtime_recorder_not_armed_v1",
                    )
                    self._terminal = error
                    raise error
                absolute = self._absolute_name(name, globals, level)
                self._import_depth += 1
                try:
                    try:
                        imported = original_import(name, globals, locals, fromlist, level)
                    except BTSError:
                        raise
                    except BaseException as exc:
                        if _matches_identity(absolute, self._policy.donor_module_identities):
                            error = BTSError(
                                BTSRejectReason.REJECT_DONOR_IMPORT_OBSERVED,
                                "a donor import attempt was observed by the diagnostic recorder",
                                detail_code="runtime_donor_import_v1",
                                cause=exc,
                            )
                            self._terminal = error
                            raise error from exc
                        error = BTSError(
                            BTSRejectReason.REJECT_UNRESOLVED_EDGE,
                            "an import attempt could not be classified successfully",
                            detail_code="runtime_import_failed_v1",
                            cause=exc,
                        )
                        self._terminal = error
                        raise error from exc
                    self._observe(absolute)
                finally:
                    self._import_depth -= 1
                return imported

            builtins.__import__ = observed_import
            function()
            if self._terminal is not None:
                raise self._terminal
        finally:
            self._armed = False
            builtins.__import__ = original_import
            _ACTIVE_LOCK.release()
        final = _module_inventory_digest()
        events = tuple(sorted(self._events))
        base = RuntimeObservationReport(
            RUNTIME_SCHEMA_VERSION,
            RuntimeEvidenceRole.DIAGNOSTIC_ONLY,
            False,
            DonorAbsenceAuthority.FILESYSTEM_MOUNT_BOUNDARY,
            RuntimeAugmentationMode.ADDITIVE_FRESH_COMPUTE_BTS_ONLY,
            self._policy.bts.bts_digest,
            self._policy.donor_tree_digest,
            self._policy.relocated_tree_digest,
            self._policy.test_probe_set_digest,
            self._policy.interpreter_build_digest,
            self._policy.stdlib_rootfs_digest,
            self._policy.environment_digest,
            self._policy.execution_policy_digest,
            self._policy.mount_policy_digest,
            initial,
            final,
            len(events),
            len(events),
            self._evidence_bytes,
            self._evidence_bytes,
            events,
            _identity_digest("runtime-observation-pending-v1"),
        )
        observation_digest = _canonical_digest(base, omit=frozenset({"observation_digest"}))
        return replace(base, observation_digest=observation_digest)


def record_imports(function: Callable[[], object], policy: RuntimeImportPolicy) -> RuntimeObservationReport:
    """Convenience entry point for one already-contained execution window."""

    return RuntimeImportRecorder(policy).record(function)


ImportObservation: TypeAlias = RuntimeObservationReport

__all__ = [
    "RUNTIME_SCHEMA_VERSION",
    "DonorAbsenceAuthority",
    "FreshBTSAnalysisTrigger",
    "ImportObservation",
    "RuntimeAnalysisAugmentation",
    "RuntimeAugmentationMode",
    "RuntimeEvidenceRole",
    "RuntimeImportClassification",
    "RuntimeImportPolicy",
    "RuntimeImportProvenance",
    "RuntimeImportRecorder",
    "RuntimeImportResult",
    "RuntimeLoaderKind",
    "RuntimeModuleManifestEntry",
    "RuntimeObservation",
    "RuntimeObservationReport",
    "RuntimeOriginRole",
    "augment_static_analysis",
    "record_imports",
]
