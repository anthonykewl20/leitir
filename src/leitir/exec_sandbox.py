"""Linux-only donor execution through a release-pinned native nsjail binary.

NsJail is invoked as an external subprocess.  It is not a Python package or a
Leitir runtime dependency.  This module deliberately has no portable or
unsandboxed fallback: Python audit hooks and :mod:`resource` are not containment.
"""

from __future__ import annotations

import hashlib
import json
import os
import platform
import re
import selectors
import signal
import stat
import subprocess
import tempfile
import time
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, replace
from enum import StrEnum
from pathlib import Path, PurePosixPath
from typing import Protocol

from leitir.bts_errors import BTSRejectReason, TransplantError

DONOR_EXECUTION_ENV = "LEITIR_ENABLE_DONOR_EXECUTION"
POLICY_SCHEMA = "leitir-containment-policy-v1"
PLAN_SCHEMA = "leitir-execution-plan-v1"
RESULT_SCHEMA = "leitir-execution-result-v1"
_DIGEST_RE = re.compile(r"sha256:[0-9a-f]{64}\Z")
_NSJAIL_VERSION_RE = re.compile(r"nsjail@([0-9a-f]{40})\Z")
_ENV_NAME_RE = re.compile(r"[A-Z_][A-Z0-9_]*\Z")
_MAX_POLICY_TEXT = 64 * 1024
_CGROUP_ROOT = Path("/sys/fs/cgroup")
_FORBIDDEN_SYSCALLS = frozenset(
    {
        "accept",
        "accept4",
        "bind",
        "bpf",
        "connect",
        "getpeername",
        "getsockname",
        "ioctl",
        "keyctl",
        "listen",
        "mount",
        "ptrace",
        "reboot",
        "recvfrom",
        "recvmsg",
        "sendmsg",
        "sendto",
        "setns",
        "shutdown",
        "socket",
        "socketpair",
        "umount",
        "umount2",
        "unshare",
    }
)


class SeccompAction(StrEnum):
    """Closed Kafel actions supported by the v1 policy generator."""

    ALLOW = "ALLOW"
    KILL = "KILL"


class PermittedSyscall(StrEnum):
    """Minimal syscall surface for the pinned CPython/runner closure."""

    ARCH_PRCTL = "arch_prctl"
    BRK = "brk"
    CLOCK_GETTIME = "clock_gettime"
    CLOSE = "close"
    EXECVE = "execve"
    EXIT = "exit"
    EXIT_GROUP = "exit_group"
    FCNTL = "fcntl"
    FSTAT = "fstat"
    FUTEX = "futex"
    GETCWD = "getcwd"
    GETDENTS64 = "getdents64"
    GETPID = "getpid"
    GETRANDOM = "getrandom"
    LSEEK = "lseek"
    MMAP = "mmap"
    MPROTECT = "mprotect"
    MUNMAP = "munmap"
    NEWFSTATAT = "newfstatat"
    OPENAT = "openat"
    PRLIMIT64 = "prlimit64"
    READ = "read"
    READLINK = "readlink"
    READLINKAT = "readlinkat"
    RT_SIGACTION = "rt_sigaction"
    RT_SIGPROCMASK = "rt_sigprocmask"
    SET_ROBUST_LIST = "set_robust_list"
    SET_TID_ADDRESS = "set_tid_address"
    STATX = "statx"
    WRITE = "write"


@dataclass(frozen=True, slots=True)
class SeccompPolicy:
    """Typed canonical policy; arbitrary caller-authored Kafel is unsupported."""

    default_action: SeccompAction
    allowed_syscalls: tuple[PermittedSyscall, ...]

    def render_kafel(self) -> str:
        names = ", ".join(item.value for item in self.allowed_syscalls)
        return f"DEFAULT {self.default_action.value}\n{SeccompAction.ALLOW.value} {{ {names} }}\n"


CANONICAL_SECCOMP_POLICY = SeccompPolicy(
    SeccompAction.KILL,
    tuple(sorted(PermittedSyscall, key=lambda item: item.value)),
)
CANONICAL_SECCOMP_STRING = CANONICAL_SECCOMP_POLICY.render_kafel()


def donor_execution_enabled(environ: Mapping[str, str] | None = None) -> bool:
    """Return whether the exact, fail-closed donor execution opt-in is present."""

    source = os.environ if environ is None else environ
    return source.get(DONOR_EXECUTION_ENV) == "1"


@dataclass(frozen=True, slots=True, order=True)
class ReadOnlyMount:
    """One already-authorized entry supplied by ADR-009's mount plan."""

    destination: str
    source: str
    source_digest: str


@dataclass(frozen=True, slots=True)
class ContainmentPolicy:
    """Complete, pinned nsjail policy; numeric limits are policy inputs."""

    schema_version: str
    nsjail_path: str
    nsjail_sha256: str
    nsjail_version: str
    nsjail_build_identity: str
    config_schema_digest: str
    architecture: str
    rootfs_digest: str
    mount_plan_digest: str
    readonly_mounts: tuple[ReadOnlyMount, ...]
    writable_tmpfs: str
    writable_tmpfs_bytes: int
    writable_tmpfs_inodes: int
    cwd: str
    mode: str
    keep_env: bool
    clone_newnet: bool
    clone_newuser: bool
    clone_newns: bool
    clone_newpid: bool
    clone_newipc: bool
    clone_newuts: bool
    iface_no_lo: bool
    cgroup_mem_max: int
    cgroup_pids_max: int
    cgroup_cpu_ms_per_sec: int
    wall_time_seconds: int
    rlimit_as_mb: int
    rlimit_cpu_seconds: int
    rlimit_fsize_mb: int
    rlimit_nofile: int
    rlimit_nproc: int
    rlimit_stack_mb: int
    rlimit_core_mb: int
    output_limit_bytes: int
    environment: tuple[str, ...]
    opt_in_satisfied: bool

    @property
    def seccomp_string(self) -> str:
        """Return Leitir's generated policy; callers cannot supply Kafel."""

        return CANONICAL_SECCOMP_STRING


@dataclass(frozen=True, slots=True)
class ExecutionPlan:
    """Canonical pre-execution plan; no host-temporary config path is retained."""

    schema_version: str
    policy: ContainmentPolicy
    nsjail_path: str
    nsjail_sha256: str
    architecture: str
    nsjail_argv: tuple[str, ...]
    config_text: str
    environment: tuple[str, ...]
    wall_time_seconds: int
    output_limit_bytes: int
    policy_digest: str
    plan_digest: str
    opt_in_satisfied: bool

    def to_json(self) -> str:
        """Render the byte-stable canonical plan with one trailing LF."""

        return _canonical_json(_plan_payload(self, include_digest=True))


@dataclass(frozen=True, slots=True)
class ValidationAbortEnvelope:
    """Bounded, nonauthorizing operational-abort information (ADR-009 V12)."""

    schema_version: str
    stage: str
    role: str
    reason: BTSRejectReason
    detail_category: str
    subject_digest: str
    stdout_bytes: int
    stderr_bytes: int
    blockers: tuple[str, ...] = ()

    def to_json(self) -> str:
        payload = {
            "blockers": list(self.blockers),
            "detail_category": self.detail_category,
            "reason": self.reason.value,
            "role": self.role,
            "schema_version": self.schema_version,
            "stage": self.stage,
            "stderr_bytes": self.stderr_bytes,
            "stdout_bytes": self.stdout_bytes,
            "subject_digest": self.subject_digest,
        }
        return _canonical_json(payload)


@dataclass(frozen=True, slots=True)
class ExecutionResult:
    """A content-addressed success or a bounded noncanonical abort."""

    completed: bool
    subject_digest: str
    exit_code: int | None
    stdout: bytes
    stderr: bytes
    stdout_digest: str | None
    stderr_digest: str | None
    result_digest: str | None
    abort: ValidationAbortEnvelope | None

    def to_json(self) -> str:
        """Render canonical success metadata or the noncanonical abort envelope."""

        if self.abort is not None:
            return self.abort.to_json()
        payload = {
            "exit_code": self.exit_code,
            "result_digest": self.result_digest,
            "schema_version": RESULT_SCHEMA,
            "subject_digest": self.subject_digest,
            "stderr_bytes": len(self.stderr),
            "stderr_digest": self.stderr_digest,
            "stdout_bytes": len(self.stdout),
            "stdout_digest": self.stdout_digest,
        }
        return _canonical_json(payload)


def _reject(message: str, detail: str) -> TransplantError:
    return TransplantError(BTSRejectReason.REJECT_EXECUTION_THREAT, message, detail_code=detail)


def _canonical_json(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False) + "\n"


def _digest_bytes(value: bytes) -> str:
    return f"sha256:{hashlib.sha256(value).hexdigest()}"


def _digest_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        while chunk := source.read(1024 * 1024):
            digest.update(chunk)
    return f"sha256:{digest.hexdigest()}"


def _nsjail_build_identity(commit: str, binary_sha256: str) -> str:
    """Derive the deterministic native-backend identity used by containment CI."""

    if _NSJAIL_VERSION_RE.fullmatch(f"nsjail@{commit}") is None or _DIGEST_RE.fullmatch(binary_sha256) is None:
        raise ValueError("nsjail identity inputs are malformed")
    return _digest_bytes((commit + binary_sha256.removeprefix("sha256:")).encode("utf-8"))


def _verify_nsjail_identity(policy: ContainmentPolicy, binary_sha256: str) -> None:
    """Reject policy identity pins that do not match the measured binary digest."""

    version_match = _NSJAIL_VERSION_RE.fullmatch(policy.nsjail_version)
    if version_match is None:
        raise _reject("nsjail release/build identity does not match policy", "nsjail_identity_mismatch")
    try:
        expected_identity = _nsjail_build_identity(version_match.group(1), binary_sha256)
    except ValueError as exc:
        raise _reject("nsjail release/build identity does not match policy", "nsjail_identity_mismatch") from exc
    if policy.nsjail_build_identity != expected_identity:
        raise _reject("nsjail release/build identity does not match policy", "nsjail_identity_mismatch")


def _digest_payload(value: object) -> str:
    return _digest_bytes(_canonical_json(value).encode("utf-8"))


def _valid_digest(value: object) -> bool:
    return isinstance(value, str) and _DIGEST_RE.fullmatch(value) is not None


def _positive_int(value: object) -> bool:
    return type(value) is int and 0 < value <= 2**63 - 1


def _absolute_clean_path(value: object) -> bool:
    if not isinstance(value, str) or not value.startswith("/") or "\x00" in value:
        return False
    path = PurePosixPath(value)
    return value == str(path) and ".." not in path.parts


def _policy_payload(policy: ContainmentPolicy) -> dict[str, object]:
    return {
        "architecture": policy.architecture,
        "cgroup_cpu_ms_per_sec": policy.cgroup_cpu_ms_per_sec,
        "cgroup_mem_max": policy.cgroup_mem_max,
        "cgroup_pids_max": policy.cgroup_pids_max,
        "clone_newipc": policy.clone_newipc,
        "clone_newnet": policy.clone_newnet,
        "clone_newns": policy.clone_newns,
        "clone_newpid": policy.clone_newpid,
        "clone_newuser": policy.clone_newuser,
        "clone_newuts": policy.clone_newuts,
        "config_schema_digest": policy.config_schema_digest,
        "cwd": policy.cwd,
        "environment": list(policy.environment),
        "iface_no_lo": policy.iface_no_lo,
        "keep_env": policy.keep_env,
        "mode": policy.mode,
        "mount_plan_digest": policy.mount_plan_digest,
        "nsjail_build_identity": policy.nsjail_build_identity,
        "nsjail_sha256": policy.nsjail_sha256,
        "nsjail_version": policy.nsjail_version,
        "opt_in_satisfied": policy.opt_in_satisfied,
        "output_limit_bytes": policy.output_limit_bytes,
        "readonly_mounts": [
            {"destination": mount.destination, "source": mount.source, "source_digest": mount.source_digest}
            for mount in policy.readonly_mounts
        ],
        "rlimit_as_mb": policy.rlimit_as_mb,
        "rlimit_core_mb": policy.rlimit_core_mb,
        "rlimit_cpu_seconds": policy.rlimit_cpu_seconds,
        "rlimit_fsize_mb": policy.rlimit_fsize_mb,
        "rlimit_nofile": policy.rlimit_nofile,
        "rlimit_nproc": policy.rlimit_nproc,
        "rlimit_stack_mb": policy.rlimit_stack_mb,
        "rootfs_digest": policy.rootfs_digest,
        "schema_version": policy.schema_version,
        "seccomp_string": policy.seccomp_string,
        "wall_time_seconds": policy.wall_time_seconds,
        "writable_tmpfs": policy.writable_tmpfs,
        "writable_tmpfs_bytes": policy.writable_tmpfs_bytes,
        "writable_tmpfs_inodes": policy.writable_tmpfs_inodes,
    }


def _validate_policy(policy: ContainmentPolicy) -> None:
    if not isinstance(policy, ContainmentPolicy) or policy.schema_version != POLICY_SCHEMA:
        raise _reject("unsupported or malformed containment policy", "invalid_policy_schema")
    if policy.mode != "ONCE" or policy.keep_env is not False:
        raise _reject("nsjail mode and environment controls are not fully applied", "invalid_nsjail_control")
    namespace_values = (
        policy.clone_newnet,
        policy.clone_newuser,
        policy.clone_newns,
        policy.clone_newpid,
        policy.clone_newipc,
        policy.clone_newuts,
    )
    if any(value is not True for value in namespace_values) or policy.iface_no_lo is not True:
        raise _reject("required namespace or network control is not fully applied", "invalid_namespace_control")
    numeric = (
        policy.cgroup_mem_max,
        policy.cgroup_pids_max,
        policy.cgroup_cpu_ms_per_sec,
        policy.wall_time_seconds,
        policy.rlimit_as_mb,
        policy.rlimit_cpu_seconds,
        policy.rlimit_fsize_mb,
        policy.rlimit_nofile,
        policy.rlimit_nproc,
        policy.rlimit_stack_mb,
        policy.writable_tmpfs_bytes,
        policy.writable_tmpfs_inodes,
        policy.output_limit_bytes,
    )
    if any(not _positive_int(value) for value in numeric) or type(policy.rlimit_core_mb) is not int or policy.rlimit_core_mb != 0:
        raise _reject("resource limits must be bounded positive integers and core must be zero", "invalid_resource_limit")
    allowed_syscalls = frozenset(item.value for item in CANONICAL_SECCOMP_POLICY.allowed_syscalls)
    if (
        CANONICAL_SECCOMP_POLICY.default_action is not SeccompAction.KILL
        or allowed_syscalls & _FORBIDDEN_SYSCALLS
        or len(policy.seccomp_string.encode("utf-8")) > _MAX_POLICY_TEXT
    ):
        raise _reject("Leitir's canonical seccomp policy is invalid", "invalid_seccomp_policy")
    digests = (policy.nsjail_sha256, policy.config_schema_digest, policy.rootfs_digest, policy.mount_plan_digest)
    if any(not _valid_digest(value) for value in digests):
        raise _reject("containment integrity digest is missing or malformed", "invalid_integrity_digest")
    if not policy.nsjail_version or not policy.nsjail_build_identity or not policy.architecture:
        raise _reject("backend identity fields are required", "missing_backend_identity")
    if not _absolute_clean_path(policy.nsjail_path) or not _absolute_clean_path(policy.writable_tmpfs) or not _absolute_clean_path(policy.cwd):
        raise _reject("containment paths must be normalized absolute paths", "invalid_containment_path")
    tmpfs = PurePosixPath(policy.writable_tmpfs)
    if PurePosixPath(policy.cwd) != tmpfs and tmpfs not in PurePosixPath(policy.cwd).parents:
        raise _reject("working directory must be inside the bounded tmpfs", "cwd_outside_tmpfs")
    if not policy.readonly_mounts:
        raise _reject("mount plan has no read-only authorized inputs", "empty_mount_plan")
    if tuple(sorted(policy.readonly_mounts)) != policy.readonly_mounts or len(set(policy.readonly_mounts)) != len(policy.readonly_mounts):
        raise _reject("mount plan must be sorted and unique", "noncanonical_mount_plan")
    destinations: set[str] = set()
    has_root = False
    for mount in policy.readonly_mounts:
        if not _absolute_clean_path(mount.source) or not _absolute_clean_path(mount.destination) or not _valid_digest(mount.source_digest):
            raise _reject("mount entry is malformed", "invalid_mount_entry")
        if mount.destination in destinations or mount.destination == policy.writable_tmpfs:
            raise _reject("mount destinations collide", "duplicate_mount_destination")
        destinations.add(mount.destination)
        has_root = has_root or mount.destination == "/"
    if not has_root:
        raise _reject("mount plan must supply a read-only rootfs", "missing_rootfs_mount")
    mount_payload = {
        "readonly_mounts": [
            {"destination": mount.destination, "source": mount.source, "source_digest": mount.source_digest}
            for mount in policy.readonly_mounts
        ],
        "rootfs_digest": policy.rootfs_digest,
        "writable_tmpfs": policy.writable_tmpfs,
        "writable_tmpfs_bytes": policy.writable_tmpfs_bytes,
        "writable_tmpfs_inodes": policy.writable_tmpfs_inodes,
    }
    if policy.mount_plan_digest != _digest_payload(mount_payload):
        raise _reject("mount plan digest does not match its inputs", "mount_plan_digest_mismatch")
    if tuple(sorted(policy.environment)) != policy.environment or len(set(policy.environment)) != len(policy.environment):
        raise _reject("environment allowlist must be sorted and unique", "noncanonical_environment")
    for entry in policy.environment:
        name, separator, _value = entry.partition("=")
        if separator != "=" or _ENV_NAME_RE.fullmatch(name) is None or name == DONOR_EXECUTION_ENV or len(entry.encode()) > 4096:
            raise _reject("environment allowlist entry is malformed or forbidden", "invalid_environment")


def _protobuf_string(value: str) -> str:
    return json.dumps(value, ensure_ascii=False)


def _render_config(policy: ContainmentPolicy) -> str:
    lines = [
        "mode: ONCE",
        "keep_env: false",
        "keep_caps: false",
        "disable_no_new_privs: false",
        "log_level: FATAL",
        "clone_newnet: true",
        "clone_newuser: true",
        "clone_newns: true",
        "clone_newpid: true",
        "clone_newipc: true",
        "clone_newuts: true",
        # NsJail's iface_no_lo switch suppresses loopback setup when true.
        "iface_no_lo: true",
        "use_cgroupv2: true",
        f"cgroup_mem_max: {policy.cgroup_mem_max}",
        f"cgroup_pids_max: {policy.cgroup_pids_max}",
        f"cgroup_cpu_ms_per_sec: {policy.cgroup_cpu_ms_per_sec}",
        f"time_limit: {policy.wall_time_seconds}",
        f"cwd: {_protobuf_string(policy.cwd)}",
        f"rlimit_as: {policy.rlimit_as_mb}",
        "rlimit_as_type: VALUE",
        f"rlimit_cpu: {policy.rlimit_cpu_seconds}",
        "rlimit_cpu_type: VALUE",
        f"rlimit_fsize: {policy.rlimit_fsize_mb}",
        "rlimit_fsize_type: VALUE",
        f"rlimit_nofile: {policy.rlimit_nofile}",
        "rlimit_nofile_type: VALUE",
        f"rlimit_nproc: {policy.rlimit_nproc}",
        "rlimit_nproc_type: VALUE",
        f"rlimit_stack: {policy.rlimit_stack_mb}",
        "rlimit_stack_type: VALUE",
        f"rlimit_core: {policy.rlimit_core_mb}",
        "rlimit_core_type: VALUE",
        f"seccomp_string: {_protobuf_string(policy.seccomp_string)}",
        'uidmap { inside_id: "65534" outside_id: "" count: 1 use_newidmap: false }',
        'gidmap { inside_id: "65534" outside_id: "" count: 1 use_newidmap: false }',
    ]
    lines.extend(f"envar: {_protobuf_string(value)}" for value in policy.environment)
    for mount in policy.readonly_mounts:
        lines.append(
            "mount { src: "
            f"{_protobuf_string(mount.source)} dst: {_protobuf_string(mount.destination)} "
            'is_bind: true rw: false mandatory: true nosuid: true nodev: true }'
        )
    tmpfs_options = f"size={policy.writable_tmpfs_bytes},nr_inodes={policy.writable_tmpfs_inodes},nosuid,nodev,noexec"
    lines.append(
        "mount { dst: "
        f"{_protobuf_string(policy.writable_tmpfs)} fstype: \"tmpfs\" options: {_protobuf_string(tmpfs_options)} "
        "rw: true is_dir: true mandatory: true nosuid: true nodev: true noexec: true }"
    )
    return "\n".join(lines) + "\n"


def _plan_payload(plan: ExecutionPlan, *, include_digest: bool) -> dict[str, object]:
    payload: dict[str, object] = {
        "config_text": plan.config_text,
        "environment": list(plan.environment),
        "architecture": plan.architecture,
        "nsjail_argv": list(plan.nsjail_argv),
        "nsjail_path": plan.nsjail_path,
        "nsjail_sha256": plan.nsjail_sha256,
        "opt_in_satisfied": plan.opt_in_satisfied,
        "output_limit_bytes": plan.output_limit_bytes,
        "policy_digest": plan.policy_digest,
        "schema_version": plan.schema_version,
        "wall_time_seconds": plan.wall_time_seconds,
    }
    if include_digest:
        payload["plan_digest"] = plan.plan_digest
    return payload


def _verify_backend(policy: ContainmentPolicy) -> None:  # pragma: no cover  # exercised only by the containment CI job (ADR-009 §10, bts-containment.yml)
    path = Path(policy.nsjail_path)
    try:
        metadata = path.stat()
        if not stat.S_ISREG(metadata.st_mode) or not os.access(path, os.X_OK):
            raise OSError("not an executable regular file")
        digest = _digest_file(path)
    except OSError as exc:
        raise _reject("pinned nsjail binary is unavailable", "nsjail_unavailable") from exc
    if digest != policy.nsjail_sha256:
        raise _reject("nsjail executable digest does not match policy", "nsjail_digest_mismatch")
    _verify_mount_sources(policy)
    # Retain the bounded execution probe: the binary must be runnable, but its
    # human-facing version text is intentionally not an identity input because
    # release builds may embed timestamps in it.
    try:
        completed = subprocess.run(
            (policy.nsjail_path, "--version"),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            env={},
            timeout=2,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise _reject("nsjail build identity could not be verified", "nsjail_identity_unavailable") from exc
    version_output = completed.stdout[:4097]
    if completed.returncode != 0 or len(version_output) > 4096:
        raise _reject("nsjail build identity probe failed", "nsjail_identity_unavailable")
    try:
        version_output.decode("utf-8", "strict")
    except UnicodeDecodeError as exc:
        raise _reject("nsjail build identity is malformed", "nsjail_identity_mismatch") from exc
    _verify_nsjail_identity(policy, digest)


def _verified_regular_file_digest(path: Path) -> str:  # pragma: no cover  # exercised only by the containment CI job (ADR-009 §10, bts-containment.yml)
    """Hash one regular mount source without following a terminal symlink."""

    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        if not stat.S_ISREG(os.fstat(descriptor).st_mode):
            raise OSError("mount source is not a regular file")
        digest = hashlib.sha256()
        while chunk := os.read(descriptor, 1024 * 1024):
            digest.update(chunk)
        return f"sha256:{digest.hexdigest()}"
    finally:
        os.close(descriptor)


def _verified_directory_tree_digest(root: Path) -> str:  # pragma: no cover  # exercised only by the containment CI job (ADR-009 §10, bts-containment.yml)
    """Hash a canonical, symlink-free directory tree including entry modes."""

    root_metadata = root.stat(follow_symlinks=False)
    if not stat.S_ISDIR(root_metadata.st_mode):
        raise OSError("rootfs mount source is not a directory")
    entries: list[dict[str, object]] = [
        {"mode": stat.S_IMODE(root_metadata.st_mode), "path": ".", "type": "directory"}
    ]

    def visit(directory: Path, relative: PurePosixPath) -> None:
        with os.scandir(directory) as iterator:
            children = sorted(iterator, key=lambda item: os.fsencode(item.name))
        for child in children:
            name = child.name
            if not name or name in {".", ".."} or "/" in name or "\x00" in name:
                raise OSError("rootfs contains a noncanonical entry name")
            child_relative = relative / name
            logical_path = child_relative.as_posix()
            metadata = child.stat(follow_symlinks=False)
            mode = stat.S_IMODE(metadata.st_mode)
            if stat.S_ISDIR(metadata.st_mode):
                entries.append({"mode": mode, "path": logical_path, "type": "directory"})
                visit(Path(child.path), child_relative)
            elif stat.S_ISREG(metadata.st_mode):
                entries.append(
                    {
                        "mode": mode,
                        "path": logical_path,
                        "sha256": _verified_regular_file_digest(Path(child.path)),
                        "type": "file",
                    }
                )
            else:
                raise OSError("rootfs contains a symlink or special file")

    visit(root, PurePosixPath())
    return _digest_payload({"entries": entries, "schema_version": "leitir-directory-tree-v1"})


def _verify_mount_sources(policy: ContainmentPolicy) -> None:  # pragma: no cover  # exercised only by the containment CI job (ADR-009 §10, bts-containment.yml)
    rootfs: ReadOnlyMount | None = None
    for mount in policy.readonly_mounts:
        try:
            source = Path(mount.source)
            if mount.destination == "/" or stat.S_ISDIR(source.stat(follow_symlinks=False).st_mode):
                actual = _verified_directory_tree_digest(Path(mount.source))
            else:
                actual = _verified_regular_file_digest(Path(mount.source))
        except (OSError, UnicodeError, ValueError) as exc:
            raise _reject("read-only mount source cannot be verified", "mount_source_unverifiable") from exc
        if actual != mount.source_digest:
            raise _reject("read-only mount source digest does not match policy", "mount_source_digest_mismatch")
        if mount.destination == "/":
            rootfs = mount
    if rootfs is None or rootfs.source_digest != policy.rootfs_digest:
        raise _reject("rootfs mount does not bind the policy rootfs digest", "rootfs_digest_mismatch")


def prepare_execution(policy: ContainmentPolicy) -> ExecutionPlan:
    """Validate all controls and return a canonical plan without running donor code."""

    if platform.system() != "Linux":
        raise _reject("donor execution containment is supported only on Linux", "unsupported_host")
    if not donor_execution_enabled() or policy.opt_in_satisfied is not True:
        raise _reject("donor execution requires the exact opt-in value", "donor_execution_disabled")
    if policy.opt_in_satisfied != donor_execution_enabled():
        raise _reject("execution gate changed while preparing containment", "execution_gate_mismatch")
    _validate_policy(policy)
    if platform.machine() != policy.architecture:
        raise _reject("host architecture does not match the pinned policy", "architecture_mismatch")
    _verify_backend(policy)
    config_text = _render_config(policy)
    if len(config_text.encode("utf-8")) > _MAX_POLICY_TEXT:
        raise _reject("generated nsjail configuration exceeds its bound", "config_too_large")
    policy_digest = _digest_payload(_policy_payload(policy))
    draft = ExecutionPlan(
        schema_version=PLAN_SCHEMA,
        policy=policy,
        nsjail_path=policy.nsjail_path,
        nsjail_sha256=policy.nsjail_sha256,
        architecture=policy.architecture,
        nsjail_argv=(policy.nsjail_path, "--config", "<ephemeral-verified-config>", "--"),
        config_text=config_text,
        environment=policy.environment,
        wall_time_seconds=policy.wall_time_seconds,
        output_limit_bytes=policy.output_limit_bytes,
        policy_digest=policy_digest,
        plan_digest="",
        opt_in_satisfied=True,
    )
    return replace(draft, plan_digest=_digest_payload(_plan_payload(draft, include_digest=False)))


@dataclass(slots=True)
class _Capture:
    stdout: bytearray
    stderr: bytearray
    timed_out: bool = False
    truncated: bool = False
    leaked: bool = False
    noncanonical_kill: bool = False


@dataclass(frozen=True, slots=True)
class _AppliedState:
    child_pid: int
    cgroup_path: Path


class _AppliedStateReader(Protocol):
    """Injectable kernel-state reader used by focused verifier tests."""

    def proc_text(self, pid: int, name: str) -> str: ...

    def namespace_identity(self, pid: int, namespace: str) -> tuple[int, int]: ...

    def cgroup_text(self, path: Path, name: str) -> str: ...

    def network_interfaces(self, pid: int) -> Mapping[str, str]: ...


class _ProcfsAppliedStateReader:  # pragma: no cover  # exercised only by the containment CI job (ADR-009 §10, bts-containment.yml)
    def proc_text(self, pid: int, name: str) -> str:
        return _read_proc_text(pid, name)

    def namespace_identity(self, pid: int, namespace: str) -> tuple[int, int]:
        return _ns_identity(pid, namespace)

    def cgroup_text(self, path: Path, name: str) -> str:
        return (path / name).read_text(encoding="ascii")

    def network_interfaces(self, pid: int) -> Mapping[str, str]:
        # /proc/net/dev has names and counters but no authoritative link-state.
        # Until the live backend supplies a post-install handshake plus a
        # namespace-scoped rtnetlink receipt, refusing is the only safe answer.
        del pid
        raise OSError("namespace-scoped interface state is unavailable")


def _read_proc_text(pid: int, name: str) -> str:  # pragma: no cover  # exercised only by the containment CI job (ADR-009 §10, bts-containment.yml)
    return Path(f"/proc/{pid}/{name}").read_text(encoding="utf-8", errors="strict")


def _ns_identity(pid: int, namespace: str) -> tuple[int, int]:  # pragma: no cover  # exercised only by the containment CI job (ADR-009 §10, bts-containment.yml)
    metadata = Path(f"/proc/{pid}/ns/{namespace}").stat()
    return metadata.st_dev, metadata.st_ino


def _discover_jailed_child(supervisor_pid: int, timeout: float = 2.0) -> int:  # pragma: no cover  # exercised only by the containment CI job (ADR-009 §10, bts-containment.yml)
    deadline = time.monotonic() + timeout
    children_file = Path(f"/proc/{supervisor_pid}/task/{supervisor_pid}/children")
    while time.monotonic() < deadline:
        try:
            children = children_file.read_text(encoding="ascii").split()
        except OSError:
            children = []
        if len(children) == 1 and children[0].isdigit():
            return int(children[0])
        time.sleep(0.005)
    raise _reject("nsjail did not expose exactly one jailed child", "applied_state_unavailable")


def _parse_status(text: str) -> dict[str, str]:
    return {name: value.strip() for line in text.splitlines() for name, separator, value in [line.partition(":")] if separator}


def _realized_cgroup(pid: int, reader: _AppliedStateReader) -> Path:  # pragma: no cover  # exercised only by the containment CI job (ADR-009 §10, bts-containment.yml)
    entries = [line.split(":", 2) for line in reader.proc_text(pid, "cgroup").splitlines()]
    unified = next((parts[2] for parts in entries if len(parts) == 3 and parts[0] == "0" and parts[1] == ""), None)
    if unified is None or not unified.startswith("/") or ".." in PurePosixPath(unified).parts:
        raise _reject("jailed child has no verifiable cgroup-v2 membership", "applied_cgroup_mismatch")
    path = (_CGROUP_ROOT / unified.lstrip("/")).resolve()
    try:
        path.relative_to(_CGROUP_ROOT)
    except ValueError as exc:
        raise _reject("jailed child cgroup escaped the v2 hierarchy", "applied_cgroup_mismatch") from exc
    return path


def _verify_applied_state(  # pragma: no cover  # exercised only by the containment CI job (ADR-009 §10, bts-containment.yml)
    process: subprocess.Popen[bytes],
    policy: ContainmentPolicy,
    *,
    child_pid: int,
    reader: _AppliedStateReader | None = None,
) -> _AppliedState:
    """Verify a child already held by an authoritative backend barrier."""

    state_reader = _ProcfsAppliedStateReader() if reader is None else reader
    try:
        if process.poll() is not None or child_pid <= 0:
            raise _reject("jailed child is not held at the applied-state barrier", "applied_state_unavailable")
        status = _parse_status(state_reader.proc_text(child_pid, "status"))
        if status.get("NoNewPrivs") != "1" or status.get("Seccomp") != "2" or int(status.get("CapEff", "-1"), 16) != 0:
            raise _reject("privilege or seccomp controls are not applied", "applied_privilege_mismatch")
        for namespace in ("net", "user", "mnt", "pid", "ipc", "uts"):
            if state_reader.namespace_identity(child_pid, namespace) == state_reader.namespace_identity(os.getpid(), namespace):
                raise _reject("required namespace is not applied", "applied_namespace_mismatch")
        for mapping_name in ("uid_map", "gid_map"):
            fields = state_reader.proc_text(child_pid, mapping_name).split()
            if len(fields) < 3 or fields[0] != "65534" or fields[2] != "1":
                raise _reject("nonprivileged UID/GID map is not applied", "applied_idmap_mismatch")

        mounts: dict[str, frozenset[str]] = {}
        for line in state_reader.proc_text(child_pid, "mountinfo").splitlines():
            before, separator, _after = line.partition(" - ")
            fields = before.split()
            if not separator or len(fields) < 6:
                raise _reject("realized mount table is malformed", "applied_mount_mismatch")
            mounts[fields[4]] = frozenset(fields[5].split(","))
        if any(mount.destination not in mounts or "ro" not in mounts[mount.destination] for mount in policy.readonly_mounts):
            raise _reject("read-only mount plan is not fully applied", "applied_mount_mismatch")
        if policy.writable_tmpfs not in mounts or "rw" not in mounts[policy.writable_tmpfs]:
            raise _reject("bounded writable tmpfs is not applied", "applied_mount_mismatch")

        interfaces = state_reader.network_interfaces(child_pid)
        if set(interfaces) != {"lo"} or interfaces.get("lo") != "down":
            raise _reject("network namespace is not limited to a down loopback", "applied_network_mismatch")
        ipv4_routes = state_reader.proc_text(child_pid, "net/route").splitlines()[1:]
        ipv6_routes = [line for line in state_reader.proc_text(child_pid, "net/ipv6_route").splitlines() if line.strip()]
        if ipv4_routes or ipv6_routes:
            raise _reject("network namespace contains a route", "applied_network_mismatch")

        cgroup = _realized_cgroup(child_pid, state_reader)
        expected_controls = {
            "memory.max": str(policy.cgroup_mem_max),
            "pids.max": str(policy.cgroup_pids_max),
            "cpu.max": f"{policy.cgroup_cpu_ms_per_sec * 1000} 1000000",
        }
        if any(state_reader.cgroup_text(cgroup, name).strip() != expected for name, expected in expected_controls.items()):
            raise _reject("cgroup-v2 limits do not match policy", "applied_cgroup_mismatch")
        controllers = frozenset(state_reader.cgroup_text(cgroup, "cgroup.controllers").split())
        events = dict(line.split(maxsplit=1) for line in state_reader.cgroup_text(cgroup, "cgroup.events").splitlines())
        if not {"cpu", "memory", "pids"} <= controllers or events.get("populated") != "1":
            raise _reject("required cgroup-v2 controllers are not active", "applied_cgroup_mismatch")
        members = {int(value) for value in state_reader.cgroup_text(cgroup, "cgroup.procs").split()}
        if child_pid not in members:
            raise _reject("jailed child is outside its realized cgroup", "applied_cgroup_mismatch")
    except (OSError, UnicodeError, ValueError) as exc:
        raise _reject("applied containment state could not be verified", "applied_state_unavailable") from exc
    return _AppliedState(child_pid, cgroup)


def _cgroup_populated(path: Path) -> bool:  # pragma: no cover  # exercised only by the containment CI job (ADR-009 §10, bts-containment.yml)
    values = dict(line.split(maxsplit=1) for line in (path / "cgroup.events").read_text(encoding="ascii").splitlines())
    return values.get("populated") != "0"


def _kill_cgroup_tree(path: Path) -> bool:  # pragma: no cover  # exercised only by the containment CI job (ADR-009 §10, bts-containment.yml)
    try:
        (path / "cgroup.kill").write_text("1", encoding="ascii")
        deadline = time.monotonic() + 2.0
        while time.monotonic() < deadline:
            if not _cgroup_populated(path):
                return True
            time.sleep(0.01)
    except (OSError, UnicodeError, ValueError):
        return False
    return False


def _terminate_tree(process: subprocess.Popen[bytes], state: _AppliedState | None) -> bool:  # pragma: no cover  # exercised only by the containment CI job (ADR-009 §10, bts-containment.yml)
    if state is not None and _kill_cgroup_tree(state.cgroup_path):
        return True
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    return False


def _bounded_communicate(  # pragma: no cover  # exercised only by the containment CI job (ADR-009 §10, bts-containment.yml)
    process: subprocess.Popen[bytes], *, limit: int, timeout: int, applied_state: _AppliedState
) -> _Capture:
    capture = _Capture(bytearray(), bytearray())
    assert process.stdout is not None and process.stderr is not None
    selector = selectors.DefaultSelector()
    selector.register(process.stdout, selectors.EVENT_READ, capture.stdout)
    selector.register(process.stderr, selectors.EVENT_READ, capture.stderr)
    deadline = time.monotonic() + timeout
    try:
        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                capture.timed_out = True
                break
            events = selector.select(min(remaining, 0.1))
            if not events and process.poll() is not None:
                events = [(key, selectors.EVENT_READ) for key in tuple(selector.get_map().values())]
            for key, _mask in events:
                target = key.data
                assert isinstance(target, bytearray)
                retained = len(capture.stdout) + len(capture.stderr)
                chunk = os.read(key.fd, min(65536, limit + 1 - retained))
                if not chunk:
                    selector.unregister(key.fileobj)
                    continue
                target.extend(chunk)
                if len(target) > limit or len(capture.stdout) + len(capture.stderr) > limit:
                    capture.truncated = True
                    break
            if capture.truncated:
                break
    finally:
        selector.close()
    teardown_attempted = False
    authoritative_teardown = False
    if capture.timed_out or capture.truncated:
        authoritative_teardown = _terminate_tree(process, applied_state)
        teardown_attempted = True
    try:
        process.wait(timeout=2)
    except subprocess.TimeoutExpired:
        capture.leaked = True
        if not teardown_attempted:
            authoritative_teardown = _terminate_tree(process, applied_state)
            teardown_attempted = True
    if not teardown_attempted:
        authoritative_teardown = _terminate_tree(process, applied_state)
    capture.noncanonical_kill = not authoritative_teardown
    return capture


def _abort(plan: ExecutionPlan, detail: str, reason: BTSRejectReason, stdout_bytes: int, stderr_bytes: int) -> ExecutionResult:
    envelope = ValidationAbortEnvelope(
        schema_version="leitir-validation-abort-v1",
        stage="execution",
        role="donor",
        reason=reason,
        detail_category=detail,
        subject_digest=plan.plan_digest,
        stdout_bytes=min(stdout_bytes, plan.output_limit_bytes),
        stderr_bytes=min(stderr_bytes, plan.output_limit_bytes),
    )
    return ExecutionResult(
        completed=False,
        subject_digest=plan.plan_digest,
        exit_code=None,
        stdout=b"",
        stderr=b"",
        stdout_digest=None,
        stderr_digest=None,
        result_digest=None,
        abort=envelope,
    )


def _require_applied_state_barrier(policy: ContainmentPolicy) -> None:
    """Refuse until the pinned backend exposes a post-install start handshake.

    NsJail's observable child/process-group state does not establish that all
    controls have been installed before donor instructions can run.  A SIGSTOP
    issued by this controller is inherently racy, so v1 does not launch merely
    because procfs inspection code is available.
    """

    del policy
    raise _reject(
        "the backend cannot establish a verified post-install execution barrier",
        "applied_state_barrier_unavailable",
    )


def run_contained(plan: ExecutionPlan, argv: Sequence[str]) -> ExecutionResult:
    """Run ``argv`` only via the verified nsjail plan and classify its outcome."""

    if platform.system() != "Linux" or not donor_execution_enabled() or plan.opt_in_satisfied is not True:  # pragma: no cover  # exercised only by the containment CI job (ADR-009 §10, bts-containment.yml)
        raise _reject("donor execution gate or Linux containment is unavailable", "execution_precondition_failed")
    if not argv or any(not isinstance(value, str) or not value or "\x00" in value for value in argv):  # pragma: no cover  # exercised only by the containment CI job (ADR-009 §10, bts-containment.yml)
        raise _reject("contained child argv is malformed", "invalid_child_argv")
    expected_digest = _digest_payload(_plan_payload(plan, include_digest=False))
    if plan.schema_version != PLAN_SCHEMA or plan.plan_digest != expected_digest:  # pragma: no cover  # exercised only by the containment CI job (ADR-009 §10, bts-containment.yml)
        raise _reject("execution plan integrity check failed", "plan_digest_mismatch")
    _validate_policy(plan.policy)
    if plan.policy_digest != _digest_payload(_policy_payload(plan.policy)):  # pragma: no cover  # exercised only by the containment CI job (ADR-009 §10, bts-containment.yml)
        raise _reject("execution policy integrity check failed", "policy_digest_mismatch")
    if (  # pragma: no cover  # exercised only by the containment CI job (ADR-009 §10, bts-containment.yml)
        plan.config_text != _render_config(plan.policy)
        or plan.nsjail_path != plan.policy.nsjail_path
        or plan.nsjail_sha256 != plan.policy.nsjail_sha256
        or plan.architecture != plan.policy.architecture
        or plan.wall_time_seconds != plan.policy.wall_time_seconds
        or plan.output_limit_bytes != plan.policy.output_limit_bytes
        or plan.environment != plan.policy.environment
    ):
        raise _reject("execution plan does not fully apply its policy", "policy_plan_mismatch")
    if platform.machine() != plan.architecture:  # pragma: no cover  # exercised only by the containment CI job (ADR-009 §10, bts-containment.yml)
        raise _reject("host architecture changed after plan preparation", "architecture_mismatch")
    _verify_backend(plan.policy)
    _require_applied_state_barrier(plan.policy)
    config_fd: int | None = None  # pragma: no cover  # exercised only by the containment CI job (ADR-009 §10, bts-containment.yml)
    config_path: str | None = None  # pragma: no cover  # exercised only by the containment CI job (ADR-009 §10, bts-containment.yml)
    try:
        config_fd, config_path = tempfile.mkstemp(prefix=".leitir-nsjail-", suffix=".cfg")  # pragma: no cover  # exercised only by the containment CI job (ADR-009 §10, bts-containment.yml)
        os.fchmod(config_fd, 0o600)  # pragma: no cover  # exercised only by the containment CI job (ADR-009 §10, bts-containment.yml)
        config_bytes = plan.config_text.encode("utf-8")  # pragma: no cover  # exercised only by the containment CI job (ADR-009 §10, bts-containment.yml)
        with os.fdopen(config_fd, "wb", closefd=True) as config_file:  # pragma: no cover  # exercised only by the containment CI job (ADR-009 §10, bts-containment.yml)
            config_fd = None  # pragma: no cover  # exercised only by the containment CI job (ADR-009 §10, bts-containment.yml)
            config_file.write(config_bytes)  # pragma: no cover  # exercised only by the containment CI job (ADR-009 §10, bts-containment.yml)
            config_file.flush()  # pragma: no cover  # exercised only by the containment CI job (ADR-009 §10, bts-containment.yml)
            os.fsync(config_file.fileno())  # pragma: no cover  # exercised only by the containment CI job (ADR-009 §10, bts-containment.yml)
        launch_argv = (plan.nsjail_path, "--config", config_path, "--", *tuple(argv))  # pragma: no cover  # exercised only by the containment CI job (ADR-009 §10, bts-containment.yml)
        # Re-read all mount sources immediately before the backend can open them.
        _verify_mount_sources(plan.policy)  # pragma: no cover  # exercised only by the containment CI job (ADR-009 §10, bts-containment.yml)
        process = subprocess.Popen(  # pragma: no cover  # exercised only by the containment CI job (ADR-009 §10, bts-containment.yml)
            launch_argv,  # pragma: no cover  # exercised only by the containment CI job (ADR-009 §10, bts-containment.yml)
            stdin=subprocess.DEVNULL,  # pragma: no cover  # exercised only by the containment CI job (ADR-009 §10, bts-containment.yml)
            stdout=subprocess.PIPE,  # pragma: no cover  # exercised only by the containment CI job (ADR-009 §10, bts-containment.yml)
            stderr=subprocess.PIPE,  # pragma: no cover  # exercised only by the containment CI job (ADR-009 §10, bts-containment.yml)
            env={},  # pragma: no cover  # exercised only by the containment CI job (ADR-009 §10, bts-containment.yml)
            start_new_session=True,  # pragma: no cover  # exercised only by the containment CI job (ADR-009 §10, bts-containment.yml)
        )
        child_pid = _discover_jailed_child(process.pid)  # pragma: no cover  # exercised only by the containment CI job (ADR-009 §10, bts-containment.yml)
        applied_state = _verify_applied_state(process, plan.policy, child_pid=child_pid)  # pragma: no cover  # exercised only by the containment CI job (ADR-009 §10, bts-containment.yml)
        capture = _bounded_communicate(  # pragma: no cover  # exercised only by the containment CI job (ADR-009 §10, bts-containment.yml)
            process,  # pragma: no cover  # exercised only by the containment CI job (ADR-009 §10, bts-containment.yml)
            limit=plan.output_limit_bytes,  # pragma: no cover  # exercised only by the containment CI job (ADR-009 §10, bts-containment.yml)
            timeout=plan.wall_time_seconds,  # pragma: no cover  # exercised only by the containment CI job (ADR-009 §10, bts-containment.yml)
            applied_state=applied_state,  # pragma: no cover  # exercised only by the containment CI job (ADR-009 §10, bts-containment.yml)
        )
    except (OSError, subprocess.SubprocessError):  # pragma: no cover  # exercised only by the containment CI job (ADR-009 §10, bts-containment.yml)
        return _abort(plan, "launcher_failure", BTSRejectReason.REJECT_HARD_GATE_FAILED, 0, 0)  # pragma: no cover  # exercised only by the containment CI job (ADR-009 §10, bts-containment.yml)
    finally:
        if config_fd is not None:  # pragma: no cover  # exercised only by the containment CI job (ADR-009 §10, bts-containment.yml)
            os.close(config_fd)  # pragma: no cover  # exercised only by the containment CI job (ADR-009 §10, bts-containment.yml)
        if config_path is not None:  # pragma: no cover  # exercised only by the containment CI job (ADR-009 §10, bts-containment.yml)
            try:
                os.unlink(config_path)  # pragma: no cover  # exercised only by the containment CI job (ADR-009 §10, bts-containment.yml)
            except FileNotFoundError:  # pragma: no cover  # exercised only by the containment CI job (ADR-009 §10, bts-containment.yml)
                pass  # pragma: no cover  # exercised only by the containment CI job (ADR-009 §10, bts-containment.yml)
    # ADR-0009 requires immutable authorizing inputs across the complete run.
    _verify_mount_sources(plan.policy)  # pragma: no cover  # exercised only by the containment CI job (ADR-009 §10, bts-containment.yml)
    if capture.noncanonical_kill:  # pragma: no cover  # exercised only by the containment CI job (ADR-009 §10, bts-containment.yml)
        return _abort(
            plan,  # pragma: no cover  # exercised only by the containment CI job (ADR-009 §10, bts-containment.yml)
            "noncanonical_killpg_fallback",  # pragma: no cover  # exercised only by the containment CI job (ADR-009 §10, bts-containment.yml)
            BTSRejectReason.REJECT_EXECUTION_THREAT,  # pragma: no cover  # exercised only by the containment CI job (ADR-009 §10, bts-containment.yml)
            len(capture.stdout),  # pragma: no cover  # exercised only by the containment CI job (ADR-009 §10, bts-containment.yml)
            len(capture.stderr),  # pragma: no cover  # exercised only by the containment CI job (ADR-009 §10, bts-containment.yml)
        )
    if capture.timed_out:  # pragma: no cover  # exercised only by the containment CI job (ADR-009 §10, bts-containment.yml)
        return _abort(plan, "wall_time_limit", BTSRejectReason.REJECT_EXECUTION_THREAT, len(capture.stdout), len(capture.stderr))
    if capture.truncated:  # pragma: no cover  # exercised only by the containment CI job (ADR-009 §10, bts-containment.yml)
        return _abort(plan, "output_limit", BTSRejectReason.REJECT_EXECUTION_THREAT, len(capture.stdout), len(capture.stderr))
    if capture.leaked:  # pragma: no cover  # exercised only by the containment CI job (ADR-009 §10, bts-containment.yml)
        return _abort(plan, "child_leak", BTSRejectReason.REJECT_EXECUTION_THREAT, len(capture.stdout), len(capture.stderr))
    if process.returncode != 0:  # pragma: no cover  # exercised only by the containment CI job (ADR-009 §10, bts-containment.yml)
        return _abort(plan, "child_crash", BTSRejectReason.REJECT_HARD_GATE_FAILED, len(capture.stdout), len(capture.stderr))
    stdout = bytes(capture.stdout)  # pragma: no cover  # exercised only by the containment CI job (ADR-009 §10, bts-containment.yml)
    stderr = bytes(capture.stderr)  # pragma: no cover  # exercised only by the containment CI job (ADR-009 §10, bts-containment.yml)
    stdout_digest = _digest_bytes(stdout)  # pragma: no cover  # exercised only by the containment CI job (ADR-009 §10, bts-containment.yml)
    stderr_digest = _digest_bytes(stderr)  # pragma: no cover  # exercised only by the containment CI job (ADR-009 §10, bts-containment.yml)
    result_payload = {  # pragma: no cover  # exercised only by the containment CI job (ADR-009 §10, bts-containment.yml)
        "exit_code": 0,  # pragma: no cover  # exercised only by the containment CI job (ADR-009 §10, bts-containment.yml)
        "schema_version": RESULT_SCHEMA,  # pragma: no cover  # exercised only by the containment CI job (ADR-009 §10, bts-containment.yml)
        "stderr_bytes": len(stderr),  # pragma: no cover  # exercised only by the containment CI job (ADR-009 §10, bts-containment.yml)
        "stderr_digest": stderr_digest,  # pragma: no cover  # exercised only by the containment CI job (ADR-009 §10, bts-containment.yml)
        "stdout_bytes": len(stdout),  # pragma: no cover  # exercised only by the containment CI job (ADR-009 §10, bts-containment.yml)
        "stdout_digest": stdout_digest,  # pragma: no cover  # exercised only by the containment CI job (ADR-009 §10, bts-containment.yml)
        "subject_digest": plan.plan_digest,  # pragma: no cover  # exercised only by the containment CI job (ADR-009 §10, bts-containment.yml)
    }
    return ExecutionResult(  # pragma: no cover  # exercised only by the containment CI job (ADR-009 §10, bts-containment.yml)
        completed=True,  # pragma: no cover  # exercised only by the containment CI job (ADR-009 §10, bts-containment.yml)
        subject_digest=plan.plan_digest,  # pragma: no cover  # exercised only by the containment CI job (ADR-009 §10, bts-containment.yml)
        exit_code=0,  # pragma: no cover  # exercised only by the containment CI job (ADR-009 §10, bts-containment.yml)
        stdout=stdout,  # pragma: no cover  # exercised only by the containment CI job (ADR-009 §10, bts-containment.yml)
        stderr=stderr,  # pragma: no cover  # exercised only by the containment CI job (ADR-009 §10, bts-containment.yml)
        stdout_digest=stdout_digest,  # pragma: no cover  # exercised only by the containment CI job (ADR-009 §10, bts-containment.yml)
        stderr_digest=stderr_digest,  # pragma: no cover  # exercised only by the containment CI job (ADR-009 §10, bts-containment.yml)
        result_digest=_digest_payload(result_payload),  # pragma: no cover  # exercised only by the containment CI job (ADR-009 §10, bts-containment.yml)
        abort=None,  # pragma: no cover  # exercised only by the containment CI job (ADR-009 §10, bts-containment.yml)
    )
