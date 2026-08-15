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

from leitir.bts_errors import BTSRejectReason, TransplantError

DONOR_EXECUTION_ENV = "LEITIR_ENABLE_DONOR_EXECUTION"
POLICY_SCHEMA = "leitir-containment-policy-v1"
PLAN_SCHEMA = "leitir-execution-plan-v1"
RESULT_SCHEMA = "leitir-execution-result-v1"
_DIGEST_RE = re.compile(r"sha256:[0-9a-f]{64}\Z")
_NSJAIL_VERSION_RE = re.compile(r"nsjail@([0-9a-f]{40})\Z")
_MAX_NSJAIL_PROBE_OUTPUT_BYTES = 64 * 1024
_ENV_NAME_RE = re.compile(r"[A-Z_][A-Z0-9_]*\Z")
_MAX_POLICY_TEXT = 64 * 1024
_CGROUP_ROOT = Path("/sys/fs/cgroup")
STARTUP_ATTESTATION_SCHEMA = "leitir-contained-startup-attestation-v1"
_ATTESTED_NAMESPACES = ("net", "user", "mnt", "pid", "ipc", "uts")
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
    # CPython probes executable accessibility while resolving its startup paths.
    ACCESS = "access"
    BRK = "brk"
    CLOCK_GETTIME = "clock_gettime"
    CLOSE = "close"
    EXECVE = "execve"
    EXIT = "exit"
    EXIT_GROUP = "exit_group"
    FCNTL = "fcntl"
    # Kafel's amd64 syscall table names syscall 5 ``newfstat`` (the kernel
    # spelling) rather than libc's ``fstat`` alias.
    FSTAT = "newfstat"
    FUTEX = "futex"
    GETCWD = "getcwd"
    GETDENTS64 = "getdents64"
    GETPID = "getpid"
    # glibc records the calling thread while initializing thread-local state.
    GETTID = "gettid"
    GETRANDOM = "getrandom"
    LSEEK = "lseek"
    MMAP = "mmap"
    MPROTECT = "mprotect"
    MUNMAP = "munmap"
    NEWFSTATAT = "newfstatat"
    OPENAT = "openat"
    # The cold interpreter still opens a small number of legacy absolute paths.
    OPEN = "open"
    # CPython reads import metadata at an explicit file offset during startup.
    PREAD64 = "pread64"
    PRLIMIT64 = "prlimit64"
    READ = "read"
    READLINK = "readlink"
    READLINKAT = "readlinkat"
    RT_SIGACTION = "rt_sigaction"
    RT_SIGPROCMASK = "rt_sigprocmask"
    # glibc queries CPU affinity before selecting its startup runtime settings.
    SCHED_GETAFFINITY = "sched_getaffinity"
    SET_ROBUST_LIST = "set_robust_list"
    SET_TID_ADDRESS = "set_tid_address"
    # glibc >= 2.35 registers restartable sequences during process startup.
    RSEQ = "rseq"
    # Kafel's amd64 table has no ``stat`` identifier: pathname metadata is
    # covered by ``newfstatat`` (and descriptor metadata by ``newfstat``).
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


def _render_config(policy: ContainmentPolicy, *, startup_environment: tuple[str, ...] = ()) -> str:
    lines = [
        "mode: ONCE",
        "keep_env: false",
        "keep_caps: false",
        "disable_no_new_privs: false",
        # NsJail's mount_proc is a read-only procfs view for the freshly cloned
        # PID namespace.  The immutable runner uses it for its startup receipt.
        "mount_proc: true",
        "log_level: FATAL",
        "clone_newnet: true",
        "clone_newuser: true",
        "clone_newns: true",
        "clone_newpid: true",
        "clone_newipc: true",
        "clone_newuts: true",
        "clone_newcgroup: true",
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
    lines.extend(f"envar: {_protobuf_string(value)}" for value in (*policy.environment, *startup_environment))
    for mount in policy.readonly_mounts:
        # NsJail applies the user mapping before it builds this mount tree.  Do
        # not let its source-path heuristic misclassify a rootfs below a
        # non-traversable CI temporary directory as a file mount.
        lines.append(
            "mount { src: "
            f"{_protobuf_string(mount.source)} dst: {_protobuf_string(mount.destination)} "
            'fstype: "bind" is_bind: true rw: false is_dir: true mandatory: true nosuid: true nodev: true }'
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
    # Retain the bounded liveness probe: the binary must be runnable, but its
    # human-facing help text is intentionally not an identity input because
    # release builds may embed timestamps in it. The pinned upstream build does
    # not implement --version; --help deliberately exits nonzero after usage.
    process: subprocess.Popen[bytes] | None = None
    try:
        process = subprocess.Popen(
            (policy.nsjail_path, "--help"),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            env={},
        )
        if process.stdout is None:
            raise OSError("nsjail probe has no output pipe")
        probe_output = process.stdout.read(_MAX_NSJAIL_PROBE_OUTPUT_BYTES + 1)
        process.wait(timeout=2)
    except (OSError, subprocess.TimeoutExpired) as exc:
        if process is not None:
            process.kill()
            process.wait()
        raise _reject("nsjail build identity could not be verified", "nsjail_identity_unavailable") from exc
    finally:
        if process is not None and process.stdout is not None:
            process.stdout.close()
    if len(probe_output) > _MAX_NSJAIL_PROBE_OUTPUT_BYTES:
        raise _reject("nsjail build identity probe failed", "nsjail_identity_unavailable")
    try:
        probe_output.decode("utf-8", "strict")
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


def _ns_identity(pid: int, namespace: str) -> tuple[int, int]:  # pragma: no cover  # exercised only by the containment CI job (ADR-009 §10, bts-containment.yml)
    metadata = Path(f"/proc/{pid}/ns/{namespace}").stat()
    return metadata.st_dev, metadata.st_ino


def _startup_attestation_environment() -> tuple[str, ...]:  # pragma: no cover - requires Linux namespace backend
    """Bind the immutable child probe to this launcher's namespace identities.

    ``keep_env: false`` prevents an ambient environment from reaching the
    child.  These six values are the sole per-launch additions and are rendered
    into nsjail's config after the plan has passed its static integrity check.
    """

    values: list[str] = []
    for namespace in _ATTESTED_NAMESPACES:
        device, inode = _ns_identity(os.getpid(), namespace)
        values.append(f"LEITIR_PARENT_NS_{namespace.upper()}={device}:{inode}")
    return tuple(values)


def startup_attestation_from_proc(
    status_text: str,
    namespace_identities: Mapping[str, tuple[int, int]],
    parent_namespace_identities: Mapping[str, tuple[int, int]],
    *,
    pid: int,
) -> dict[str, object]:
    """Build the canonical child receipt from injectable procfs observations.

    The immutable rootfs runner implements this same small stdlib projection at
    startup.  Keeping this function pure gives the verifier tests faked procfs
    coverage without treating parent-side inspection as a release barrier.
    """

    status = _parse_status(status_text)
    try:
        seccomp_mode = int(status["Seccomp"])
        no_new_privs = status["NoNewPrivs"] == "1"
        namespace_mismatch = all(
            namespace_identities[namespace] != parent_namespace_identities[namespace]
            for namespace in _ATTESTED_NAMESPACES
        )
    except (KeyError, TypeError, ValueError) as exc:
        raise ValueError("startup procfs receipt is malformed") from exc
    return {
        "namespace_mismatch": namespace_mismatch,
        "no_new_privs": no_new_privs,
        "pid_namespace_init": pid == 1,
        "schema_version": STARTUP_ATTESTATION_SCHEMA,
        "seccomp_mode": seccomp_mode,
    }


def validate_startup_attestation(value: object) -> None:
    """Fail closed unless the runner reports its pre-execution kernel receipt.

    ``mount_proc`` makes cloned namespace identities and status available to
    the immutable rootfs runner.  The runner snapshots injected parent
    identities and emits this receipt before opening any relocated or donor
    input; this validator intentionally accepts no weaker shape.
    """

    if not isinstance(value, Mapping) or set(value) != {
        "namespace_mismatch", "no_new_privs", "pid_namespace_init", "schema_version", "seccomp_mode"
    }:
        raise ValueError("startup containment attestation has an invalid shape")
    if value.get("schema_version") != STARTUP_ATTESTATION_SCHEMA:
        raise ValueError("startup containment attestation has an unsupported schema")
    if type(value.get("namespace_mismatch")) is not bool or value["namespace_mismatch"] is not True:
        raise ValueError("startup containment attestation did not observe a namespace boundary")
    if type(value.get("pid_namespace_init")) is not bool or value["pid_namespace_init"] is not True:
        raise ValueError("startup containment attestation did not observe PID namespace init")
    if type(value.get("no_new_privs")) is not bool or type(value.get("seccomp_mode")) is not int:
        raise ValueError("startup containment privilege receipt is malformed")
    if value["seccomp_mode"] != 2 and value["no_new_privs"] is not True:
        raise ValueError("startup containment privilege receipt is not applied")


def _parse_status(text: str) -> dict[str, str]:
    return {name: value.strip() for line in text.splitlines() for name, separator, value in [line.partition(":")] if separator}


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
    process: subprocess.Popen[bytes], *, limit: int, timeout: int, applied_state: _AppliedState | None
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
    if not teardown_attempted and applied_state is not None:
        authoritative_teardown = _terminate_tree(process, applied_state)
    elif not teardown_attempted and process.returncode is None:
        authoritative_teardown = _terminate_tree(process, None)
    elif not teardown_attempted:
        # A cleanly exited direct child has no remaining process tree to tear
        # down.  Do not manufacture a cgroup receipt after the fact.
        authoritative_teardown = True
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
    config_fd: int | None = None  # pragma: no cover  # exercised only by the containment CI job (ADR-009 §10, bts-containment.yml)
    config_path: str | None = None  # pragma: no cover  # exercised only by the containment CI job (ADR-009 §10, bts-containment.yml)
    try:
        config_fd, config_path = tempfile.mkstemp(prefix=".leitir-nsjail-", suffix=".cfg")  # pragma: no cover  # exercised only by the containment CI job (ADR-009 §10, bts-containment.yml)
        os.fchmod(config_fd, 0o600)  # pragma: no cover  # exercised only by the containment CI job (ADR-009 §10, bts-containment.yml)
        # The static plan is integrity-bound.  Parent namespace identities are
        # launch facts, not authorization inputs, and are consumed solely by
        # the immutable child startup probe.
        config_bytes = _render_config(
            plan.policy, startup_environment=_startup_attestation_environment()
        ).encode("utf-8")  # pragma: no cover  # exercised only by the containment CI job (ADR-009 §10, bts-containment.yml)
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
        capture = _bounded_communicate(  # pragma: no cover  # exercised only by the containment CI job (ADR-009 §10, bts-containment.yml)
            process,  # pragma: no cover  # exercised only by the containment CI job (ADR-009 §10, bts-containment.yml)
            limit=plan.output_limit_bytes,  # pragma: no cover  # exercised only by the containment CI job (ADR-009 §10, bts-containment.yml)
            timeout=plan.wall_time_seconds,  # pragma: no cover  # exercised only by the containment CI job (ADR-009 §10, bts-containment.yml)
            # Parent-side discovery cannot provide a race-free launch barrier;
            # the immutable child runner emits the authoritative startup
            # receipt before it opens relocated or donor input.
            applied_state=None,  # pragma: no cover  # exercised only by the containment CI job (ADR-009 §10, bts-containment.yml)
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
