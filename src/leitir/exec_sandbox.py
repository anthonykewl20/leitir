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
from pathlib import Path, PurePosixPath

from leitir.bts_errors import BTSRejectReason, TransplantError

DONOR_EXECUTION_ENV = "LEITIR_ENABLE_DONOR_EXECUTION"
POLICY_SCHEMA = "leitir-containment-policy-v1"
PLAN_SCHEMA = "leitir-execution-plan-v1"
RESULT_SCHEMA = "leitir-execution-result-v1"
_DIGEST_RE = re.compile(r"sha256:[0-9a-f]{64}\Z")
_ENV_NAME_RE = re.compile(r"[A-Z_][A-Z0-9_]*\Z")
_MAX_POLICY_TEXT = 64 * 1024


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
    seccomp_string: str
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
    if any(value is not True for value in namespace_values) or policy.iface_no_lo is not False:
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
    if not policy.seccomp_string.strip() or len(policy.seccomp_string.encode("utf-8")) > _MAX_POLICY_TEXT:
        raise _reject("a bounded nonempty seccomp policy is required", "invalid_seccomp_policy")
    seccomp_upper = policy.seccomp_string.upper()
    if "DEFAULT" not in seccomp_upper or not any(word in seccomp_upper for word in ("KILL", "ERRNO", "TRAP")):
        raise _reject("seccomp policy must declare default-deny behavior", "seccomp_not_default_deny")
    forbidden_syscalls = (
        "ACCEPT",
        "BIND",
        "BPF",
        "CONNECT",
        "IOCTL",
        "KEYCTL",
        "LISTEN",
        "MOUNT",
        "PTRACE",
        "REBOOT",
        "RECVFROM",
        "SENDTO",
        "SETNS",
        "SOCKET",
        "UMOUNT",
        "UNSHARE",
    )
    if any(re.search(rf"\b{syscall}\w*\b", seccomp_upper) for syscall in forbidden_syscalls):
        raise _reject("seccomp allowlist mentions a policy-forbidden syscall", "seccomp_forbidden_syscall")
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
        "iface_no_lo: false",
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


def _verify_backend(policy: ContainmentPolicy) -> None:
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
    version = completed.stdout[:4097]
    if completed.returncode != 0 or len(version) > 4096:
        raise _reject("nsjail build identity probe failed", "nsjail_identity_unavailable")
    try:
        rendered_version = version.decode("utf-8", "strict").rstrip("\r\n")
    except UnicodeDecodeError as exc:
        raise _reject("nsjail build identity is malformed", "nsjail_identity_mismatch") from exc
    if rendered_version != policy.nsjail_version or policy.nsjail_build_identity != _digest_bytes(version):
        raise _reject("nsjail release/build identity does not match policy", "nsjail_identity_mismatch")


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


def _bounded_communicate(process: subprocess.Popen[bytes], *, limit: int, timeout: int) -> _Capture:
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
    if capture.timed_out or capture.truncated:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
    try:
        process.wait(timeout=2)
    except subprocess.TimeoutExpired:
        capture.leaked = True
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
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

    if platform.system() != "Linux" or not donor_execution_enabled() or plan.opt_in_satisfied is not True:
        raise _reject("donor execution gate or Linux containment is unavailable", "execution_precondition_failed")
    if not argv or any(not isinstance(value, str) or not value or "\x00" in value for value in argv):
        raise _reject("contained child argv is malformed", "invalid_child_argv")
    expected_digest = _digest_payload(_plan_payload(plan, include_digest=False))
    if plan.schema_version != PLAN_SCHEMA or plan.plan_digest != expected_digest:
        raise _reject("execution plan integrity check failed", "plan_digest_mismatch")
    _validate_policy(plan.policy)
    if plan.policy_digest != _digest_payload(_policy_payload(plan.policy)):
        raise _reject("execution policy integrity check failed", "policy_digest_mismatch")
    if (
        plan.config_text != _render_config(plan.policy)
        or plan.nsjail_path != plan.policy.nsjail_path
        or plan.nsjail_sha256 != plan.policy.nsjail_sha256
        or plan.architecture != plan.policy.architecture
        or plan.wall_time_seconds != plan.policy.wall_time_seconds
        or plan.output_limit_bytes != plan.policy.output_limit_bytes
        or plan.environment != plan.policy.environment
    ):
        raise _reject("execution plan does not fully apply its policy", "policy_plan_mismatch")
    if platform.machine() != plan.architecture:
        raise _reject("host architecture changed after plan preparation", "architecture_mismatch")
    _verify_backend(plan.policy)
    config_fd: int | None = None
    config_path: str | None = None
    try:
        config_fd, config_path = tempfile.mkstemp(prefix=".leitir-nsjail-", suffix=".cfg")
        os.fchmod(config_fd, 0o600)
        config_bytes = plan.config_text.encode("utf-8")
        with os.fdopen(config_fd, "wb", closefd=True) as config_file:
            config_fd = None
            config_file.write(config_bytes)
            config_file.flush()
            os.fsync(config_file.fileno())
        launch_argv = (plan.nsjail_path, "--config", config_path, "--", *tuple(argv))
        process = subprocess.Popen(
            launch_argv,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env={},
            start_new_session=True,
        )
        capture = _bounded_communicate(process, limit=plan.output_limit_bytes, timeout=plan.wall_time_seconds)
    except (OSError, subprocess.SubprocessError):
        return _abort(plan, "launcher_failure", BTSRejectReason.REJECT_HARD_GATE_FAILED, 0, 0)
    finally:
        if config_fd is not None:
            os.close(config_fd)
        if config_path is not None:
            try:
                os.unlink(config_path)
            except FileNotFoundError:
                pass
    if capture.timed_out:
        return _abort(plan, "wall_time_limit", BTSRejectReason.REJECT_EXECUTION_THREAT, len(capture.stdout), len(capture.stderr))
    if capture.truncated:
        return _abort(plan, "output_limit", BTSRejectReason.REJECT_EXECUTION_THREAT, len(capture.stdout), len(capture.stderr))
    if capture.leaked:
        return _abort(plan, "child_leak", BTSRejectReason.REJECT_EXECUTION_THREAT, len(capture.stdout), len(capture.stderr))
    if process.returncode != 0:
        return _abort(plan, "child_crash", BTSRejectReason.REJECT_HARD_GATE_FAILED, len(capture.stdout), len(capture.stderr))
    stdout = bytes(capture.stdout)
    stderr = bytes(capture.stderr)
    stdout_digest = _digest_bytes(stdout)
    stderr_digest = _digest_bytes(stderr)
    result_payload = {
        "exit_code": 0,
        "schema_version": RESULT_SCHEMA,
        "stderr_bytes": len(stderr),
        "stderr_digest": stderr_digest,
        "stdout_bytes": len(stdout),
        "stdout_digest": stdout_digest,
        "subject_digest": plan.plan_digest,
    }
    return ExecutionResult(
        completed=True,
        subject_digest=plan.plan_digest,
        exit_code=0,
        stdout=stdout,
        stderr=stderr,
        stdout_digest=stdout_digest,
        stderr_digest=stderr_digest,
        result_digest=_digest_payload(result_payload),
        abort=None,
    )
