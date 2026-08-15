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

import leitir.exec_sandbox as sandbox
from leitir.bts_errors import BTSRejectReason, TransplantError
from leitir.exec_sandbox import (
    POLICY_SCHEMA,
    ContainmentPolicy,
    ReadOnlyMount,
    ValidationAbortEnvelope,
    donor_execution_enabled,
    prepare_execution,
    run_contained,
)


def _digest(data: bytes) -> str:
    return f"sha256:{hashlib.sha256(data).hexdigest()}"


def _canonical_digest(value: object) -> str:
    data = (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False) + "\n").encode()
    return _digest(data)


_NSJAIL_COMMIT = "f78475530b46d0186111a9096b30725f816b55fe"


@pytest.fixture
def fake_nsjail(tmp_path: Path) -> tuple[Path, str, str]:
    path = tmp_path / "nsjail"
    timestamped_version = "nsjail version test-pinned built 2026-08-15T00:00:00Z"
    path.write_text(
        f"#!{sys.executable}\n"
        "import os, sys\n"
        f"VERSION = {timestamped_version!r}\n"
        "if sys.argv[1:] == ['--version']:\n"
        "    print(VERSION)\n"
        "    raise SystemExit(0)\n"
        "separator = sys.argv.index('--')\n"
        "argv = sys.argv[separator + 1:]\n"
        "os.execv(argv[0], argv)\n",
        encoding="utf-8",
    )
    path.chmod(0o700)
    binary_digest = _digest(path.read_bytes())
    return path, f"nsjail@{_NSJAIL_COMMIT}", sandbox._nsjail_build_identity(_NSJAIL_COMMIT, binary_digest)


def _policy(fake_nsjail: tuple[Path, str, str], *, output_limit: int = 4096, wall_time: int = 2) -> ContainmentPolicy:
    path, version, build_identity = fake_nsjail
    rootfs = path.parent / "rootfs"
    rootfs.mkdir()
    (rootfs / "python").write_bytes(b"rootfs")
    (rootfs / "python").chmod(0o555)
    root_digest = sandbox._verified_directory_tree_digest(rootfs)
    mount = ReadOnlyMount("/", str(rootfs), root_digest)
    mount_payload = {
        "readonly_mounts": [{"destination": "/", "source": str(rootfs), "source_digest": root_digest}],
        "rootfs_digest": root_digest,
        "writable_tmpfs": "/work",
        "writable_tmpfs_bytes": 1_048_576,
        "writable_tmpfs_inodes": 128,
    }
    return ContainmentPolicy(
        schema_version=POLICY_SCHEMA,
        nsjail_path=str(path),
        nsjail_sha256=_digest(path.read_bytes()),
        nsjail_version=version,
        nsjail_build_identity=build_identity,
        config_schema_digest=_digest(b"upstream-config-proto"),
        architecture=platform.machine(),
        rootfs_digest=root_digest,
        mount_plan_digest=_canonical_digest(mount_payload),
        readonly_mounts=(mount,),
        writable_tmpfs="/work",
        writable_tmpfs_bytes=1_048_576,
        writable_tmpfs_inodes=128,
        cwd="/work",
        mode="ONCE",
        keep_env=False,
        clone_newnet=True,
        clone_newuser=True,
        clone_newns=True,
        clone_newpid=True,
        clone_newipc=True,
        clone_newuts=True,
        iface_no_lo=True,
        cgroup_mem_max=67_108_864,
        cgroup_pids_max=16,
        cgroup_cpu_ms_per_sec=500,
        wall_time_seconds=wall_time,
        rlimit_as_mb=64,
        rlimit_cpu_seconds=1,
        rlimit_fsize_mb=1,
        rlimit_nofile=32,
        rlimit_nproc=16,
        rlimit_stack_mb=8,
        rlimit_core_mb=0,
        output_limit_bytes=output_limit,
        environment=("LANG=C.UTF-8", "PYTHONHASHSEED=0", "TZ=UTC"),
        opt_in_satisfied=True,
    )


def test_nsjail_ci_identity_derivation_is_accepted_without_running_nsjail(fake_nsjail: tuple[Path, str, str]) -> None:
    """Match bts-containment.yml: sha256(commit UTF-8 + binary-sha hex UTF-8)."""

    path, version, identity = fake_nsjail
    policy = _policy(fake_nsjail)
    binary_digest = _digest(path.read_bytes())
    binary_sha_hex = binary_digest.removeprefix("sha256:")
    assert version == f"nsjail@{_NSJAIL_COMMIT}"
    assert identity == f"sha256:{hashlib.sha256((_NSJAIL_COMMIT + binary_sha_hex).encode()).hexdigest()}"
    assert sandbox._nsjail_build_identity(_NSJAIL_COMMIT, binary_digest) == identity
    sandbox._verify_nsjail_identity(policy, binary_digest)


def test_nsjail_timestamped_version_output_identity_is_rejected(fake_nsjail: tuple[Path, str, str]) -> None:
    legacy_output = "nsjail version test-pinned built 2026-08-15T00:00:00Z"
    legacy_identity = _digest((legacy_output + "\n").encode())
    path, _, _ = fake_nsjail
    with pytest.raises(TransplantError) as caught:
        sandbox._verify_nsjail_identity(
            replace(_policy(fake_nsjail), nsjail_version=legacy_output, nsjail_build_identity=legacy_identity),
            _digest(path.read_bytes()),
        )
    assert caught.value.evidence.detail_code == "nsjail_identity_mismatch"


@pytest.mark.parametrize("value", [None, "0", "true", "yes", "01", " 1"])
@pytest.mark.skipif(
    sys.platform != "linux",
    reason="nsjail containment is Linux-only (ADR-0009 §3)",
)
def test_exact_opt_in_gate_rejects_every_other_value(monkeypatch: pytest.MonkeyPatch, fake_nsjail: tuple[Path, str, str], value: str | None) -> None:
    if value is None:
        monkeypatch.delenv("LEITIR_ENABLE_DONOR_EXECUTION", raising=False)
    else:
        monkeypatch.setenv("LEITIR_ENABLE_DONOR_EXECUTION", value)
    assert donor_execution_enabled() is False
    with pytest.raises(TransplantError) as caught:
        prepare_execution(_policy(fake_nsjail))
    assert caught.value.reason is BTSRejectReason.REJECT_EXECUTION_THREAT
    assert caught.value.evidence.detail_code == "donor_execution_disabled"
    assert value not in caught.value.to_json() if value else True


@pytest.mark.skipif(
    sys.platform != "linux",
    reason="nsjail containment is Linux-only (ADR-0009 §3)",
)
def test_only_exact_one_enables(monkeypatch: pytest.MonkeyPatch, fake_nsjail: tuple[Path, str, str]) -> None:
    monkeypatch.setenv("LEITIR_ENABLE_DONOR_EXECUTION", "1")
    assert donor_execution_enabled() is True
    plan = prepare_execution(_policy(fake_nsjail))
    assert plan.opt_in_satisfied is True
    assert "LEITIR_ENABLE_DONOR_EXECUTION" not in plan.to_json()


def test_non_linux_host_rejects(monkeypatch: pytest.MonkeyPatch, fake_nsjail: tuple[Path, str, str]) -> None:
    monkeypatch.setenv("LEITIR_ENABLE_DONOR_EXECUTION", "1")
    monkeypatch.setattr("leitir.exec_sandbox.platform.system", lambda: "Darwin")
    with pytest.raises(TransplantError) as caught:
        prepare_execution(_policy(fake_nsjail))
    assert caught.value.reason is BTSRejectReason.REJECT_EXECUTION_THREAT
    assert caught.value.evidence.detail_code == "unsupported_host"


def test_execution_result_rendering_covers_success_and_abort() -> None:
    abort = ValidationAbortEnvelope(
        "leitir-validation-abort-v1",
        "execution",
        "donor",
        BTSRejectReason.REJECT_EXECUTION_THREAT,
        "wall_time_limit",
        _digest(b"plan"),
        3,
        4,
    )
    aborted = sandbox.ExecutionResult(False, _digest(b"plan"), None, b"", b"", None, None, None, abort)
    assert json.loads(aborted.to_json())["detail_category"] == "wall_time_limit"
    successful = sandbox.ExecutionResult(
        True,
        _digest(b"plan"),
        0,
        b"out",
        b"err",
        _digest(b"out"),
        _digest(b"err"),
        _digest(b"result"),
        None,
    )
    assert json.loads(successful.to_json())["stdout_bytes"] == 3


@pytest.mark.parametrize(
    ("changes", "detail"),
    [
        ({"schema_version": "wrong"}, "invalid_policy_schema"),
        ({"rlimit_core_mb": 1}, "invalid_resource_limit"),
        ({"nsjail_sha256": "bad"}, "invalid_integrity_digest"),
        ({"nsjail_version": ""}, "missing_backend_identity"),
        ({"cwd": "relative"}, "invalid_containment_path"),
        ({"cwd": "/outside"}, "cwd_outside_tmpfs"),
        ({"readonly_mounts": ()}, "empty_mount_plan"),
        ({"environment": ("TZ=UTC", "LANG=C.UTF-8")}, "noncanonical_environment"),
        ({"environment": ("BAD",)}, "invalid_environment"),
    ],
)
@pytest.mark.skipif(
    sys.platform != "linux",
    reason="containment policy paths are POSIX-absolute (ADR-0009 Linux backend)",
)
def test_portable_policy_validation_rejects_malformed_fields(
    fake_nsjail: tuple[Path, str, str], changes: dict[str, object], detail: str
) -> None:
    with pytest.raises(TransplantError) as caught:
        sandbox._validate_policy(replace(_policy(fake_nsjail), **changes))
    assert caught.value.evidence.detail_code == detail


@pytest.mark.skipif(
    sys.platform != "linux",
    reason="containment policy paths are POSIX-absolute (ADR-0009 Linux backend)",
)
def test_portable_policy_validation_rejects_mount_shape(fake_nsjail: tuple[Path, str, str]) -> None:
    policy = _policy(fake_nsjail)
    duplicate = replace(policy, readonly_mounts=(policy.readonly_mounts[0], policy.readonly_mounts[0]))
    with pytest.raises(TransplantError) as caught:
        sandbox._validate_policy(duplicate)
    assert caught.value.evidence.detail_code == "noncanonical_mount_plan"
    no_root = replace(policy, readonly_mounts=(replace(policy.readonly_mounts[0], destination="/input"),))
    with pytest.raises(TransplantError) as caught:
        sandbox._validate_policy(no_root)
    assert caught.value.evidence.detail_code == "missing_rootfs_mount"


def test_abort_bounds_reported_stream_lengths(fake_nsjail: tuple[Path, str, str]) -> None:
    policy = _policy(fake_nsjail, output_limit=3)
    draft = sandbox.ExecutionPlan(
        sandbox.PLAN_SCHEMA,
        policy,
        policy.nsjail_path,
        policy.nsjail_sha256,
        policy.architecture,
        (),
        "",
        policy.environment,
        policy.wall_time_seconds,
        policy.output_limit_bytes,
        _digest(b"policy"),
        _digest(b"plan"),
        True,
    )
    result = sandbox._abort(draft, "output_limit", BTSRejectReason.REJECT_EXECUTION_THREAT, 99, 98)
    assert result.abort is not None
    assert (result.abort.stdout_bytes, result.abort.stderr_bytes) == (3, 3)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("mode", "RERUN"),
        ("keep_env", True),
        ("clone_newnet", False),
        ("clone_newuser", None),
        ("clone_newns", False),
        ("clone_newpid", False),
        ("clone_newipc", False),
        ("clone_newuts", False),
        ("iface_no_lo", False),
        ("cgroup_mem_max", 0),
        ("cgroup_pids_max", 0),
        ("cgroup_cpu_ms_per_sec", 0),
    ],
)
def test_missing_or_unapplied_v1_control_rejects_before_launch(
    monkeypatch: pytest.MonkeyPatch,
    fake_nsjail: tuple[Path, str, str],
    field: str,
    value: object,
) -> None:
    monkeypatch.setenv("LEITIR_ENABLE_DONOR_EXECUTION", "1")
    policy = replace(_policy(fake_nsjail), **{field: value})
    with pytest.raises(TransplantError) as caught:
        prepare_execution(policy)
    assert caught.value.reason is BTSRejectReason.REJECT_EXECUTION_THREAT


def test_generated_nsjail_config_explicitly_applies_required_controls(monkeypatch: pytest.MonkeyPatch, fake_nsjail: tuple[Path, str, str]) -> None:
    monkeypatch.setenv("LEITIR_ENABLE_DONOR_EXECUTION", "1")
    config_text = sandbox._render_config(_policy(fake_nsjail))
    required = (
        "mode: ONCE",
        "keep_env: false",
        "clone_newnet: true",
        "clone_newuser: true",
        "clone_newns: true",
        "clone_newpid: true",
        "clone_newipc: true",
        "clone_newuts: true",
        "iface_no_lo: true",
        "use_cgroupv2: true",
        "cgroup_mem_max: 67108864",
        "cgroup_pids_max: 16",
        "cgroup_cpu_ms_per_sec: 500",
        "rlimit_nofile: 32",
        "seccomp_string:",
    )
    for control in required:
        assert control in config_text


@pytest.mark.skipif(
    sys.platform != "linux",
    reason="nsjail containment is Linux-only (ADR-0009 §3)",
)
def test_binary_digest_tamper_rejects(monkeypatch: pytest.MonkeyPatch, fake_nsjail: tuple[Path, str, str]) -> None:
    monkeypatch.setenv("LEITIR_ENABLE_DONOR_EXECUTION", "1")
    policy = _policy(fake_nsjail)
    fake_nsjail[0].write_text("tampered", encoding="utf-8")
    with pytest.raises(TransplantError) as caught:
        prepare_execution(policy)
    assert caught.value.evidence.detail_code == "nsjail_digest_mismatch"


@pytest.mark.skipif(
    sys.platform != "linux",
    reason="containment policy paths are POSIX-absolute (ADR-0009 Linux backend)",
)
def test_seccomp_is_exact_canonical_generated_kafel(
    monkeypatch: pytest.MonkeyPatch, fake_nsjail: tuple[Path, str, str]
) -> None:
    monkeypatch.setenv("LEITIR_ENABLE_DONOR_EXECUTION", "1")
    policy = _policy(fake_nsjail)
    sandbox._validate_policy(policy)
    assert policy.seccomp_string == sandbox.CANONICAL_SECCOMP_STRING
    assert policy.seccomp_string == (
        "DEFAULT KILL\n"
        "ALLOW { arch_prctl, brk, clock_gettime, close, execve, exit, exit_group, fcntl, fstat, futex, "
        "getcwd, getdents64, getpid, getrandom, lseek, mmap, mprotect, munmap, newfstatat, openat, "
        "prlimit64, read, readlink, readlinkat, rt_sigaction, rt_sigprocmask, set_robust_list, "
        "set_tid_address, statx, write }\n"
    )
    allowed = {item.value for item in sandbox.CANONICAL_SECCOMP_POLICY.allowed_syscalls}
    assert allowed.isdisjoint(sandbox._FORBIDDEN_SYSCALLS)


@pytest.mark.parametrize(
    "custom",
    [
        "DEFAULT KILL /* hidden */ ALLOW { socket }",
        "DEFAULT KILL\nLOG { socket }",
        "DEFAULT KILL\nALLOW { SYSCALL[41] }",
        "DEFAULT KILL // comment\nALLOW { socket }",
    ],
)
def test_caller_cannot_supply_smuggled_kafel(fake_nsjail: tuple[Path, str, str], custom: str) -> None:
    with pytest.raises((TypeError, AttributeError, ValueError)):
        replace(_policy(fake_nsjail), seccomp_string=custom)


@pytest.mark.skipif(
    sys.platform != "linux",
    reason="nsjail containment is Linux-only (ADR-0009 §3)",
)
def test_mount_source_digest_tamper_rejects_before_launch(
    monkeypatch: pytest.MonkeyPatch, fake_nsjail: tuple[Path, str, str]
) -> None:
    monkeypatch.setenv("LEITIR_ENABLE_DONOR_EXECUTION", "1")
    policy = _policy(fake_nsjail)
    root_file = Path(policy.readonly_mounts[0].source, "python")
    root_file.chmod(0o755)
    root_file.write_bytes(b"tampered")
    with pytest.raises(TransplantError) as caught:
        prepare_execution(policy)
    assert caught.value.evidence.detail_code == "mount_source_digest_mismatch"


@pytest.mark.skipif(
    sys.platform != "linux",
    reason="nsjail containment is Linux-only (ADR-0009 §3)",
)
def test_rootfs_mount_digest_must_equal_policy_rootfs_digest(
    monkeypatch: pytest.MonkeyPatch, fake_nsjail: tuple[Path, str, str]
) -> None:
    monkeypatch.setenv("LEITIR_ENABLE_DONOR_EXECUTION", "1")
    policy = _policy(fake_nsjail)
    wrong = _digest(b"different-rootfs")
    payload = {
        "readonly_mounts": [
            {
                "destination": item.destination,
                "source": item.source,
                "source_digest": item.source_digest,
            }
            for item in policy.readonly_mounts
        ],
        "rootfs_digest": wrong,
        "writable_tmpfs": policy.writable_tmpfs,
        "writable_tmpfs_bytes": policy.writable_tmpfs_bytes,
        "writable_tmpfs_inodes": policy.writable_tmpfs_inodes,
    }
    policy = replace(policy, rootfs_digest=wrong, mount_plan_digest=_canonical_digest(payload))
    with pytest.raises(TransplantError) as caught:
        prepare_execution(policy)
    assert caught.value.evidence.detail_code == "rootfs_digest_mismatch"


@pytest.mark.skipif(
    sys.platform != "linux",
    reason="nsjail containment is Linux-only (ADR-0009 §3)",
)
def test_offline_execution_refuses_before_donor_launch(
    monkeypatch: pytest.MonkeyPatch, fake_nsjail: tuple[Path, str, str], tmp_path: Path
) -> None:
    monkeypatch.setenv("LEITIR_ENABLE_DONOR_EXECUTION", "1")
    plan = prepare_execution(_policy(fake_nsjail))
    marker = tmp_path / "donor-ran"
    with pytest.raises(TransplantError) as caught:
        run_contained(plan, (sys.executable, "-c", f"open({str(marker)!r}, 'w').write('bad')"))
    assert caught.value.reason is BTSRejectReason.REJECT_EXECUTION_THREAT
    assert caught.value.evidence.detail_code == "applied_state_barrier_unavailable"
    assert not marker.exists()


class _FakeProcess:
    pid = 100

    def poll(self) -> None:
        return None


class _FakeAppliedStateReader:
    def __init__(self, interfaces: dict[str, str] | None = None) -> None:
        self.interfaces = {"lo": "down"} if interfaces is None else interfaces

    def proc_text(self, pid: int, name: str) -> str:
        del pid
        values = {
            "status": "NoNewPrivs:\t1\nSeccomp:\t2\nCapEff:\t0000000000000000\n",
            "uid_map": "65534 1000 1\n",
            "gid_map": "65534 1000 1\n",
            "mountinfo": "1 0 0:1 / / ro - ext4 root ro\n2 1 0:2 / /work rw - tmpfs tmpfs rw\n",
            "net/route": "Iface Destination Gateway Flags RefCnt Use Metric Mask MTU Window IRTT\n",
            "net/ipv6_route": "",
            "cgroup": "0::/leitir-test\n",
        }
        return values[name]

    def namespace_identity(self, pid: int, namespace: str) -> tuple[int, int]:
        identities = {name: index for index, name in enumerate(("net", "user", "mnt", "pid", "ipc", "uts"), 1)}
        return (identities[namespace], pid)

    def cgroup_text(self, path: Path, name: str) -> str:
        del path
        values = {
            "memory.max": "67108864\n",
            "pids.max": "16\n",
            "cpu.max": "500000 1000000\n",
            "cgroup.controllers": "cpu memory pids\n",
            "cgroup.events": "populated 1\n",
            "cgroup.procs": "100\n",
        }
        return values[name]

    def network_interfaces(self, pid: int) -> dict[str, str]:
        del pid
        return self.interfaces


@pytest.mark.skipif(
    sys.platform != "linux",
    reason="nsjail containment is Linux-only (ADR-0009 §3)",
)
def test_real_applied_state_verifier_accepts_only_complete_kernel_receipt(fake_nsjail: tuple[Path, str, str]) -> None:
    state = sandbox._verify_applied_state(
        _FakeProcess(),  # type: ignore[arg-type]
        _policy(fake_nsjail),
        child_pid=100,
        reader=_FakeAppliedStateReader(),
    )
    assert state.child_pid == 100


@pytest.mark.parametrize("interfaces", [{"lo": "up"}, {"lo": "down", "eth0": "down"}, {}])
def test_real_applied_state_verifier_rejects_network_bypass(
    fake_nsjail: tuple[Path, str, str], interfaces: dict[str, str]
) -> None:
    with pytest.raises(TransplantError) as caught:
        sandbox._verify_applied_state(
            _FakeProcess(),  # type: ignore[arg-type]
            _policy(fake_nsjail),
            child_pid=100,
            reader=_FakeAppliedStateReader(interfaces),
        )
    assert caught.value.evidence.detail_code == "applied_network_mismatch"


def test_cgroup_tree_kill_writes_kill_and_verifies_unpopulated(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    cgroup = tmp_path / "realized"
    cgroup.mkdir()
    (cgroup / "cgroup.kill").write_text("", encoding="ascii")
    states = iter((True, False))
    monkeypatch.setattr(sandbox, "_cgroup_populated", lambda path: next(states))
    assert sandbox._kill_cgroup_tree(cgroup) is True
    assert (cgroup / "cgroup.kill").read_text(encoding="ascii") == "1"


@pytest.mark.skipif(
    sys.platform != "linux",
    reason="nsjail containment is Linux-only (ADR-0009 §3)",
)
def test_plan_cannot_recompute_away_an_unapplied_policy_control(monkeypatch: pytest.MonkeyPatch, fake_nsjail: tuple[Path, str, str]) -> None:
    monkeypatch.setenv("LEITIR_ENABLE_DONOR_EXECUTION", "1")
    plan = prepare_execution(_policy(fake_nsjail))
    tampered = replace(plan, policy=replace(plan.policy, clone_newnet=False))
    with pytest.raises(TransplantError) as caught:
        run_contained(tampered, ("/bin/true",))
    assert caught.value.reason is BTSRejectReason.REJECT_EXECUTION_THREAT


@pytest.mark.parametrize(
    ("program", "limit", "timeout"),
    [
        ("print('ok')", 4096, 2),
        ("raise SystemExit(7)", 4096, 2),
        ("import os; os.write(1, b'x' * 4096)", 64, 2),
        ("import time; time.sleep(5)", 4096, 1),
    ],
)
@pytest.mark.skipif(
    sys.platform != "linux",
    reason="nsjail containment is Linux-only (ADR-0009 §3)",
)
def test_cgroup_teardown_is_attempted_for_every_capture_outcome(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, program: str, limit: int, timeout: int
) -> None:
    process = subprocess.Popen(
        (sys.executable, "-c", program),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        start_new_session=True,
    )
    calls: list[Path] = []

    def kill_tree(path: Path) -> bool:
        calls.append(path)
        try:
            os.killpg(process.pid, 9)
        except ProcessLookupError:
            pass
        return True

    monkeypatch.setattr(sandbox, "_kill_cgroup_tree", kill_tree)
    cgroup = tmp_path / "cgroup"
    capture = sandbox._bounded_communicate(
        process,
        limit=limit,
        timeout=timeout,
        applied_state=sandbox._AppliedState(process.pid, cgroup),
    )
    assert calls == [cgroup]
    assert capture.noncanonical_kill is False


def test_plan_rendering_is_pythonhashseed_independent(fake_nsjail: tuple[Path, str, str]) -> None:
    path, version, build_identity = fake_nsjail
    rootfs = path.parent / "rootfs"
    rootfs.mkdir()
    (rootfs / "python").write_bytes(b"rootfs")
    (rootfs / "python").chmod(0o555)
    script = f"""
import json, platform
from leitir.exec_sandbox import *
import hashlib
root_path = {str(path.parent / 'rootfs')!r}
import leitir.exec_sandbox as sandbox
root = sandbox._verified_directory_tree_digest(__import__('pathlib').Path(root_path))
mounts = (ReadOnlyMount('/', root_path, root),)
payload = {{'readonly_mounts':[{{'destination':'/','source':root_path,'source_digest':root}}], 'rootfs_digest':root, 'writable_tmpfs':'/work', 'writable_tmpfs_bytes':1048576, 'writable_tmpfs_inodes':128}}
md = 'sha256:' + hashlib.sha256((json.dumps(payload, sort_keys=True, separators=(',', ':')) + '\\n').encode()).hexdigest()
p = ContainmentPolicy(POLICY_SCHEMA, {str(path)!r}, {_digest(path.read_bytes())!r}, {version!r}, {build_identity!r}, 'sha256:'+'2'*64, platform.machine(), root, md, mounts, '/work', 1048576, 128, '/work', 'ONCE', False, True, True, True, True, True, True, True, 67108864, 16, 500, 2, 64, 1, 1, 32, 16, 8, 0, 4096, ('LANG=C.UTF-8','PYTHONHASHSEED=0','TZ=UTC'), True)
print(sandbox._canonical_json({{'config_text': sandbox._render_config(p), 'policy': sandbox._policy_payload(p)}}), end='')
"""
    outputs = []
    for seed in ("0", "1", "42"):
        env = os.environ.copy()
        env.update({"LEITIR_ENABLE_DONOR_EXECUTION": "1", "PYTHONHASHSEED": seed, "PYTHONPATH": os.pathsep.join(("src", "."))})
        outputs.append(subprocess.check_output((sys.executable, "-c", script), cwd=Path(__file__).parents[1], env=env))
    assert outputs[0] == outputs[1] == outputs[2]


@pytest.mark.skipif(
    os.environ.get("LEITIR_ENABLE_DONOR_EXECUTION") != "1" or not Path("/usr/bin/nsjail").exists(),
    reason="live nsjail test requires exact donor opt-in and /usr/bin/nsjail",
)
def test_live_nsjail_network_and_tmpfs_controls_require_release_policy() -> None:
    pytest.skip("release-pinned nsjail/rootfs policy artifact is not available in the source tree")
