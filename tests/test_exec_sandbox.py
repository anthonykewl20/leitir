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
    donor_execution_enabled,
    prepare_execution,
    run_contained,
)

_REAL_CGROUP_KILL = sandbox._kill_cgroup_tree


def _digest(data: bytes) -> str:
    return f"sha256:{hashlib.sha256(data).hexdigest()}"


def _canonical_digest(value: object) -> str:
    data = (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False) + "\n").encode()
    return _digest(data)


@pytest.fixture
def fake_nsjail(tmp_path: Path) -> tuple[Path, str, str]:
    path = tmp_path / "nsjail"
    version = "nsjail version test-pinned"
    path.write_text(
        f"#!{sys.executable}\n"
        "import os, sys\n"
        f"VERSION = {version!r}\n"
        "if sys.argv[1:] == ['--version']:\n"
        "    print(VERSION)\n"
        "    raise SystemExit(0)\n"
        "separator = sys.argv.index('--')\n"
        "argv = sys.argv[separator + 1:]\n"
        "os.execv(argv[0], argv)\n",
        encoding="utf-8",
    )
    path.chmod(0o700)
    version_bytes = (version + "\n").encode()
    return path, version, _digest(version_bytes)


def _policy(fake_nsjail: tuple[Path, str, str], *, output_limit: int = 4096, wall_time: int = 2) -> ContainmentPolicy:
    path, version, build_identity = fake_nsjail
    rootfs = path.parent / "rootfs"
    rootfs.write_bytes(b"rootfs")
    root_digest = _digest(b"rootfs")
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
        seccomp_string="DEFAULT KILL { read, write, exit, exit_group }",
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


@pytest.fixture(autouse=True)
def applied_state_stub(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    cgroup = tmp_path / "cgroup"
    cgroup.mkdir()
    monkeypatch.setattr(sandbox, "_verify_applied_state", lambda process, policy: sandbox._AppliedState(process.pid, cgroup))
    monkeypatch.setattr(sandbox, "_kill_cgroup_tree", lambda path: True)


@pytest.mark.parametrize("value", [None, "0", "true", "yes", "01", " 1"])
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
        ("seccomp_string", ""),
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
    plan = prepare_execution(_policy(fake_nsjail))
    assert plan.nsjail_argv[1:] == ("--config", "<ephemeral-verified-config>", "--")
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
        assert control in plan.config_text


def test_binary_digest_tamper_rejects(monkeypatch: pytest.MonkeyPatch, fake_nsjail: tuple[Path, str, str]) -> None:
    monkeypatch.setenv("LEITIR_ENABLE_DONOR_EXECUTION", "1")
    policy = _policy(fake_nsjail)
    fake_nsjail[0].write_text("tampered", encoding="utf-8")
    with pytest.raises(TransplantError) as caught:
        prepare_execution(policy)
    assert caught.value.evidence.detail_code == "nsjail_digest_mismatch"


def test_seccomp_default_allow_rejects_even_when_kill_appears_elsewhere(
    monkeypatch: pytest.MonkeyPatch, fake_nsjail: tuple[Path, str, str]
) -> None:
    monkeypatch.setenv("LEITIR_ENABLE_DONOR_EXECUTION", "1")
    policy = replace(_policy(fake_nsjail), seccomp_string="ALLOW { read, write } DEFAULT ALLOW # KILL")
    with pytest.raises(TransplantError) as caught:
        prepare_execution(policy)
    assert caught.value.evidence.detail_code == "seccomp_not_default_deny"


def test_default_kill_with_explicit_full_network_deny_set_passes(
    monkeypatch: pytest.MonkeyPatch, fake_nsjail: tuple[Path, str, str]
) -> None:
    monkeypatch.setenv("LEITIR_ENABLE_DONOR_EXECUTION", "1")
    network = ", ".join(sorted(sandbox._FORBIDDEN_SYSCALLS))
    policy = replace(
        _policy(fake_nsjail),
        seccomp_string=f"ALLOW {{ read, write, exit, exit_group }} DENY {{ {network} }} DEFAULT KILL",
    )
    assert prepare_execution(policy).policy.seccomp_string.endswith("DEFAULT KILL")


def test_mount_source_digest_tamper_rejects_before_launch(
    monkeypatch: pytest.MonkeyPatch, fake_nsjail: tuple[Path, str, str]
) -> None:
    monkeypatch.setenv("LEITIR_ENABLE_DONOR_EXECUTION", "1")
    policy = _policy(fake_nsjail)
    Path(policy.readonly_mounts[0].source).write_bytes(b"tampered")
    with pytest.raises(TransplantError) as caught:
        prepare_execution(policy)
    assert caught.value.evidence.detail_code == "mount_source_digest_mismatch"


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


def test_applied_state_failure_rejects_without_releasing_child(
    monkeypatch: pytest.MonkeyPatch, fake_nsjail: tuple[Path, str, str]
) -> None:
    monkeypatch.setenv("LEITIR_ENABLE_DONOR_EXECUTION", "1")

    def reject_state(process: subprocess.Popen[bytes], policy: ContainmentPolicy) -> sandbox._AppliedState:
        del policy
        os.killpg(process.pid, 9)
        raise sandbox._reject("applied state missing", "applied_state_unavailable")

    monkeypatch.setattr(sandbox, "_verify_applied_state", reject_state)
    with pytest.raises(TransplantError) as caught:
        run_contained(prepare_execution(_policy(fake_nsjail)), (sys.executable, "-c", "import time; time.sleep(30)"))
    assert caught.value.evidence.detail_code == "applied_state_unavailable"


def test_mount_source_change_during_execution_rejects_result(
    monkeypatch: pytest.MonkeyPatch, fake_nsjail: tuple[Path, str, str]
) -> None:
    monkeypatch.setenv("LEITIR_ENABLE_DONOR_EXECUTION", "1")
    plan = prepare_execution(_policy(fake_nsjail))
    rootfs = plan.policy.readonly_mounts[0].source
    with pytest.raises(TransplantError) as caught:
        run_contained(plan, (sys.executable, "-c", f"open({rootfs!r}, 'wb').write(b'tampered')"))
    assert caught.value.evidence.detail_code == "mount_source_digest_mismatch"


def test_cgroup_tree_kill_writes_kill_and_verifies_unpopulated(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    cgroup = tmp_path / "realized"
    cgroup.mkdir()
    (cgroup / "cgroup.kill").write_text("", encoding="ascii")
    states = iter((True, False))
    monkeypatch.setattr(sandbox, "_kill_cgroup_tree", _REAL_CGROUP_KILL)
    monkeypatch.setattr(sandbox, "_cgroup_populated", lambda path: next(states))
    assert sandbox._kill_cgroup_tree(cgroup) is True
    assert (cgroup / "cgroup.kill").read_text(encoding="ascii") == "1"


def test_plan_cannot_recompute_away_an_unapplied_policy_control(monkeypatch: pytest.MonkeyPatch, fake_nsjail: tuple[Path, str, str]) -> None:
    monkeypatch.setenv("LEITIR_ENABLE_DONOR_EXECUTION", "1")
    plan = prepare_execution(_policy(fake_nsjail))
    tampered = replace(plan, policy=replace(plan.policy, clone_newnet=False))
    with pytest.raises(TransplantError) as caught:
        run_contained(tampered, ("/bin/true",))
    assert caught.value.reason is BTSRejectReason.REJECT_EXECUTION_THREAT


def test_timeout_is_bounded_nonauthorizing_abort(monkeypatch: pytest.MonkeyPatch, fake_nsjail: tuple[Path, str, str]) -> None:
    monkeypatch.setenv("LEITIR_ENABLE_DONOR_EXECUTION", "1")
    plan = prepare_execution(_policy(fake_nsjail, wall_time=1))
    result = run_contained(plan, (sys.executable, "-c", "import time; time.sleep(5)"))
    assert result.completed is False
    assert result.result_digest is None
    assert result.stdout == result.stderr == b""
    assert result.abort is not None
    assert result.abort.reason is BTSRejectReason.REJECT_EXECUTION_THREAT
    assert result.abort.detail_category == "wall_time_limit"


def test_nonzero_exit_is_hard_gate_abort(monkeypatch: pytest.MonkeyPatch, fake_nsjail: tuple[Path, str, str]) -> None:
    monkeypatch.setenv("LEITIR_ENABLE_DONOR_EXECUTION", "1")
    result = run_contained(prepare_execution(_policy(fake_nsjail)), (sys.executable, "-c", "raise SystemExit(7)"))
    assert result.abort is not None
    assert result.abort.reason is BTSRejectReason.REJECT_HARD_GATE_FAILED
    assert result.abort.detail_category == "child_crash"


def test_output_truncation_is_bounded_execution_threat(monkeypatch: pytest.MonkeyPatch, fake_nsjail: tuple[Path, str, str]) -> None:
    monkeypatch.setenv("LEITIR_ENABLE_DONOR_EXECUTION", "1")
    plan = prepare_execution(_policy(fake_nsjail, output_limit=64))
    result = run_contained(plan, (sys.executable, "-c", "import os; os.write(1, b'x' * 4096)"))
    assert result.abort is not None
    assert result.abort.reason is BTSRejectReason.REJECT_EXECUTION_THREAT
    assert result.abort.detail_category == "output_limit"
    assert result.abort.stdout_bytes <= 64
    assert len(result.to_json()) < 1024


def test_success_is_content_addressed(monkeypatch: pytest.MonkeyPatch, fake_nsjail: tuple[Path, str, str]) -> None:
    monkeypatch.setenv("LEITIR_ENABLE_DONOR_EXECUTION", "1")
    result = run_contained(prepare_execution(_policy(fake_nsjail)), (sys.executable, "-c", "print('fixed')"))
    assert result.completed is True
    assert result.stdout == b"fixed\n"
    assert result.stdout_digest == _digest(b"fixed\n")
    assert result.result_digest is not None


def test_plan_rendering_is_pythonhashseed_independent(fake_nsjail: tuple[Path, str, str]) -> None:
    path, version, build_identity = fake_nsjail
    (path.parent / "rootfs").write_bytes(b"rootfs")
    script = f"""
import json, platform
from leitir.exec_sandbox import *
import hashlib
root_path = {str(path.parent / 'rootfs')!r}
root = 'sha256:' + hashlib.sha256(open(root_path, 'rb').read()).hexdigest()
mounts = (ReadOnlyMount('/', root_path, root),)
payload = {{'readonly_mounts':[{{'destination':'/','source':root_path,'source_digest':root}}], 'rootfs_digest':root, 'writable_tmpfs':'/work', 'writable_tmpfs_bytes':1048576, 'writable_tmpfs_inodes':128}}
md = 'sha256:' + hashlib.sha256((json.dumps(payload, sort_keys=True, separators=(',', ':')) + '\\n').encode()).hexdigest()
p = ContainmentPolicy(POLICY_SCHEMA, {str(path)!r}, {_digest(path.read_bytes())!r}, {version!r}, {build_identity!r}, 'sha256:'+'2'*64, platform.machine(), root, md, mounts, '/work', 1048576, 128, '/work', 'ONCE', False, True, True, True, True, True, True, True, 67108864, 16, 500, 'DEFAULT KILL {{ read, write, exit, exit_group }}', 2, 64, 1, 1, 32, 16, 8, 0, 4096, ('LANG=C.UTF-8','PYTHONHASHSEED=0','TZ=UTC'), True)
print(prepare_execution(p).to_json(), end='')
"""
    outputs = []
    for seed in ("0", "1", "42"):
        env = os.environ.copy()
        env.update({"LEITIR_ENABLE_DONOR_EXECUTION": "1", "PYTHONHASHSEED": seed, "PYTHONPATH": "src"})
        outputs.append(subprocess.check_output((sys.executable, "-c", script), cwd=Path(__file__).parents[1], env=env))
    assert outputs[0] == outputs[1] == outputs[2]


@pytest.mark.skipif(
    os.environ.get("LEITIR_ENABLE_DONOR_EXECUTION") != "1" or not Path("/usr/bin/nsjail").exists(),
    reason="live nsjail test requires exact donor opt-in and /usr/bin/nsjail",
)
def test_live_nsjail_network_and_tmpfs_controls_require_release_policy() -> None:
    pytest.skip("release-pinned nsjail/rootfs policy artifact is not available in the source tree")
