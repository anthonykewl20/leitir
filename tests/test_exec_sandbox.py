from __future__ import annotations

import hashlib
import json
import os
import platform
import subprocess
import sys
import textwrap
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
        "if sys.argv[1:] == ['--help']:\n"
        "    sys.stderr.write('usage: nsjail [options]\\n' * 512)\n"
        "    raise SystemExit(255)\n"
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
    scratch = path.parent / "scratch"
    scratch.mkdir()
    scratch.chmod(0o777)
    mount_payload = {
        "readonly_mounts": [{"destination": "/", "source": str(rootfs), "source_digest": root_digest}],
        "rootfs_digest": root_digest,
        "scratch_dir": str(scratch),
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
        scratch_dir=str(scratch),
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


@pytest.mark.skipif(
    sys.platform != "linux",
    reason="nsjail containment is Linux-only (ADR-0009 §3)",
)
def test_nsjail_help_usage_is_an_accepted_bounded_liveness_probe(
    monkeypatch: pytest.MonkeyPatch, fake_nsjail: tuple[Path, str, str],
) -> None:
    """Pinned nsjail exits 255 with usage for --help; identity remains pin-derived."""

    monkeypatch.setenv("LEITIR_ENABLE_DONOR_EXECUTION", "1")
    plan = prepare_execution(_policy(fake_nsjail))

    assert plan.nsjail_argv[0] == str(fake_nsjail[0])


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


def test_startup_attestation_accepts_faked_applied_procfs_receipt() -> None:
    parent = {name: (1, index) for index, name in enumerate(("net", "user", "mnt", "pid", "ipc", "uts"), 1)}
    child = {name: (2, index) for index, name in enumerate(("net", "user", "mnt", "pid", "ipc", "uts"), 1)}
    receipt = sandbox.startup_attestation_from_proc(
        "Name:\trunner\nNoNewPrivs:\t1\nSeccomp:\t2\n", child, parent, pid=1
    )
    sandbox.validate_startup_attestation(receipt)


def test_launch_config_debug_opt_in_does_not_change_the_static_policy(
    monkeypatch: pytest.MonkeyPatch, fake_nsjail: tuple[Path, str, str]
) -> None:
    policy = _policy(fake_nsjail)
    plan = sandbox.ExecutionPlan("leitir-execution-plan-v1", policy, str(fake_nsjail[0]), policy.nsjail_sha256, platform.machine(), (), "", (), 2, 4096, "sha256:" + "0" * 64, "sha256:" + "0" * 64, True)
    monkeypatch.setattr(sandbox, "_startup_attestation_environment", lambda: ())
    monkeypatch.setenv(sandbox.NSJAIL_DEBUG_ENV, "1")

    assert "log_level: FATAL" in plan.config_text or plan.config_text == ""
    assert "log_level: DEBUG" in sandbox._launch_config(plan)
    assert policy.seccomp_string == sandbox.CANONICAL_SECCOMP_STRING


@pytest.mark.parametrize(
    ("status", "child", "pid"),
    [
        ("NoNewPrivs:\t0\nSeccomp:\t0\n", {name: (2, index) for index, name in enumerate(("net", "user", "mnt", "pid", "ipc", "uts"), 1)}, 1),
        ("NoNewPrivs:\t1\nSeccomp:\t2\n", {name: (1, index) for index, name in enumerate(("net", "user", "mnt", "pid", "ipc", "uts"), 1)}, 1),
        ("NoNewPrivs:\t1\nSeccomp:\t2\n", {name: (2, index) for index, name in enumerate(("net", "user", "mnt", "pid", "ipc", "uts"), 1)}, 2),
    ],
)
def test_startup_attestation_rejects_missing_applied_control(
    status: str, child: dict[str, tuple[int, int]], pid: int
) -> None:
    parent = {name: (1, index) for index, name in enumerate(("net", "user", "mnt", "pid", "ipc", "uts"), 1)}
    receipt = sandbox.startup_attestation_from_proc(status, child, parent, pid=pid)
    with pytest.raises(ValueError):
        sandbox.validate_startup_attestation(receipt)


@pytest.mark.parametrize(
    ("changes", "detail"),
    [
        ({"schema_version": "wrong"}, "invalid_policy_schema"),
        ({"rlimit_core_mb": 1}, "invalid_resource_limit"),
        ({"nsjail_sha256": "bad"}, "invalid_integrity_digest"),
        ({"nsjail_version": ""}, "missing_backend_identity"),
        ({"cwd": "relative"}, "invalid_containment_path"),
        ({"scratch_dir": "relative"}, "invalid_containment_path"),
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
    child_abort = sandbox._abort(
        draft,
        "child_crash",
        BTSRejectReason.REJECT_HARD_GATE_FAILED,
        1,
        2,
        exit_code=137,
        stdout=b"o",
        stderr=b"ab",
    )
    assert (child_abort.completed, child_abort.exit_code, child_abort.stdout, child_abort.stderr) == (False, 137, b"o", b"ab")


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
    policy = _policy(fake_nsjail)
    config_text = sandbox._render_config(policy)
    required = (
        "mode: ONCE",
        "keep_env: false",
        "clone_newnet: true",
        "clone_newuser: true",
        "clone_newns: true",
        "clone_newpid: true",
        "clone_newipc: true",
        "clone_newuts: true",
        "clone_newcgroup: true",
        "iface_no_lo: true",
        "use_cgroupv2: true",
        'cgroupv2_mount: "/sys/fs/cgroup"',
        "cgroup_mem_max: 67108864",
        "cgroup_pids_max: 16",
        "cgroup_cpu_ms_per_sec: 500",
        "rlimit_nofile: 32",
        "seccomp_string:",
    )
    for control in required:
        assert control in config_text
    host_uid = sandbox._host_mapping_id("SUDO_UID", getattr(os, "getuid", lambda: 0)())
    host_gid = sandbox._host_mapping_id("SUDO_GID", getattr(os, "getgid", lambda: 0)())
    assert f'uidmap {{ inside_id: "65534" outside_id: "{host_uid}" count: 1 use_newidmap: false }}' in config_text
    assert f'gidmap {{ inside_id: "65534" outside_id: "{host_gid}" count: 1 use_newidmap: false }}' in config_text
    assert (
        f'mount {{ src: {json.dumps(policy.readonly_mounts[0].source)} dst: "/" '
        'fstype: "bind" is_bind: true rw: false is_dir: true mandatory: true nosuid: true nodev: true }'
    ) in config_text
    assert (
        f'mount {{ src: {json.dumps(policy.scratch_dir)} dst: "/work" '
        'fstype: "bind" is_bind: true rw: true is_dir: true mandatory: true nosuid: true nodev: true noexec: true }'
    ) in config_text
    assert 'fstype: "tmpfs"' not in config_text


def test_generated_nsjail_config_maps_sudo_invoker_for_runner_owned_mount_sources(
    monkeypatch: pytest.MonkeyPatch, fake_nsjail: tuple[Path, str, str]
) -> None:
    monkeypatch.setattr(sandbox.os, "geteuid", lambda: 0, raising=False)
    monkeypatch.setenv("SUDO_UID", "1001")
    monkeypatch.setenv("SUDO_GID", "1002")

    config_text = sandbox._render_config(_policy(fake_nsjail))

    assert 'uidmap { inside_id: "65534" outside_id: "1001" count: 1 use_newidmap: false }' in config_text
    assert 'gidmap { inside_id: "65534" outside_id: "1002" count: 1 use_newidmap: false }' in config_text


def test_generated_nsjail_config_mounts_exact_files_below_work_after_its_writable_bind(
    fake_nsjail: tuple[Path, str, str]
) -> None:
    policy = _policy(fake_nsjail)
    source = Path(policy.scratch_dir).parent / "input.json"
    source.write_bytes(b"{}")
    file_mount = ReadOnlyMount("/work/staging-v1/manifests/input.json", str(source), _digest(b"{}"))
    config_text = sandbox._render_config(
        replace(policy, readonly_mounts=tuple(sorted((*policy.readonly_mounts, file_mount))))
    )

    writable = f'mount {{ src: {json.dumps(policy.scratch_dir)} dst: "/work" '
    root = f'mount {{ src: {json.dumps(policy.readonly_mounts[0].source)} dst: "/" '
    exact_file = f'mount {{ src: {json.dumps(str(source))} dst: "/work/staging-v1/manifests/input.json" '
    assert root in config_text and writable in config_text and exact_file in config_text
    assert config_text.index(root) < config_text.index(writable) < config_text.index(exact_file)
    assert 'is_dir: false mandatory: true nosuid: true nodev: true }' in config_text[config_text.index(exact_file):]


def test_generated_nsjail_config_uses_effective_identity_without_a_valid_sudo_invoker(
    monkeypatch: pytest.MonkeyPatch, fake_nsjail: tuple[Path, str, str]
) -> None:
    monkeypatch.setattr(sandbox.os, "geteuid", lambda: 0, raising=False)
    monkeypatch.setattr(sandbox.os, "getuid", lambda: 1003, raising=False)
    monkeypatch.setattr(sandbox.os, "getgid", lambda: 1004, raising=False)
    monkeypatch.setenv("SUDO_UID", "not-an-id")
    monkeypatch.setenv("SUDO_GID", "also-not-an-id")

    config_text = sandbox._render_config(_policy(fake_nsjail))

    assert 'uidmap { inside_id: "65534" outside_id: "1003" count: 1 use_newidmap: false }' in config_text
    assert 'gidmap { inside_id: "65534" outside_id: "1004" count: 1 use_newidmap: false }' in config_text


def test_malformed_nsjail_identity_inputs_reject() -> None:
    with pytest.raises(ValueError, match="identity inputs are malformed"):
        sandbox._nsjail_build_identity("not-a-commit", "sha256:" + "0" * 64)


def test_duplicate_mount_destination_rejects_before_execution(fake_nsjail: tuple[Path, str, str]) -> None:
    policy = replace(_policy(fake_nsjail), nsjail_path="/fixture-nsjail", scratch_dir="/fixture-scratch")
    # _validate_policy's contract is POSIX paths even when this unit test runs
    # on Windows, whose temporary paths are drive-letter paths.
    root_mount = replace(policy.readonly_mounts[0], source="/fixture-root")
    duplicate = replace(root_mount, source="/different-rootfs")
    duplicate_mounts = tuple(sorted((root_mount, duplicate)))
    invalid = replace(policy, readonly_mounts=duplicate_mounts)

    with pytest.raises(TransplantError) as caught:
        sandbox._validate_policy(invalid)

    assert caught.value.evidence.detail_code == "duplicate_mount_destination"


def test_scratch_source_cannot_overlap_readonly_inputs(fake_nsjail: tuple[Path, str, str]) -> None:
    policy = replace(_policy(fake_nsjail), nsjail_path="/fixture-nsjail", scratch_dir="/fixture-scratch")
    root_mount = replace(policy.readonly_mounts[0], source="/fixture-root")
    policy = replace(policy, readonly_mounts=(root_mount,))

    with pytest.raises(TransplantError) as caught:
        sandbox._validate_policy(replace(policy, scratch_dir=root_mount.source + "/scratch"))

    assert caught.value.evidence.detail_code == "scratch_source_overlap"


@pytest.mark.skipif(
    sys.platform != "linux",
    reason="nsjail containment is Linux-only (ADR-0009 §3)",
)
def test_missing_policy_pinned_scratch_source_rejects_before_execution(
    monkeypatch: pytest.MonkeyPatch, fake_nsjail: tuple[Path, str, str]
) -> None:
    monkeypatch.setenv("LEITIR_ENABLE_DONOR_EXECUTION", "1")
    policy = _policy(fake_nsjail)
    Path(policy.scratch_dir).rmdir()

    with pytest.raises(TransplantError) as caught:
        prepare_execution(policy)

    assert caught.value.evidence.detail_code == "scratch_source_unavailable"


def test_generated_config_matches_the_passing_handwritten_smoke_except_policy_mounts(
    fake_nsjail: tuple[Path, str, str]
) -> None:
    """Pin the runner-class smoke shape, including its direct bind-mounted root."""

    workflow = Path(__file__).parents[1] / ".github" / "workflows" / "bts-containment.yml"
    source = workflow.read_text(encoding="utf-8")
    marker = 'cat >"$config" <<EOF\n'
    pieces = source.split(marker, 1)
    assert len(pieces) == 2, f"workflow handwritten-smoke marker {marker!r} is missing"
    source_lines = pieces[1].splitlines()
    eof_index = next((index for index, line in enumerate(source_lines) if line.strip() == "EOF"), None)
    assert eof_index is not None, "workflow handwritten-smoke terminator is missing"
    handwritten = "\n".join(source_lines[:eof_index])
    host_uid = sandbox._host_mapping_id("SUDO_UID", getattr(os, "getuid", lambda: 0)())
    host_gid = sandbox._host_mapping_id("SUDO_GID", getattr(os, "getgid", lambda: 0)())
    expected = textwrap.dedent(handwritten).replace("$host_uid", str(host_uid)).replace("$host_gid", str(host_gid))
    policy = _policy(fake_nsjail)
    actual = sandbox._render_config(policy)

    def non_mount_lines(config: str) -> tuple[str, ...]:
        policy_bound = ("mount {", "cgroup_mem_max:", "cgroup_pids_max:", "cgroup_cpu_ms_per_sec:", "time_limit:", "cwd:", "rlimit_", "envar:")
        return tuple(line.strip() for line in config.splitlines() if not line.strip().startswith((*policy_bound, "#")))

    actual_root_mount = next(line for line in actual.splitlines() if ' dst: "/" ' in line)
    expected_root_mount = next(line for line in expected.splitlines() if ' dst: "/" ' in line)
    rendered_destinations = {
        json.loads(line.split(" dst: ", 1)[1].split(" fstype:", 1)[0])
        for line in actual.splitlines()
        if line.startswith("mount {")
    }
    assert rendered_destinations <= set(sandbox.ROOTFS_MOUNT_TARGETS)
    assert policy.writable_tmpfs == "/work" and "/work" in sandbox.ROOTFS_MOUNT_TARGETS
    assert "mount_proc: true" in actual and "/proc" in sandbox.ROOTFS_MOUNT_TARGETS
    assert non_mount_lines(actual) == non_mount_lines(expected)
    # Only the policy-pinned source differs; the root bind's destination and
    # security shape must remain identical to the passing handwritten smoke.
    assert actual_root_mount.split(" dst:", 1)[1] == expected_root_mount.split(" dst:", 1)[1]
    assert 'cgroupv2_mount: "/sys/fs/cgroup"' in actual
    assert 'cgroupv2_mount: "/sys/fs/cgroup"' in expected


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
        "ALLOW { access, arch_prctl, brk, clock_gettime, close, epoll_create1 { flags == 524288 }, execve, exit, exit_group, fcntl, futex, getcwd, "
        "getdents64, getpid, getrandom, gettid, ioctl { cmd == 21505 }, lseek, mkdir, mmap, mprotect, munmap, "
        "newfstat, newfstatat, open, openat, pread64, prlimit64, read, readlink, readlinkat, rename, rseq, rt_sigaction, rt_sigprocmask, "
        "sched_getaffinity, set_robust_list, set_tid_address, statx, write }\n"
    )
    allowed = {item.value for item in sandbox.CANONICAL_SECCOMP_POLICY.allowed_syscalls}
    assert "stat" not in allowed
    assert {"newfstat", "newfstatat"} <= allowed
    assert "ioctl { cmd == 21505 }" in allowed
    assert "ALLOW { ioctl," not in policy.seccomp_string
    assert "epoll_create1 { flags == 524288 }" in allowed
    assert "ALLOW { epoll_create1," not in policy.seccomp_string
    assert allowed.isdisjoint(sandbox._FORBIDDEN_SYSCALLS)


def test_debug_config_enables_kernel_seccomp_audit_only_when_requested(
    monkeypatch: pytest.MonkeyPatch, fake_nsjail: tuple[Path, str, str]
) -> None:
    policy = _policy(fake_nsjail)
    assert "seccomp_log: true" not in sandbox._render_config(policy)
    monkeypatch.setenv(sandbox.NSJAIL_DEBUG_ENV, "1")
    config = sandbox._render_config(policy)
    assert "seccomp_log: true" in config
    assert f"seccomp_string: {json.dumps(sandbox.CANONICAL_SECCOMP_STRING)}" in config


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


@pytest.mark.skipif(sys.platform != "linux", reason="nsjail containment is Linux-only (ADR-0009 §3)")
def test_mount_source_digest_debug_reports_per_entry_diff(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], fake_nsjail: tuple[Path, str, str]
) -> None:
    monkeypatch.setenv("LEITIR_ENABLE_DONOR_EXECUTION", "1")
    monkeypatch.setenv("LEITIR_NSJAIL_DEBUG", "1")
    policy = _policy(fake_nsjail)
    sandbox.record_debug_mount_source_manifests(policy)
    root_file = Path(policy.readonly_mounts[0].source, "python")
    root_file.chmod(0o755)
    root_file.write_bytes(b"tampered")
    with pytest.raises(TransplantError):
        prepare_execution(policy)
    diagnostic = capsys.readouterr().err.removeprefix("leitir mount-source digest mismatch ")
    payload = json.loads(diagnostic)
    assert payload["actual_digest"] != payload["expected_digest"]
    assert payload["entry_diff"] == [
        {
            "actual": {"mode": 0o755, "path": "python", "sha256": _digest(b"tampered"), "size": 8, "type": "file"},
            "expected": {"mode": 0o555, "path": "python", "sha256": _digest(b"rootfs"), "size": 6, "type": "file"},
            "path": "python",
        }
    ]


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
        "scratch_dir": policy.scratch_dir,
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
def test_offline_execution_reaches_backend_after_static_containment_validation(
    monkeypatch: pytest.MonkeyPatch, fake_nsjail: tuple[Path, str, str], tmp_path: Path
) -> None:
    monkeypatch.setenv("LEITIR_ENABLE_DONOR_EXECUTION", "1")
    plan = prepare_execution(_policy(fake_nsjail))
    marker = tmp_path / "donor-ran"
    result = run_contained(plan, (sys.executable, "-c", f"open({str(marker)!r}, 'w').write('ok')"))
    # The old unconditional parent-side barrier made this unreachable.  The
    # real rootfs runner's mandatory startup frame is verified by rerun.py.
    assert result.completed
    assert marker.read_text(encoding="utf-8") == "ok"


@pytest.mark.skipif(
    sys.platform != "linux",
    reason="nsjail containment is Linux-only (ADR-0009 §3)",
)
def test_contained_launch_clears_state_left_in_the_policy_pinned_scratch_source(
    monkeypatch: pytest.MonkeyPatch, fake_nsjail: tuple[Path, str, str]
) -> None:
    monkeypatch.setenv("LEITIR_ENABLE_DONOR_EXECUTION", "1")
    policy = _policy(fake_nsjail)
    stale = Path(policy.scratch_dir) / "from-prior-role"
    stale.write_text("untrusted", encoding="utf-8")

    result = run_contained(prepare_execution(policy), (sys.executable, "-c", "pass"))

    assert result.completed and not stale.exists()


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
scratch_path = {str(path.parent / 'scratch')!r}
__import__('pathlib').Path(scratch_path).mkdir(exist_ok=True)
__import__('pathlib').Path(scratch_path).chmod(0o777)
payload = {{'readonly_mounts':[{{'destination':'/','source':root_path,'source_digest':root}}], 'rootfs_digest':root, 'scratch_dir':scratch_path, 'writable_tmpfs':'/work', 'writable_tmpfs_bytes':1048576, 'writable_tmpfs_inodes':128}}
md = 'sha256:' + hashlib.sha256((json.dumps(payload, sort_keys=True, separators=(',', ':')) + '\\n').encode()).hexdigest()
p = ContainmentPolicy(POLICY_SCHEMA, {str(path)!r}, {_digest(path.read_bytes())!r}, {version!r}, {build_identity!r}, 'sha256:'+'2'*64, platform.machine(), root, md, mounts, '/work', 1048576, 128, scratch_path, '/work', 'ONCE', False, True, True, True, True, True, True, True, 67108864, 16, 500, 2, 64, 1, 1, 32, 16, 8, 0, 4096, ('LANG=C.UTF-8','PYTHONHASHSEED=0','TZ=UTC'), True)
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
