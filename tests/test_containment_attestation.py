"""Direct-call lifecycle tests for contained startup attestation and abort (issue #192).

The tests exercise the validation and lifecycle functions directly with test
doubles only: the genuinely backend-bound paths stay ``pragma: no cover`` and
are exercised by the bts-containment CI job (ADR-0009 §10).  Every spawned
double self-terminates, so a probe that fails to kill its child cannot leak a
process past the double's own deadline.
"""

from __future__ import annotations

import hashlib
import json
import os
import platform
import subprocess
import sys
import time
from pathlib import Path

import pytest

import leitir.exec_sandbox as sandbox
from leitir.bts_errors import BTSRejectReason, TransplantError
from leitir.exec_sandbox import (
    POLICY_SCHEMA,
    ContainmentPolicy,
    ReadOnlyMount,
    prepare_execution,
    run_contained,
    validate_startup_attestation,
)

_LINUX_ONLY = pytest.mark.skipif(
    sys.platform != "linux",
    reason="nsjail containment is Linux-only (ADR-0009 §3)",
)
_NAMESPACES = ("net", "user", "mnt", "pid", "ipc", "uts")
_NSJAIL_COMMIT = "f78475530b46d0186111a9096b30725f816b55fe"


def _digest(data: bytes) -> str:
    return f"sha256:{hashlib.sha256(data).hexdigest()}"


def _canonical_digest(value: object) -> str:
    data = (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False) + "\n").encode()
    return _digest(data)


def _applied_receipt(**overrides: object) -> dict[str, object]:
    receipt: dict[str, object] = {
        "schema_version": sandbox.STARTUP_ATTESTATION_SCHEMA,
        "namespace_mismatch": True,
        "pid_namespace_init": True,
        "no_new_privs": True,
        "seccomp_mode": 2,
    }
    receipt.update(overrides)
    return receipt


# ---------------------------------------------------------------------------
# (a) startup attestation requires BOTH seccomp and NoNewPrivs (C-1/C-2)
# ---------------------------------------------------------------------------


def test_g0_receipt_with_seccomp_absent_but_no_new_privs_set_is_rejected() -> None:
    """The contract's G-0 probe: NoNewPrivs alone must never satisfy the receipt."""

    receipt = _applied_receipt(seccomp_mode=0)
    with pytest.raises(ValueError, match="startup containment privilege receipt is not applied"):
        validate_startup_attestation(receipt)


@pytest.mark.parametrize("mode", [0, 1, 3])
def test_receipt_without_installed_seccomp_filter_is_rejected_whatever_nnp(mode: int) -> None:
    with pytest.raises(ValueError, match="startup containment privilege receipt is not applied"):
        validate_startup_attestation(_applied_receipt(seccomp_mode=mode))


def test_receipt_without_no_new_privs_is_rejected_whatever_seccomp() -> None:
    with pytest.raises(ValueError, match="startup containment privilege receipt is not applied"):
        validate_startup_attestation(_applied_receipt(no_new_privs=False))


def test_applied_receipt_with_both_controls_is_accepted() -> None:
    validate_startup_attestation(_applied_receipt())


@pytest.mark.parametrize(
    "receipt",
    [
        {"schema_version": sandbox.STARTUP_ATTESTATION_SCHEMA, "no_new_privs": True, "seccomp_mode": 2},
        _applied_receipt(subject_digest=None),
        _applied_receipt(no_new_privs="true"),
        _applied_receipt(seccomp_mode=True),
        _applied_receipt(schema_version="leitir-contained-startup-attestation-v2"),
        _applied_receipt(namespace_mismatch=False),
        _applied_receipt(pid_namespace_init=False),
    ],
)
def test_receipt_shape_failures_still_reject_before_the_privilege_check(receipt: dict[str, object]) -> None:
    """SP-2: malformed shapes keep rejecting; the AND fix accepts nothing new."""

    with pytest.raises(ValueError):
        validate_startup_attestation(receipt)


def test_procfs_receipt_with_no_new_privs_but_seccomp_absent_is_rejected_end_to_end() -> None:
    parent = {name: (1, index) for index, name in enumerate(_NAMESPACES, 1)}
    child = {name: (2, index) for index, name in enumerate(_NAMESPACES, 1)}
    receipt = sandbox.startup_attestation_from_proc("NoNewPrivs:\t1\nSeccomp:\t0\n", child, parent, pid=1)
    with pytest.raises(ValueError, match="startup containment privilege receipt is not applied"):
        validate_startup_attestation(receipt)


# ---------------------------------------------------------------------------
# Containment lifecycle doubles (mirrors tests/test_exec_sandbox.py fixtures)
# ---------------------------------------------------------------------------


def _fake_backend(tmp_path: Path, name: str, probe_body: str) -> tuple[Path, str, str]:
    path = tmp_path / name
    path.write_text(f"#!{sys.executable}\n{probe_body}", encoding="utf-8")
    path.chmod(0o700)
    binary_digest = _digest(path.read_bytes())
    return path, f"nsjail@{_NSJAIL_COMMIT}", sandbox._nsjail_build_identity(_NSJAIL_COMMIT, binary_digest)


@pytest.fixture
def fake_nsjail(tmp_path: Path) -> tuple[Path, str, str]:
    return _fake_backend(
        tmp_path,
        "nsjail",
        "import os, sys\n"
        "if sys.argv[1:] == ['--help']:\n"
        "    sys.stderr.write('usage: nsjail [options]\\n' * 512)\n"
        "    raise SystemExit(255)\n"
        "separator = sys.argv.index('--')\n"
        "argv = sys.argv[separator + 1:]\n"
        "os.execv(argv[0], argv)\n",
    )


@pytest.fixture
def hanging_nsjail(tmp_path: Path) -> tuple[Path, str, str]:
    return _fake_backend(
        tmp_path,
        "nsjail-hanging",
        "import os, sys, time\n"
        f"open({str(tmp_path / 'hung-child.pid')!r}, 'w').write(str(os.getpid()))\n"
        "sys.stdout.write('usage: nsjail [options]\\n')\n"
        "sys.stdout.flush()\n"
        "time.sleep(60)\n",
    )


def _policy(backend: tuple[Path, str, str], *, output_limit: int = 4096, wall_time: int = 2) -> ContainmentPolicy:
    path, version, build_identity = backend
    rootfs = path.parent / f"{path.name}-rootfs"
    rootfs.mkdir()
    (rootfs / "python").write_bytes(b"rootfs")
    (rootfs / "python").chmod(0o555)
    root_digest = sandbox._verified_directory_tree_digest(rootfs)
    mount = ReadOnlyMount("/", str(rootfs), root_digest)
    scratch = path.parent / f"{path.name}-scratch"
    scratch.mkdir()
    scratch.chmod(0o777)
    mount_payload = {"readonly_mounts": [{"destination": "/", "source_digest": root_digest}], "rootfs_digest": root_digest, "writable_tmpfs": "/work", "writable_tmpfs_bytes": 1_048_576, "writable_tmpfs_inodes": 128}
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


# ---------------------------------------------------------------------------
# (b) abort path kills and reaps the launched child (C-3 / AC-2 / SP-3)
# ---------------------------------------------------------------------------


@_LINUX_ONLY
def test_controller_failure_kills_and_reaps_the_child_before_aborting(
    monkeypatch: pytest.MonkeyPatch, fake_nsjail: tuple[Path, str, str]
) -> None:
    monkeypatch.setenv(sandbox.DONOR_EXECUTION_ENV, "1")
    plan = prepare_execution(_policy(fake_nsjail))
    spawned: list[subprocess.Popen[bytes]] = []

    def controller_failure(
        process: subprocess.Popen[bytes], *, limit: int, timeout: int, applied_state: object
    ) -> object:
        spawned.append(process)
        raise OSError("controller-side failure after child spawn")

    monkeypatch.setattr(sandbox, "_bounded_communicate", controller_failure)

    result = run_contained(plan, (sys.executable, "-c", "import time; time.sleep(60)"))

    [process] = spawned
    assert result.completed is False
    assert result.abort is not None
    assert result.abort.detail_category == "launcher_failure"
    assert result.abort.reason is BTSRejectReason.REJECT_HARD_GATE_FAILED
    # returncode is set only once wait() has reaped the child; a negative code
    # proves it died by signal (SIGKILL) instead of outliving the controller.
    assert process.poll() is not None
    assert process.returncode is not None and process.returncode < 0
    assert process.stdout is not None and process.stdout.closed
    assert process.stderr is not None and process.stderr.closed
    # C-3 idempotency: reaping the already-reaped child again is a no-op.
    assert sandbox._reap_launched_child(process) is True


@_LINUX_ONLY
def test_reap_helper_is_idempotent_on_an_already_exited_child() -> None:
    process = subprocess.Popen(
        (sys.executable, "-c", "pass"),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        start_new_session=True,
    )
    process.wait(timeout=10)

    assert sandbox._reap_launched_child(process) is True
    assert process.stdout is not None and process.stdout.closed
    assert process.stderr is not None and process.stderr.closed
    assert sandbox._reap_launched_child(process) is True


# ---------------------------------------------------------------------------
# (c) the nsjail identity probe is time- and byte-bounded (C-4 / AC-3 / SP-4)
# ---------------------------------------------------------------------------


@_LINUX_ONLY
def test_probe_returns_usage_output_from_a_cooperative_backend(fake_nsjail: tuple[Path, str, str]) -> None:
    path, _, _ = fake_nsjail

    output = sandbox._probe_backend_output(str(path))

    assert b"usage: nsjail [options]" in output
    assert len(output) <= sandbox._MAX_NSJAIL_PROBE_OUTPUT_BYTES + 1


@_LINUX_ONLY
def test_probe_is_bounded_and_kills_a_child_that_never_closes_stdout(
    tmp_path: Path, hanging_nsjail: tuple[Path, str, str]
) -> None:
    started = time.monotonic()
    with pytest.raises(subprocess.TimeoutExpired):
        sandbox._probe_backend_output(str(hanging_nsjail[0]))
    elapsed = time.monotonic() - started

    # The bound is 2s plus a bounded reap; 30s is far above it and far below
    # the double's own 60s self-termination.
    assert elapsed < 30
    child_pid = int((tmp_path / "hung-child.pid").read_text(encoding="ascii"))
    # A zombie would still be signalable: ENOENT proves the hung child was
    # killed AND reaped (waited on) before the probe surfaced its failure.
    with pytest.raises(ProcessLookupError):
        os.kill(child_pid, 0)


@_LINUX_ONLY
def test_probe_never_reads_beyond_the_output_cap_from_a_flooding_child(tmp_path: Path) -> None:
    backend = _fake_backend(
        tmp_path,
        "nsjail-flooding",
        "import os, sys, time\n"
        f"open({str(tmp_path / 'flooding-child.pid')!r}, 'w').write(str(os.getpid()))\n"
        "for _ in range(2048):\n"
        "    sys.stdout.write('x' * 4096)\n"
        "    sys.stdout.flush()\n"
        "time.sleep(60)\n",
    )

    started = time.monotonic()
    with pytest.raises(subprocess.TimeoutExpired):
        sandbox._probe_backend_output(str(backend[0]))

    # An unbounded read would either block forever on the stalled pipe or
    # consume megabytes; the bounded probe fails within its deadline instead.
    assert time.monotonic() - started < 30
    child_pid = int((tmp_path / "flooding-child.pid").read_text(encoding="ascii"))
    with pytest.raises(ProcessLookupError):
        os.kill(child_pid, 0)


@_LINUX_ONLY
def test_verify_backend_rejects_a_hung_backend_within_the_bound(hanging_nsjail: tuple[Path, str, str]) -> None:
    policy = _policy(hanging_nsjail)

    started = time.monotonic()
    with pytest.raises(TransplantError) as caught:
        sandbox._verify_backend(policy)

    assert time.monotonic() - started < 30
    assert caught.value.evidence.detail_code == "nsjail_identity_unavailable"
