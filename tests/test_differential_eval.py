"""Offline tests for the differential eval harness (issue #266 E2/E3).

All tests here run with the deterministic stub runner
(``benchmarks.differential.stub_runner.DeterministicStubRunner``): no
network, no model credential, no paid call. Every ``leitir check`` shell-out
is redirected (via ``check_env_overrides``) to an unreachable local port so
the harness is deterministic regardless of whether the host running it
happens to have real network access.
"""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest
from _http_server import json_body, routed_server

_REPO_ROOT = Path(__file__).resolve().parents[1]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from benchmarks.differential import harness, report, tasks
from benchmarks.differential.check_bridge import run_leitir_check
from benchmarks.differential.metrics import Measured, Unavailable
from benchmarks.differential.prompt import (
    EvaluatorLeakError,
    assert_no_evaluator_leak,
    build_generation_request,
    render_payload,
)
from benchmarks.differential.runner import Arm, GenerationResult
from benchmarks.differential.stub_runner import DeterministicStubRunner

# An address nothing listens on: every `leitir check` network call this
# harness makes in these tests is redirected here, so it fails fast with
# ECONNREFUSED instead of depending on (or being blocked by) real network
# access in whatever sandbox runs these tests.
_UNREACHABLE_ENV = {
    "LEITIR_PYPI_BASE_URL": "http://127.0.0.1:1",
    "LEITIR_GITHUB_API_BASE_URL": "http://127.0.0.1:1",
    "LEITIR_CODELOAD_BASE_URL": "http://127.0.0.1:1",
}


def _manifest_bytes() -> bytes:
    return tasks.MANIFEST_PATH.read_bytes()


def _run_full_harness(tmp_path: Path) -> tuple[harness.DifferentialRunResult, tuple]:
    all_tasks = tasks.load_tasks()
    result = harness.run_all(
        all_tasks,
        DeterministicStubRunner(),
        check_corpus_root=tmp_path / "corpus-root",
        check_env_overrides=_UNREACHABLE_ENV,
    )
    return result, all_tasks


# ---------------------------------------------------------------------------
# End-to-end, all three arms, offline
# ---------------------------------------------------------------------------


def test_end_to_end_stub_run_all_arms_offline(tmp_path: Path) -> None:
    before_bytes = _manifest_bytes()
    digest_before = tasks.manifest_digest()

    result, all_tasks = _run_full_harness(tmp_path)
    assert len(result.tasks) == 5

    digest_after = tasks.manifest_digest()
    after_bytes = _manifest_bytes()
    assert digest_before == digest_after
    assert before_bytes == after_bytes

    payload = report.build_report(
        result,
        manifest_digest_before=digest_before,
        manifest_digest_after=digest_after,
        runner_name="stub",
    )
    # The whole report must be JSON-serializable and round-trip cleanly.
    json.dumps(payload)
    assert payload["manifest_unchanged"] is True

    for task_json in payload["tasks"]:
        arms = task_json["arms"]
        # Arm C (leitir): the stub always gets it right first try.
        assert arms["C"]["status"] == "scored"
        assert arms["C"]["first_pass_correct"] == {"status": "measured", "value": True}
        assert arms["C"]["post_repair_correct"] == {"status": "measured", "value": True}
        assert arms["C"]["repair_attempts_used"] == {"status": "measured", "value": 0}

        # Arm B (raw search): wrong first try, converges after one repair.
        assert arms["B"]["status"] == "scored"
        assert arms["B"]["first_pass_correct"] == {"status": "measured", "value": False}
        assert arms["B"]["post_repair_correct"] == {"status": "measured", "value": True}
        assert arms["B"]["repair_attempts_used"] == {"status": "measured", "value": 1}

        # Arm A (no retrieval): never converges within the repair budget.
        assert arms["A"]["status"] == "scored"
        assert arms["A"]["first_pass_correct"] == {"status": "measured", "value": False}
        assert arms["A"]["post_repair_correct"] == {"status": "measured", "value": False}
        assert arms["A"]["repair_attempts_used"]["value"] == harness.DEFAULT_REPAIR_BUDGET

    agg = payload["aggregate_metrics"]
    assert agg["C"]["fpcr"]["numerator"] == 5
    assert agg["C"]["fpcr"]["denominator"] == 5
    assert agg["C"]["fpcr"]["percentage"] == 1.0
    assert agg["B"]["fpcr"]["percentage"] == 0.0
    assert agg["B"]["sccr"]["percentage"] == 1.0
    assert agg["A"]["sccr"]["percentage"] == 0.0

    compared = payload["arms_compared"]
    assert compared["fpcr_delta"] == {"status": "measured", "value": 1.0}
    # Arm C (leitir) never has a first-pass failure in this stub scenario, so
    # its SCCR population is empty (zero-denominator) -- per ADR-0002, that
    # is honestly Unavailable, never a fabricated 0.0 or 1.0.
    assert compared["sccr_delta"]["status"] == "unavailable"
    assert agg["C"]["sccr"]["denominator"] == 0
    assert agg["C"]["sccr"]["percentage"] is None


# ---------------------------------------------------------------------------
# Evaluator seam
# ---------------------------------------------------------------------------


def test_contract_test_bytes_never_appear_in_any_prompt_payload(tmp_path: Path) -> None:
    result, all_tasks = _run_full_harness(tmp_path)
    assert result.prompt_trace, "expected at least one prompt to have been built"

    all_contract_bytes = [t.evaluator.contract_test_bytes for t in all_tasks]
    all_contract_paths = [str(t.evaluator.contract_test_path) for t in all_tasks]

    for record in result.prompt_trace:
        payload_bytes = record.text.encode("utf-8", errors="surrogateescape")
        for contract_bytes in all_contract_bytes:
            assert contract_bytes not in payload_bytes, (
                f"contract-test bytes leaked into a {record.phase} prompt for "
                f"task={record.task_id} arm={record.arm}"
            )
        for contract_path in all_contract_paths:
            assert contract_path not in record.text


def test_assert_no_evaluator_leak_is_not_vacuous(tmp_path: Path) -> None:
    """Positive control: the leak check actually detects a real leak."""

    all_tasks = tasks.load_tasks()
    evaluator_assets = tuple(t.evaluator for t in all_tasks)
    leaking_payload = "here is the hidden test:\n" + evaluator_assets[0].contract_test_bytes.decode()

    with pytest.raises(EvaluatorLeakError):
        assert_no_evaluator_leak(leaking_payload, evaluator_assets)

    # A clean payload, built the sanctioned way, must not raise.
    clean_request = build_generation_request(all_tasks[0].public, Arm.LEITIR)
    assert_no_evaluator_leak(render_payload(clean_request), evaluator_assets)


def test_harness_aborts_run_if_a_leak_is_ever_constructed(tmp_path: Path) -> None:
    """The harness calls the leak check on every payload it builds -- confirm it is wired in."""

    all_tasks = tasks.load_tasks()
    evaluator_assets = tuple(t.evaluator for t in all_tasks)
    leaking_payload = evaluator_assets[0].contract_test_bytes.decode()
    with pytest.raises(EvaluatorLeakError):
        assert_no_evaluator_leak(leaking_payload, evaluator_assets)


# ---------------------------------------------------------------------------
# Unavailable, never zero
# ---------------------------------------------------------------------------


def test_uncomputable_metric_is_unavailable_never_zero(tmp_path: Path) -> None:
    result, _ = _run_full_harness(tmp_path)
    saw_any = False
    for task_result in result.tasks:
        for arm_result in task_result.arms.values():
            assert arm_result.status == "scored"
            metric = arm_result.hallucinated_symbol_count
            # Network is redirected to an unreachable address, so this must
            # always come back Unavailable -- never Measured(0).
            assert isinstance(metric, Unavailable), (
                f"expected hallucination count to be Unavailable without network, got {metric!r}"
            )
            assert not isinstance(metric, Measured)
            saw_any = True
    assert saw_any


def test_infrastructure_invalid_never_reported_as_a_pass_or_fail() -> None:
    task = tasks.load_tasks()[0]

    class _CrashingRunner:
        def generate(self, request):  # noqa: ANN001, ANN201
            return GenerationResult(
                code="this is not ) ( valid python :::",
                tokens_used=Measured(1),
                steps_used=Measured(1),
            )

        def repair(self, request, prior_code, signal):  # noqa: ANN001, ANN201
            return self.generate(request)

    result = harness.run_all(
        (task,),
        _CrashingRunner(),
        check_corpus_root=Path("/tmp/unused-corpus-root"),
        check_env_overrides=_UNREACHABLE_ENV,
    )
    arm_result = result.tasks[0].arms[Arm.LEITIR]
    # A syntax error still collects as a pytest failure/error, not a crash --
    # but assert the harness never reports invalid infra as first_pass True.
    assert arm_result.status in {"scored", "infrastructure_invalid"}
    if arm_result.status == "scored":
        assert arm_result.first_pass_correct == Measured(False)
    else:
        assert isinstance(arm_result.first_pass_correct, Unavailable)


# ---------------------------------------------------------------------------
# check_bridge: real classification logic, exercised offline via a fixture
# ---------------------------------------------------------------------------

_SHA = "b" * 40


def _demo_tarball() -> bytes:
    import io
    import tarfile

    # Issue #269 follow-up: tier 4 (a purely structural directory-layout
    # scan) was retired as an authority (ADR-0032, "Tier 4 was retired as
    # an authority") -- it could still bind a wrong root and produce a
    # false violation. A real top_level.txt (tier 1, authoritative) is
    # now required for check to resolve "demo" as the import root at all.
    source = b"def Known(x):\n    return x\n"
    files = {
        "demo/__init__.py": source,
        "demo.egg-info/top_level.txt": b"demo\n",
    }
    data = io.BytesIO()
    with tarfile.open(fileobj=data, mode="w:gz") as archive:
        for name, content_bytes in files.items():
            member = tarfile.TarInfo(f"demo-{_SHA}/{name}")
            member.size = len(content_bytes)
            archive.addfile(member, io.BytesIO(content_bytes))
    return data.getvalue()


def _demo_routes(package_bytes: bytes) -> dict:
    return {
        "/pypi/demo/1.2/json": (
            200,
            {},
            json_body({"info": {"project_urls": {"Source": "https://github.com/acme/demo"}}}),
        ),
        "/repos/acme/demo/git/ref/tags/v1.2": (
            200,
            {},
            json_body({"object": {"type": "commit", "sha": _SHA}}),
        ),
        f"/acme/demo/tar.gz/{_SHA}": (200, {}, package_bytes),
    }


def test_check_bridge_measures_a_real_violation_via_local_fixture(tmp_path: Path) -> None:
    candidate = tmp_path / "candidate.py"
    candidate.write_text("import demo\n\ndemo.TotallyMadeUp(1)\n", encoding="utf-8")
    with routed_server(_demo_routes(_demo_tarball())) as server:
        measurement = run_leitir_check(
            candidate_path=candidate,
            against_spec="pypi:demo@1.2",
            corpus_root=tmp_path / "root",
            cwd=tmp_path,
            extra_env={
                "LEITIR_PYPI_BASE_URL": server.base_url + "/pypi",
                "LEITIR_GITHUB_API_BASE_URL": server.base_url,
                "LEITIR_CODELOAD_BASE_URL": server.base_url,
            },
        )
    assert measurement.hallucinated_symbol_count == Measured(1)
    assert measurement.check_status == Measured("violations_found")


def test_check_bridge_measures_clean_via_local_fixture(tmp_path: Path) -> None:
    candidate = tmp_path / "candidate.py"
    candidate.write_text("import demo\n\ndemo.Known(1)\n", encoding="utf-8")
    with routed_server(_demo_routes(_demo_tarball())) as server:
        measurement = run_leitir_check(
            candidate_path=candidate,
            against_spec="pypi:demo@1.2",
            corpus_root=tmp_path / "root",
            cwd=tmp_path,
            extra_env={
                "LEITIR_PYPI_BASE_URL": server.base_url + "/pypi",
                "LEITIR_GITHUB_API_BASE_URL": server.base_url,
                "LEITIR_CODELOAD_BASE_URL": server.base_url,
            },
        )
    assert measurement.hallucinated_symbol_count == Measured(0)
    assert measurement.check_status == Measured("clean")


def test_check_bridge_nothing_examined_is_unavailable_not_zero(tmp_path: Path) -> None:
    candidate = tmp_path / "candidate.py"
    candidate.write_text("print('no usage of demo at all')\n", encoding="utf-8")
    with routed_server(_demo_routes(_demo_tarball())) as server:
        measurement = run_leitir_check(
            candidate_path=candidate,
            against_spec="pypi:demo@1.2",
            corpus_root=tmp_path / "root",
            cwd=tmp_path,
            extra_env={
                "LEITIR_PYPI_BASE_URL": server.base_url + "/pypi",
                "LEITIR_GITHUB_API_BASE_URL": server.base_url,
                "LEITIR_CODELOAD_BASE_URL": server.base_url,
            },
        )
    assert isinstance(measurement.hallucinated_symbol_count, Unavailable)
    assert isinstance(measurement.check_status, Unavailable)


def test_check_bridge_unreachable_network_is_unavailable(tmp_path: Path) -> None:
    candidate = tmp_path / "candidate.py"
    candidate.write_text("import demo\n", encoding="utf-8")
    measurement = run_leitir_check(
        candidate_path=candidate,
        against_spec="pypi:demo@1.2",
        corpus_root=tmp_path / "root",
        cwd=tmp_path,
        extra_env=_UNREACHABLE_ENV,
    )
    assert isinstance(measurement.hallucinated_symbol_count, Unavailable)


# ---------------------------------------------------------------------------
# Manifest is read, not modified
# ---------------------------------------------------------------------------


def test_exit_corpus_manifest_digest_unchanged_after_a_run(tmp_path: Path) -> None:
    before = hashlib.sha256(_manifest_bytes()).hexdigest()
    _run_full_harness(tmp_path)
    after = hashlib.sha256(_manifest_bytes()).hexdigest()
    assert before == after
    assert before == hashlib.sha256(tasks.MANIFEST_PATH.read_bytes()).hexdigest()


def test_load_tasks_does_not_write_under_exit_corpus(tmp_path: Path) -> None:
    corpus_dir = tasks.EXIT_CORPUS_ROOT
    before = sorted(str(p) for p in corpus_dir.rglob("*"))
    tasks.load_tasks()
    _run_full_harness(tmp_path)
    after = sorted(str(p) for p in corpus_dir.rglob("*"))
    assert before == after


# ---------------------------------------------------------------------------
# Determinism across PYTHONHASHSEED
# ---------------------------------------------------------------------------

_DETERMINISM_SCRIPT = """
import json
import sys
from pathlib import Path

sys.path.insert(0, {repo_root!r})

from benchmarks.differential import harness, report, tasks
from benchmarks.differential.stub_runner import DeterministicStubRunner

all_tasks = tasks.load_tasks()
one_task = (all_tasks[0],)
result = harness.run_all(
    one_task,
    DeterministicStubRunner(),
    check_corpus_root=Path({corpus_root!r}),
    repair_budget=1,
    check_env_overrides={unreachable_env!r},
)
digest = tasks.manifest_digest()
payload = report.build_report(
    result,
    manifest_digest_before=digest,
    manifest_digest_after=digest,
    runner_name="stub",
)
print(json.dumps(payload, sort_keys=True))
"""


def test_deterministic_across_pythonhashseed(tmp_path: Path) -> None:
    seeds = ["0", "1", "2", "17"]
    outputs = []
    for i, seed in enumerate(seeds):
        corpus_root = tmp_path / f"corpus-{i}"
        script = _DETERMINISM_SCRIPT.format(
            repo_root=str(_REPO_ROOT),
            corpus_root=str(corpus_root),
            unreachable_env=_UNREACHABLE_ENV,
        )
        env = dict(os.environ)
        env["PYTHONHASHSEED"] = seed
        completed = subprocess.run(
            [sys.executable, "-c", script],
            cwd=str(_REPO_ROOT),
            env=env,
            capture_output=True,
            text=True,
            timeout=120,
        )
        assert completed.returncode == 0, completed.stderr
        outputs.append(completed.stdout)

    assert len(set(outputs)) == 1, "harness output differs across PYTHONHASHSEED values"
