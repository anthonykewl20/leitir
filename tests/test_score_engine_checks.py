"""ADR-002 S3 offline engine-correctness collector and adapter gates."""

from __future__ import annotations

import ast
import hashlib
import json
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from tools.score_engine import (
    ADR001_OFFLINE_GATE_ARGV,
    ADR001_OFFLINE_GATE_TESTS,
    CheckResult,
    CheckStatus,
    CommandExecution,
    EvidenceArtifact,
    Producer,
    Profile,
    Subject,
    collect_adr001_pytest_junit,
    evaluate,
    evaluate_deterministic_replay,
    evaluate_engine_correctness_evidence,
    evaluate_global_no_exhaustiveness,
    evaluate_pytest_junit,
    evaluate_result_provenance,
    evaluate_retired_surfaces_absent,
    evaluate_scoped_coverage,
    evaluate_total_ordering,
    load_policy,
)

REPO_ROOT = Path(__file__).resolve().parents[1]
FIXTURES = REPO_ROOT / "tests" / "fixtures_score" / "engine"


def _artifact(
    name: str,
    artifact_id: str,
    *,
    process_exit: int | None = None,
) -> EvidenceArtifact:
    content = (FIXTURES / name).read_bytes()
    command = None
    if process_exit is not None:
        command = CommandExecution(
            argv=ADR001_OFFLINE_GATE_ARGV,
            process_exit=process_exit,
            collector_reason_code="COLLECTOR_COMPLETE",
        )
    return EvidenceArtifact(
        id=artifact_id,
        path=f"tests/fixtures_score/engine/{name}",
        sha256=hashlib.sha256(content).hexdigest(),
        content=content,
        command=command,
    )


def _global_artifact(exclusions: object) -> EvidenceArtifact:
    content = json.dumps(
        {
            "spec_digest": "c" * 64,
            "coverage": {
                "status": "indeterminate_global",
                "files_eligible": 2,
                "files_indexed": 1,
                "files_excluded": 1,
                "incomplete_results": False,
                "exclusions": exclusions,
            },
            "matches": [],
            "resolution": {
                "strategy": "indexed_commit",
                "as_of": "2026-08-06T12:00:00Z",
            },
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return EvidenceArtifact(
        id="global.coverage",
        path="global-report.json",
        sha256=hashlib.sha256(content).hexdigest(),
        content=content,
    )


def _junit(name: str, process_exit: int) -> EvidenceArtifact:
    return _artifact(name, f"junit.{name.removesuffix('.xml')}", process_exit=process_exit)


def _replays() -> tuple[EvidenceArtifact, ...]:
    return (
        _artifact("benchmark-run-pass.json", "benchmark.baseline"),
        _artifact("benchmark-run-repeat.json", "benchmark.repeat"),
        _artifact("benchmark-run-permuted.json", "benchmark.permuted"),
    )


def _collected_junit(
    tmp_path: Path,
    monkeypatch,
    content: bytes,
    *,
    process_exit: int = 0,
) -> EvidenceArtifact:
    (tmp_path / "src").mkdir(exist_ok=True)

    def fake_run(_argv, **_kwargs):
        output = tmp_path / ".leitir-score" / "evidence" / "adr001-offline-junit.xml"
        output.write_bytes(content)
        return SimpleNamespace(returncode=process_exit)

    monkeypatch.setattr(subprocess, "run", fake_run)
    return collect_adr001_pytest_junit(tmp_path)


def _ten_test_junit(*, passed: int, skipped: int, timestamp: str) -> bytes:
    cases = [
        f'<testcase classname="tests.test_engine" name="test_pass_{index}" time="0.001" />'
        for index in range(passed)
    ]
    cases.extend(
        f'<testcase classname="tests.test_engine" name="test_skip_{index}" time="0.002">'
        '<skipped type="pytest.skip" message="offline prerequisite unavailable">'
        "offline prerequisite unavailable</skipped></testcase>"
        for index in range(skipped)
    )
    return (
        '<?xml version="1.0" encoding="utf-8"?>'
        '<testsuites name="pytest tests"><testsuite name="pytest" errors="0" '
        f'failures="0" skipped="{skipped}" tests="{passed + skipped}" '
        f'time="9.999" timestamp="{timestamp}" hostname="volatile-host">'
        + "".join(cases)
        + "</testsuite></testsuites>"
    ).encode("utf-8")


def test_passing_engine_vector_is_policy_complete_and_canonical():
    junit = _junit("pytest-pass.xml", 0)
    replay_artifacts = _replays()
    global_report = _artifact("global-report-pass.json", "global.pass")
    results = evaluate_engine_correctness_evidence(
        pytest_junit=junit,
        replay_artifacts=replay_artifacts,
        global_report=global_report,
        repository_root=REPO_ROOT,
    )

    assert len(results) == 7
    assert all(item.status is CheckStatus.PASS for item in results)
    assert {item.id for item in results} == {
        "engine.deterministic_replay",
        "engine.global_no_exhaustiveness",
        "engine.offline_contracts",
        "engine.result_provenance",
        "engine.retired_surfaces_absent",
        "engine.scoped_coverage",
        "engine.total_ordering",
    }

    policy = load_policy(REPO_ROOT / "scorecard" / "policy-v1.json")
    assessment = evaluate(
        policy,
        results,
        profile=Profile.OFFLINE,
        subject=Subject("https://example.invalid/leitir", "1" * 40, "clean"),
        producer=Producer("leitir-score-engine", "3", "2" * 40),
        evidence=(junit, *replay_artifacts, global_report),
    )
    engine = next(
        item for item in assessment.dimensions if item.id == "engine_correctness"
    )
    assert engine.aggregate.score_bps == 10000
    assert engine.aggregate.included_weight == engine.aggregate.eligible_weight == 7


def test_passing_result_vector_is_identical_when_evidence_inputs_are_permuted():
    junit = _junit("pytest-pass.xml", 0)
    global_report = _artifact("global-report-pass.json", "global.pass")
    baseline, repeated, permuted = _replays()
    forward = evaluate_engine_correctness_evidence(
        pytest_junit=junit,
        replay_artifacts=(baseline, repeated, permuted),
        global_report=global_report,
        repository_root=REPO_ROOT,
    )
    reverse = evaluate_engine_correctness_evidence(
        pytest_junit=junit,
        replay_artifacts=(baseline, permuted, repeated),
        global_report=global_report,
        repository_root=REPO_ROOT,
    )
    assert forward == reverse
    assert hash(forward) == hash(reverse)


def test_failing_pytest_junit_is_a_known_failure():
    result = evaluate_pytest_junit(_junit("pytest-fail.xml", 1))
    assert result.status is CheckStatus.FAIL
    assert result.reason_code == "PYTEST_TEST_FAILURES"
    assert (result.numerator, result.denominator, result.score_bps) == (1, 2, 5000)


@pytest.mark.parametrize("process_exit", [0, 5])
def test_zero_test_junit_cannot_read_as_pass_even_if_exit_is_normalized(process_exit):
    result = evaluate_pytest_junit(_junit("pytest-zero.xml", process_exit))
    assert result.status is CheckStatus.FAIL
    assert result.score_bps == 0
    assert result.reason_code == "PYTEST_ZERO_TESTS_COLLECTED"


def test_malformed_junit_is_an_error_not_missing_or_green():
    result = evaluate_pytest_junit(_junit("pytest-malformed.xml", 3))
    assert result.status is CheckStatus.ERROR
    assert result.score_bps is None
    assert result.reason_code == "PYTEST_JUNIT_MALFORMED"


def test_all_skipped_junit_is_unresolved_not_green():
    result = evaluate_pytest_junit(_junit("pytest-all-skipped.xml", 0))
    assert result.status is CheckStatus.SKIPPED
    assert result.score_bps is None
    assert result.reason_code == "PYTEST_ALL_TESTS_SKIPPED"
    assert (result.numerator, result.denominator) == (0, 2)
    assert result.exclusions == (("PYTEST_SKIPPED", 2),)


def test_partially_skipped_junit_deducts_and_reports_skips():
    result = evaluate_pytest_junit(_junit("pytest-partial-skipped.xml", 0))
    assert result.status is CheckStatus.FAIL
    assert result.score_bps == 6667
    assert result.reason_code == "PYTEST_TESTS_SKIPPED"
    assert (result.numerator, result.denominator) == (2, 3)
    assert result.exclusions == (("PYTEST_SKIPPED", 1),)


def test_non_green_exit_with_skips_cannot_have_a_perfect_failure_score():
    result = evaluate_pytest_junit(_junit("pytest-partial-skipped.xml", 1))
    assert result.status is CheckStatus.FAIL
    assert result.score_bps == 6667
    assert result.score_bps < 10000
    assert result.reason_code == "PYTEST_NON_GREEN_EXIT"
    assert result.exclusions == (("PYTEST_SKIPPED", 1),)


@pytest.mark.parametrize(
    ("passed", "skipped", "process_exit", "status", "score_bps", "reason_code"),
    [
        (0, 10, 0, CheckStatus.SKIPPED, None, "PYTEST_ALL_TESTS_SKIPPED"),
        (8, 2, 0, CheckStatus.FAIL, 8000, "PYTEST_TESTS_SKIPPED"),
        (5, 5, 1, CheckStatus.FAIL, 5000, "PYTEST_NON_GREEN_EXIT"),
    ],
)
def test_collector_canonicalization_preserves_skip_arithmetic(
    tmp_path,
    monkeypatch,
    passed,
    skipped,
    process_exit,
    status,
    score_bps,
    reason_code,
):
    artifact = _collected_junit(
        tmp_path,
        monkeypatch,
        _ten_test_junit(
            passed=passed,
            skipped=skipped,
            timestamp="2026-08-03T00:00:00+00:00",
        ),
        process_exit=process_exit,
    )

    result = evaluate_pytest_junit(artifact)

    assert (result.status, result.score_bps, result.reason_code) == (
        status,
        score_bps,
        reason_code,
    )
    assert (result.numerator, result.denominator) == (passed, passed + skipped)
    assert artifact.normalization == "pytest-junit-volatile-v1"


def test_fresh_junit_collections_have_stable_identity_but_real_changes_do_not(
    tmp_path, monkeypatch
):
    first = _collected_junit(
        tmp_path,
        monkeypatch,
        _ten_test_junit(
            passed=8,
            skipped=2,
            timestamp="2026-08-03T00:00:00+00:00",
        ),
    )
    second_content = _ten_test_junit(
        passed=8,
        skipped=2,
        timestamp="2030-01-01T12:34:56+00:00",
    ).replace(b'time="9.999"', b'time="0.123"').replace(
        b'hostname="volatile-host"', b'hostname="another-host"'
    )
    second = _collected_junit(tmp_path, monkeypatch, second_content)
    changed = _collected_junit(
        tmp_path,
        monkeypatch,
        second_content.replace(b'name="test_pass_0"', b'name="test_changed_0"'),
    )

    assert first.raw_sha256 != second.raw_sha256
    assert first.sha256 == second.sha256
    assert first.content == second.content
    assert changed.sha256 != second.sha256

    policy = load_policy(REPO_ROOT / "scorecard" / "policy-v1.json")
    subject = Subject("https://example.invalid/leitir", "1" * 40, "clean")
    producer = Producer("leitir-score-engine", "8", "2" * 40)

    def assessed(artifact):
        return evaluate(
            policy,
            (evaluate_pytest_junit(artifact),),
            profile=Profile.OFFLINE,
            subject=subject,
            producer=producer,
            evidence=(artifact,),
        )

    assert assessed(first).digest() == assessed(second).digest()
    assert assessed(changed).digest() != assessed(second).digest()


def test_collector_canonicalization_keeps_lied_exit_zero_collection_failed(
    tmp_path, monkeypatch
):
    content = (FIXTURES / "pytest-zero.xml").read_bytes()
    artifact = _collected_junit(
        tmp_path, monkeypatch, content, process_exit=0
    )

    result = evaluate_pytest_junit(artifact)

    assert artifact.normalization == "pytest-junit-volatile-v1"
    assert result.status is CheckStatus.FAIL
    assert result.score_bps == 0
    assert result.reason_code == "PYTEST_ZERO_TESTS_COLLECTED"


def test_partial_scoped_coverage_is_a_known_failure():
    result = evaluate_scoped_coverage(
        _artifact("benchmark-run-partial.json", "benchmark.partial")
    )
    assert result.status is CheckStatus.FAIL
    assert result.reason_code == "DECLARED_UNIVERSE_PARTIAL"


def test_global_exhaustiveness_overclaim_is_a_known_failure():
    result = evaluate_global_no_exhaustiveness(
        _artifact("global-report-overclaim.json", "global.overclaim")
    )
    assert result.status is CheckStatus.FAIL
    assert result.reason_code == "GLOBAL_EXHAUSTIVENESS_OVERCLAIM"


def test_global_coverage_accepts_exclusion_breakdown():
    result = evaluate_global_no_exhaustiveness(
        _global_artifact({"decode_failed": 1})
    )

    assert result.status is CheckStatus.PASS
    assert result.reason_code == "INDETERMINATE_GLOBAL_PRESERVED"


@pytest.mark.parametrize("exclusions", [{"decode_failed": "1"}, {"decode_failed": -1}])
def test_global_coverage_rejects_malformed_exclusion_breakdown(exclusions):
    result = evaluate_global_no_exhaustiveness(_global_artifact(exclusions))

    assert result.status is CheckStatus.ERROR
    assert result.reason_code == "GLOBAL_COVERAGE_MALFORMED"


def test_global_coverage_rejects_malformed_resolution():
    artifact = _global_artifact({})
    raw = json.loads(artifact.content)
    raw["resolution"] = {"strategy": "moving_head", "as_of": 123}
    content = json.dumps(raw, sort_keys=True, separators=(",", ":")).encode()
    malformed = EvidenceArtifact(
        id=artifact.id,
        path=artifact.path,
        sha256=hashlib.sha256(content).hexdigest(),
        content=content,
    )
    result = evaluate_global_no_exhaustiveness(malformed)
    assert result.status is CheckStatus.ERROR
    assert result.reason_code == "GLOBAL_COVERAGE_MALFORMED"


def test_result_permalink_provenance_mismatch_is_a_known_failure():
    result = evaluate_result_provenance(
        _artifact(
            "benchmark-run-provenance-mismatch.json", "benchmark.provenance-mismatch"
        )
    )
    assert result.status is CheckStatus.FAIL
    assert result.reason_code == "RESULT_PROVENANCE_MISMATCH"


def test_nondeterministic_repeated_output_is_a_known_failure():
    baseline, repeated, _permuted = _replays()
    nondeterministic = _artifact(
        "benchmark-run-nondeterministic.json", "benchmark.nondeterministic"
    )
    result = evaluate_deterministic_replay(
        (baseline, repeated, nondeterministic)
    )
    assert result.status is CheckStatus.FAIL
    assert result.reason_code == "NONDETERMINISTIC_OUTPUT"


def test_adr001_p6_total_order_artifact_passes_without_importing_kernel():
    result = evaluate_total_ordering(_replays()[0])
    assert result.status is CheckStatus.PASS
    assert result.reason_code == "ADR001_TOTAL_ORDER_VALID"


def test_scorer_has_no_leitir_import_dependency():
    tree = ast.parse((REPO_ROOT / "tools" / "score_engine.py").read_text(encoding="utf-8"))
    imported = {
        alias.name
        for node in ast.walk(tree)
        if isinstance(node, ast.Import)
        for alias in node.names
    }
    imported.update(
        node.module or ""
        for node in ast.walk(tree)
        if isinstance(node, ast.ImportFrom)
    )
    assert not any(name == "leitir" or name.startswith("leitir.") for name in imported)


def test_retired_surface_absence_checks_top_level_import_surfaces(tmp_path):
    module_root = tmp_path / "src" / "leitir"
    module_root.mkdir(parents=True)
    assert evaluate_retired_surfaces_absent(tmp_path).status is CheckStatus.PASS
    (module_root / "openrouter.py").write_text("# retired\n", encoding="utf-8")
    result = evaluate_retired_surfaces_absent(tmp_path)
    assert result.status is CheckStatus.FAIL
    assert result.reason_code == "RETIRED_SURFACES_PRESENT"
    assert {entry["value"] for entry in result.evidence if entry["kind"] == "present_surface"} == {
        "src/leitir/openrouter.py"
    }


def test_stale_pycache_is_not_mistaken_for_a_top_level_module_surface(tmp_path):
    # Built in tmp_path rather than asserted against the real repository: the
    # scorer imports no Leitir code, so src/leitir/__pycache__ exists only if
    # some earlier test happened to import the kernel first. Reading the live
    # tree made this pass or fail on test order and on whether the checkout was
    # fresh. The cached module is a retired one, so a compiled artefact alone
    # must not count as a surviving import surface.
    module_root = tmp_path / "src" / "leitir"
    cache = module_root / "__pycache__"
    cache.mkdir(parents=True)
    (cache / "openrouter.cpython-314.pyc").write_bytes(b"\x00stale")
    (cache / "verification.cpython-314.pyc").write_bytes(b"\x00stale")

    result = evaluate_retired_surfaces_absent(tmp_path)

    assert result.status is CheckStatus.PASS
    assert not [
        entry for entry in result.evidence if entry["kind"] == "present_surface"
    ]


def test_pytest_collector_uses_fixed_adr001_argv_shell_false_and_sanitized_env(
    tmp_path, monkeypatch
):
    (tmp_path / "src").mkdir()
    monkeypatch.setenv("OPENROUTER_API_KEY", "must-not-leak")
    monkeypatch.setenv("GH_TOKEN", "must-not-leak")
    monkeypatch.setenv("SYSTEMROOT", str(tmp_path / "windows"))
    calls = []

    def fake_run(argv, **kwargs):
        calls.append((argv, kwargs))
        output = tmp_path / ".leitir-score" / "evidence" / "adr001-offline-junit.xml"
        output.write_bytes((FIXTURES / "pytest-pass.xml").read_bytes())
        return SimpleNamespace(returncode=0)

    monkeypatch.setattr(subprocess, "run", fake_run)
    artifact = collect_adr001_pytest_junit(tmp_path)

    assert artifact.command is not None
    assert artifact.command.argv == ADR001_OFFLINE_GATE_ARGV
    assert ADR001_OFFLINE_GATE_TESTS == ADR001_OFFLINE_GATE_ARGV[3:16]
    assert len(calls) == 1
    argv, kwargs = calls[0]
    assert isinstance(argv, tuple)
    assert kwargs["shell"] is False
    assert kwargs["check"] is False
    assert kwargs["timeout"] == 600
    assert kwargs["env"]["PYTHONHASHSEED"] == "0"
    assert kwargs["env"]["PYTEST_DISABLE_PLUGIN_AUTOLOAD"] == "1"
    assert kwargs["env"]["PYTHONPATH"] == str(tmp_path / "src")
    assert kwargs["env"]["HOME"] == str(tmp_path)
    assert kwargs["env"]["USERPROFILE"] == str(tmp_path)
    assert kwargs["env"]["SYSTEMROOT"] == str(tmp_path / "windows")
    assert "OPENROUTER_API_KEY" not in kwargs["env"]
    assert "GH_TOKEN" not in kwargs["env"]


def test_pytest_collector_timeout_returns_error_artifact_and_removes_partial(
    tmp_path, monkeypatch
):
    (tmp_path / "src").mkdir()
    output = tmp_path / ".leitir-score" / "evidence" / "adr001-offline-junit.xml"

    def fake_run(argv, **kwargs):
        output.write_bytes(b"<testsuites><partial")
        raise subprocess.TimeoutExpired(cmd=argv, timeout=kwargs["timeout"])

    monkeypatch.setattr(subprocess, "run", fake_run)
    artifact = collect_adr001_pytest_junit(tmp_path)

    assert artifact.content == b""
    assert artifact.command is not None
    assert artifact.command.process_exit == -1
    assert artifact.command.collector_reason_code == "COLLECTOR_TIMEOUT"
    assert not output.exists()
    result = evaluate_pytest_junit(artifact)
    assert result.status is CheckStatus.ERROR
    assert result.reason_code == "COLLECTOR_TIMEOUT"


def test_pytest_collector_unwritable_path_returns_error_without_running(
    tmp_path, monkeypatch
):
    (tmp_path / "src").mkdir()
    (tmp_path / ".leitir-score").write_text("blocks evidence directory\n")

    def unexpected_run(*_args, **_kwargs):
        raise AssertionError("pytest must not run when its evidence path is unusable")

    monkeypatch.setattr(subprocess, "run", unexpected_run)
    artifact = collect_adr001_pytest_junit(tmp_path)

    assert artifact.content == b""
    assert artifact.command is not None
    assert artifact.command.process_exit == -1
    assert artifact.command.collector_reason_code == "COLLECTOR_FILESYSTEM_ERROR"
    result = evaluate_pytest_junit(artifact)
    assert result.status is CheckStatus.ERROR
    assert result.reason_code == "COLLECTOR_FILESYSTEM_ERROR"


@pytest.mark.parametrize("executable", ["", None])
def test_pytest_collector_missing_interpreter_returns_execution_error(
    tmp_path, monkeypatch, executable
):
    (tmp_path / "src").mkdir()
    monkeypatch.setattr(sys, "executable", executable)
    monkeypatch.setattr(
        subprocess,
        "run",
        lambda *_args, **_kwargs: pytest.fail("collector must not execute pytest"),
    )

    artifact = collect_adr001_pytest_junit(tmp_path)

    assert artifact.content == b""
    assert artifact.command is not None
    assert artifact.command.process_exit == -1
    assert artifact.command.collector_reason_code == "COLLECTOR_EXECUTION_ERROR"


def test_shipped_policy_declares_every_s3_check_as_required_and_equal_weight():
    policy = load_policy(REPO_ROOT / "scorecard" / "policy-v1.json")
    engine_checks = [
        item for item in policy.checks if item.dimension == "engine_correctness"
    ]
    assert len(engine_checks) == 7
    assert all(item.weight == 1 for item in engine_checks)
    assert all(item.score_eligible for item in engine_checks)
    assert all(item.offline_mode.value == "required" for item in engine_checks)
    assert all(item.release_mode.value == "required" for item in engine_checks)
    assert all(item.criterion.op == "eq" for item in engine_checks)
    assert all(item.criterion.value == 10000 for item in engine_checks)


@pytest.mark.parametrize(
    "fixture_name",
    [
        "pytest-pass.xml",
        "pytest-fail.xml",
        "pytest-zero.xml",
        "pytest-malformed.xml",
        "pytest-all-skipped.xml",
        "pytest-partial-skipped.xml",
        "benchmark-run-pass.json",
        "benchmark-run-repeat.json",
        "benchmark-run-permuted.json",
        "benchmark-run-partial.json",
        "benchmark-run-provenance-mismatch.json",
        "benchmark-run-nondeterministic.json",
        "global-report-pass.json",
        "global-report-overclaim.json",
    ],
)
def test_engine_fixtures_are_committed_real_files(fixture_name):
    fixture = FIXTURES / fixture_name
    assert fixture.is_file()
    assert fixture.read_bytes()


def test_assessment_schema_needs_no_s3_special_case():
    schema = json.loads(
        (REPO_ROOT / "scorecard" / "assessment-v1.schema.json").read_text(
            encoding="utf-8"
        )
    )
    artifact = schema["$defs"]["evidenceArtifact"]
    assert set(artifact["required"]) == {"id", "path", "sha256", "command", "sources"}
    assert artifact["additionalProperties"] is False


def test_result_type_remains_the_s1_check_contract():
    result = evaluate_total_ordering(_replays()[0])
    assert isinstance(result, CheckResult)
