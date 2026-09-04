"""Calibration harness contracts: the tool that hunts blind spots must not have obvious ones itself."""

from __future__ import annotations

import ast
import json
import sys
from pathlib import Path

import pytest

TOOLS = Path(__file__).resolve().parents[1] / "tools"
if str(TOOLS) not in sys.path:
    sys.path.insert(0, str(TOOLS))

from calibration.ledger import Finding, Ledger  # noqa: E402

from calibration import fuzz, mutation, stats  # noqa: E402

REPO_ROOT = Path(__file__).resolve().parents[1]


# -- statistics ---------------------------------------------------------------


def test_wilson_interval_brackets_the_point_estimate_and_narrows_with_trials():
    lo_small, hi_small = stats.wilson_interval(8, 10)
    lo_large, hi_large = stats.wilson_interval(800, 1000)
    assert lo_small < 0.8 < hi_small
    assert lo_large < 0.8 < hi_large
    assert (hi_large - lo_large) < (hi_small - lo_small)
    assert stats.wilson_interval(0, 0) == (0.0, 1.0)


def test_rule_of_three_and_good_turing_bound_the_unseen():
    assert stats.rule_of_three(300) == pytest.approx(0.01)
    assert stats.rule_of_three(0) == 1.0
    # Two singleton classes out of 400 inputs: ~0.5% chance the next input is a new class.
    assert stats.good_turing_unseen_mass([1, 1, 7], 400) == pytest.approx(0.005)
    assert stats.good_turing_unseen_mass([], 400) == 0.0


def test_robust_regression_ignores_noise_but_catches_real_slowdowns():
    baseline = [1.00, 1.02, 0.98, 1.01, 0.99, 1.00, 1.03]
    assert stats.robust_regression(baseline, [1.05, 1.04, 1.06, 1.05, 1.04, 1.05, 1.06])[0] is False
    regressed, ratio = stats.robust_regression(baseline, [1.6, 1.7, 1.5, 1.6, 1.65, 1.6, 1.7])
    assert regressed is True
    assert ratio > 1.5


# -- ledger -------------------------------------------------------------------


def _finding(identity: str, severity: str = "medium", probe: str = "fuzz") -> Finding:
    return Finding(probe, "cat", severity, f"title {identity}", "loc", {"identity": identity}, "repro")


def test_finding_identity_is_stable_across_title_changes():
    assert _finding("a").id == Finding("fuzz", "cat", "high", "different title", "loc", {"identity": "a"}).id
    assert _finding("a").id != _finding("b").id


def test_ledger_transitions_open_fixed_regressed_and_dispositions(tmp_path):
    ledger = Ledger.empty()
    ledger.record_run(run_id="r1", started_at="t", git_sha="s", executed_probes=["fuzz"], observed=[_finding("a"), _finding("b", "high")], metrics={})
    assert ledger.open_by_severity()["medium"] == 1
    assert ledger.blind_spot_index() == 3 + 8
    ledger.record_run(run_id="r2", started_at="t", git_sha="s", executed_probes=["fuzz"], observed=[_finding("a")], metrics={})
    assert ledger.findings[_finding("b").id]["status"] == "fixed"
    # A probe that did not run cannot mark its findings fixed.
    ledger.record_run(run_id="r3", started_at="t", git_sha="s", executed_probes=["static"], observed=[], metrics={})
    assert ledger.findings[_finding("a").id]["status"] == "open"
    summary = ledger.record_run(run_id="r4", started_at="t", git_sha="s", executed_probes=["fuzz"], observed=[_finding("a"), _finding("b", "high")], metrics={})
    assert summary["regressed"] == [_finding("b").id]
    ledger.set_disposition(_finding("a").id, "equivalent", "same behaviour")
    assert ledger.blind_spot_index() == 8
    path = tmp_path / "ledger.json"
    ledger.save(path)
    reloaded = Ledger.load(path)
    assert reloaded.blind_spot_index() == 8
    assert json.loads(path.read_text(encoding="utf-8"))["schema_version"] == "leitir-calibration-ledger-v1"


def test_sampled_probe_cannot_mark_untested_findings_fixed():
    ledger = Ledger.empty()
    ledger.record_run(run_id="r1", started_at="t", git_sha="s", executed_probes=["mutation"], observed=[_finding("m1", probe="mutation"), _finding("m2", probe="mutation")], metrics={})
    # A later sample re-tested only m1 and no longer observes it; m2 was simply not sampled.
    summary = ledger.record_run(run_id="r2", started_at="t", git_sha="s", executed_probes=["mutation"], observed=[], metrics={}, retested={"mutation": {"m1"}})
    assert summary["fixed"] == [_finding("m1", probe="mutation").id]
    assert ledger.findings[_finding("m2", probe="mutation").id]["status"] == "open"


def test_fuzz_check_input_reproduces_one_historical_failure():
    def run(value, _tmp):
        if value == 5:
            raise KeyError("boom")
        return value

    target = fuzz.Target("toy", lambda rng: rng.randint(0, 9), run, lambda: ())
    first = fuzz.fuzz_target(target, seed=3, count=200)
    assert first.failures
    failure = first.failures[0]
    again = fuzz.check_input(target, failure.seed, failure.index)
    assert [item.signature for item in again] == [failure.signature]


def test_ledger_rejects_unknown_severity():
    with pytest.raises(ValueError):
        Finding("p", "c", "urgent", "t", "l")


# -- mutation engine ----------------------------------------------------------


def test_every_enumerated_mutant_compiles_and_changes_exactly_its_span(tmp_path):
    source = (
        "from __future__ import annotations\n\n"
        "LIMIT = 3\n\n"
        "def check(value: int, flag: bool = True) -> int:\n"
        '    """Doc with True and 5 inside must stay untouched."""\n'
        "    if value < LIMIT and flag:\n"
        "        raise ValueError('too small')\n"
        "    for item in range(value):\n"
        "        if item == 2:\n"
        "            break\n"
        "    return value + 1  # pragma: no mutate\n"
    )
    src = tmp_path / "src" / "leitir"
    src.mkdir(parents=True)
    target = src / "sample.py"
    target.write_text(source, encoding="utf-8")
    mutants = mutation.enumerate_mutants(tmp_path, target)
    operators = {mutant.operator for mutant in mutants}
    assert {"cmp-swap", "boolop-swap", "raise-drop", "break-continue", "int-shift"} <= operators
    assert all(mutant.lineno != 12 for mutant in mutants), "pragma: no mutate must be honoured"
    assert all(mutant.lineno != 6 for mutant in mutants), "docstrings are never mutated"
    assert all("int" not in mutant.original and "bool" not in mutant.original for mutant in mutants), "annotations are never mutated"
    for mutant in mutants:
        mutated = mutation.apply_mutant(source, mutant)
        compile(mutated, "sample", "exec")
        assert mutated != source
        assert mutated.count("\n") == source.count("\n") or mutant.operator in {"raise-drop", "return-none", "if-negate", "cmp-swap", "boolop-swap"}
    assert len({mutant.id for mutant in mutants}) == len(mutants)


def test_apply_mutant_fails_closed_when_source_drifted(tmp_path):
    src = tmp_path / "src" / "leitir"
    src.mkdir(parents=True)
    target = src / "m.py"
    target.write_text("def f(a):\n    return a == 1\n", encoding="utf-8")
    mutant = mutation.enumerate_mutants(tmp_path, target)[0]
    with pytest.raises(ValueError):
        mutation.apply_mutant("def f(a):\n    return a != 1\n", mutant)


def test_run_mutant_restores_source_bytes_even_when_tests_pass(tmp_path):
    (tmp_path / "src" / "leitir").mkdir(parents=True)
    (tmp_path / "src" / "leitir" / "__init__.py").write_text("", encoding="utf-8")
    (tmp_path / "tests").mkdir()
    target = tmp_path / "src" / "leitir" / "m.py"
    original = "def is_big(value):\n    return value > 10\n"
    target.write_bytes(original.encode("utf-8"))
    (tmp_path / "tests" / "test_m.py").write_text("from leitir.m import is_big\n\ndef test_big():\n    assert is_big(11)\n", encoding="utf-8")
    mutant = next(m for m in mutation.enumerate_mutants(tmp_path, target) if m.operator == "cmp-swap")
    outcome = mutation.run_mutant(tmp_path, mutant, ("tests/test_m.py",), "static", timeout=120)
    assert target.read_bytes() == original.encode("utf-8")
    # ``>`` -> ``>=`` survives a test that only checks 11; that is exactly the blind spot the loop reports.
    assert outcome.outcome in {mutation.SURVIVED, mutation.KILLED}
    assert outcome.outcome == mutation.SURVIVED


def test_static_selector_maps_modules_to_importing_tests():
    mapping = mutation.build_static_map(REPO_ROOT)
    assert "tests/test_spec.py" in mapping["leitir.spec"]
    assert "tests/test_treehash.py" in mapping["leitir.treehash"]


def test_coverage_contexts_parse_to_line_test_map(tmp_path):
    payload = {"files": {"src/leitir/spec.py": {"contexts": {"10": ["tests/test_spec.py::test_a|run", ""], "11": ["tests/test_spec.py::test_b|setup"]}}}}
    path = tmp_path / "c.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    contexts = mutation.load_coverage_contexts(path)
    assert contexts["src/leitir/spec.py"][10] == ("tests/test_spec.py::test_a",)
    selector = mutation.TestSelector(tmp_path, contexts=contexts)
    mutant = mutation.Mutant("src/leitir/spec.py", "leitir.spec", "cmp-swap", 10, 10, 0, 1, "a", "b")
    assert selector.select(mutant) == (("tests/test_spec.py::test_a",), "contexts")
    assert selector.select(mutation.Mutant("src/leitir/spec.py", "leitir.spec", "cmp-swap", 99, 99, 0, 1, "a", "b")) == ((), "none")


def test_severity_weights_integrity_raise_drops_highest():
    raise_drop = mutation.Mutant("src/leitir/treehash.py", "leitir.treehash", "raise-drop", 1, 1, 0, 1, "raise X", "pass")
    assert mutation.severity_for(raise_drop) == "high"
    other = mutation.Mutant("src/leitir/examples.py", "leitir.examples", "cmp-swap", 1, 1, 0, 1, "a", "b")
    assert mutation.severity_for(other) == "low"


# -- fuzz ---------------------------------------------------------------------


def test_fuzz_inputs_are_reproducible_from_target_seed_index():
    for name, target in fuzz.TARGETS.items():
        assert fuzz.canon(fuzz.input_for(target, 7, 3)) == fuzz.canon(fuzz.input_for(target, 7, 3)), name
        assert fuzz.canon(fuzz.input_for(target, 7, 3)) != fuzz.canon(fuzz.input_for(target, 8, 3)), name


def test_fuzz_runner_classifies_unexpected_exceptions_and_property_violations():
    def generate(rng):
        return rng.randint(0, 9)

    def run(value, _tmp):
        if value == 3:
            raise KeyError("boom")
        if value == 4:
            raise ValueError("by design")
        return value

    def prop(value, output, _tmp):
        return "odd output" if output % 2 else None

    target = fuzz.Target("toy", generate, run, lambda: (ValueError,), (prop,))
    result = fuzz.fuzz_target(target, seed=1, count=60)
    kinds = {failure.kind for failure in result.failures}
    assert "crash" in kinds and "property" in kinds
    assert result.by_design > 0
    assert all(failure.signature.startswith("toy:") for failure in result.failures)


@pytest.mark.skipif(not hasattr(__import__("signal"), "setitimer"), reason="hard deadline needs POSIX interval timers")
def test_fuzz_hard_deadline_turns_a_hang_into_a_finding():
    fuzz_hang = fuzz.HANG_SECONDS
    fuzz.HANG_SECONDS = 0.2
    try:
        target = fuzz.Target("hang", lambda rng: 0, lambda value, tmp: __import__("time").sleep(5), lambda: ())
        result = fuzz.fuzz_target(target, seed=1, count=1)
    finally:
        fuzz.HANG_SECONDS = fuzz_hang
    assert [failure.kind for failure in result.failures] == ["slow"]


def test_stable_digest_ignores_wall_clock_fields():
    assert fuzz.stable_digest({"resolution": {"as_of": "now", "x": 1}}) == fuzz.stable_digest({"resolution": {"as_of": "later", "x": 1}})
    assert fuzz.stable_digest({"x": 1}) != fuzz.stable_digest({"x": 2})


# -- issues ---------------------------------------------------------------------


def test_file_issues_is_idempotent_and_capped_and_writes_back_numbers():
    from calibration import issues

    ledger = Ledger.empty()
    ledger.record_run(run_id="r1", started_at="t", git_sha="s", executed_probes=["fuzz"], observed=[_finding("a", "high"), _finding("b", "high"), _finding("c", "medium")], metrics={})
    calls: list[list[str]] = []

    def fake_gh(command):
        calls.append(list(command))
        if command[1:3] == ["issue", "list"]:
            return (0, '[{"number": 41}]' if "calibration-id:" + _finding("a", "high").id in " ".join(command) else "[]")
        if command[1:3] == ["issue", "create"]:
            return (0, "https://github.com/o/r/issues/42\n")
        return (0, "")

    records = issues.file_issues(ledger, run_id="r1", min_severity="high", limit=5, runner=fake_gh)
    actions = {record["id"]: record["action"] for record in records}
    assert actions[_finding("a", "high").id] == "linked"
    assert actions[_finding("b", "high").id] == "created"
    assert _finding("c", "medium").id not in actions, "medium is below the threshold"
    assert ledger.findings[_finding("a", "high").id]["issue"] == 41
    assert ledger.findings[_finding("b", "high").id]["issue"] == 42
    create = next(call for call in calls if call[1:3] == ["issue", "create"])
    assert "ready-for-agent" in create[create.index("--label") + 1]
    assert issues.marker(_finding("b", "high").id) in create[create.index("--body") + 1]
    # Second pass files nothing new.
    again = issues.file_issues(ledger, run_id="r2", min_severity="high", limit=5, runner=fake_gh)
    assert again == []
    dry = issues.file_issues(Ledger.empty(), run_id="r", dry_run=True, runner=fake_gh)
    assert dry == []


def test_comment_fixed_posts_once_and_never_closes():
    from calibration import issues

    ledger = Ledger.empty()
    ledger.record_run(run_id="r1", started_at="t", git_sha="s", executed_probes=["fuzz"], observed=[_finding("a", "high")], metrics={})
    ledger.findings[_finding("a", "high").id]["issue"] = 7
    ledger.record_run(run_id="r2", started_at="t", git_sha="s", executed_probes=["fuzz"], observed=[], metrics={})
    calls: list[list[str]] = []
    runner = lambda command: (calls.append(list(command)), (0, ""))[1]  # noqa: E731
    assert issues.comment_fixed(ledger, run_id="r2", runner=runner) == 1
    assert issues.comment_fixed(ledger, run_id="r3", runner=runner) == 0
    assert all(call[1:3] != ["issue", "close"] for call in calls)


# -- tool hygiene --------------------------------------------------------------


def test_calibration_tool_imports_no_leitir_code_at_module_level():
    for path in sorted((TOOLS / "calibration").rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in tree.body:
            if isinstance(node, ast.ImportFrom) and (node.module or "").startswith("leitir"):
                raise AssertionError(f"{path.name} imports leitir at module level")
            if isinstance(node, ast.Import) and any(alias.name.startswith("leitir") for alias in node.names):
                raise AssertionError(f"{path.name} imports leitir at module level")
