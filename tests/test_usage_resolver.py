"""Tests for the purely static Python usage resolver (issue #257).

``leitir.usage.resolver.resolve_consumer`` never imports, execs, or
evaluates consumer source -- it only calls ``ast.parse`` over the file text.
Every case below feeds it small, local, stdlib-only fixture trees under
``tests/fixtures/usage/resolver/`` (this subdirectory has no
``manifest.json`` of its own, so ``tests/test_usage_fixtures.py``'s corpus
discovery -- which only looks at immediate children of
``tests/fixtures/usage/`` -- does not pick it up as a case; these fixtures
exist purely for this module).
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from leitir.usage import UnresolvedState
from leitir.usage.resolver import (
    MAX_RESOLVER_COVERAGE_RECORDS,
    RESOLVER_RESULT_SCHEMA_VERSION,
    ResolverResult,
    resolve_consumer,
)

FIXTURES_ROOT = Path(__file__).resolve().parent / "fixtures" / "usage" / "resolver"

_WIDGETLIB_ROOTS = {"widgetlib": "widgetlib"}


def _consumer(case: str) -> Path:
    return FIXTURES_ROOT / case / "consumer"


def _single_record_state(result: ResolverResult, file: str) -> UnresolvedState:
    matching = [record for record in result.coverage.records if record.file == file]
    assert len(matching) == 1, (file, result.coverage.records)
    return matching[0].state


# ---------------------------------------------------------------------------
# AC-1: imports, aliases, calls, shadowing resolve deterministically without
# executing consumer code.
# ---------------------------------------------------------------------------


def test_plain_import_resolves_to_the_tracked_distribution() -> None:
    result = resolve_consumer(consumer_root=_consumer("plain_import"), import_roots=_WIDGETLIB_ROOTS)

    assert result.schema_version == RESOLVER_RESULT_SCHEMA_VERSION
    assert len(result.references) == 1
    reference = result.references[0]
    assert reference.distribution == "widgetlib"
    assert reference.span.file == "app.py"
    assert _single_record_state(result, "app.py") == UnresolvedState.RESOLVED
    assert result.coverage.capped is False
    assert result.coverage.exclusions == ()


def test_aliased_import_resolves_to_the_same_distribution() -> None:
    result = resolve_consumer(consumer_root=_consumer("alias_chain"), import_roots=_WIDGETLIB_ROOTS)

    assert len(result.references) == 1
    assert result.references[0].distribution == "widgetlib"
    assert _single_record_state(result, "app.py") == UnresolvedState.RESOLVED


def test_from_import_with_alias_resolves() -> None:
    result = resolve_consumer(consumer_root=_consumer("from_import_alias"), import_roots=_WIDGETLIB_ROOTS)

    assert len(result.references) == 1
    assert result.references[0].distribution == "widgetlib"
    assert _single_record_state(result, "app.py") == UnresolvedState.RESOLVED


def test_calls_inside_functions_and_methods_attribute_back_to_the_import() -> None:
    result = resolve_consumer(consumer_root=_consumer("call_attribution"), import_roots=_WIDGETLIB_ROOTS)

    assert len(result.references) == 2
    assert {reference.distribution for reference in result.references} == {"widgetlib"}
    assert _single_record_state(result, "app.py") == UnresolvedState.RESOLVED


def test_module_level_function_shadow_suppresses_attribution_after_the_rebind() -> None:
    result = resolve_consumer(consumer_root=_consumer("shadow_function"), import_roots=_WIDGETLIB_ROOTS)

    # The usage before the shadowing `def widgetlib():` still resolves; the
    # call after it does not (and is not silently reported as resolved).
    assert len(result.references) == 1
    assert result.references[0].distribution == "widgetlib"
    assert _single_record_state(result, "app.py") == UnresolvedState.RE_EXPORT


def test_function_parameter_shadow_is_local_and_does_not_leak() -> None:
    result = resolve_consumer(consumer_root=_consumer("shadow_parameter"), import_roots=_WIDGETLIB_ROOTS)

    # The parameter shadows widgetlib only inside handler(); the module-level
    # call after the def still resolves cleanly.
    assert len(result.references) == 1
    assert result.references[0].distribution == "widgetlib"
    assert _single_record_state(result, "app.py") == UnresolvedState.RESOLVED


def test_for_loop_target_shadow_suppresses_attribution() -> None:
    result = resolve_consumer(consumer_root=_consumer("shadow_for_loop"), import_roots=_WIDGETLIB_ROOTS)

    assert result.references == ()
    assert _single_record_state(result, "app.py") == UnresolvedState.RE_EXPORT


def test_with_as_target_shadow_suppresses_attribution() -> None:
    result = resolve_consumer(consumer_root=_consumer("shadow_with_as"), import_roots=_WIDGETLIB_ROOTS)

    assert result.references == ()
    assert _single_record_state(result, "app.py") == UnresolvedState.RE_EXPORT


def test_except_as_target_shadow_suppresses_attribution() -> None:
    result = resolve_consumer(consumer_root=_consumer("shadow_except_as"), import_roots=_WIDGETLIB_ROOTS)

    assert result.references == ()
    assert _single_record_state(result, "app.py") == UnresolvedState.RE_EXPORT


def test_comprehension_target_shadow_is_scoped_and_does_not_leak() -> None:
    result = resolve_consumer(consumer_root=_consumer("shadow_comprehension"), import_roots=_WIDGETLIB_ROOTS)

    # Comprehensions get their own scope in Python 3: the loop variable
    # named `widgetlib` inside the comprehension must not rebind the
    # module-level import, so both surrounding calls resolve.
    assert len(result.references) == 2
    assert {reference.distribution for reference in result.references} == {"widgetlib"}
    assert _single_record_state(result, "app.py") == UnresolvedState.RESOLVED


def test_global_declared_rebind_inside_a_function_suppresses_attribution() -> None:
    result = resolve_consumer(consumer_root=_consumer("shadow_global"), import_roots=_WIDGETLIB_ROOTS)

    assert result.references == ()
    assert _single_record_state(result, "app.py") == UnresolvedState.RE_EXPORT


def test_would_raise_if_executed_module_is_never_executed() -> None:
    """The module body contains a top-level `raise`; if the resolver ever executed it, this test would error out."""

    result = resolve_consumer(consumer_root=_consumer("would_raise_if_executed"), import_roots=_WIDGETLIB_ROOTS)

    assert len(result.references) == 1
    assert result.references[0].distribution == "widgetlib"
    assert _single_record_state(result, "app.py") == UnresolvedState.RESOLVED


def test_relative_import_binds_the_correct_name_without_crashing_or_guessing() -> None:
    result = resolve_consumer(consumer_root=_consumer("relative_import"), import_roots=_WIDGETLIB_ROOTS)

    # `from . import helper` is handled without raising, and since the
    # resolver cannot verify what it points to it must not report a guess:
    # no reference is emitted for `helper.run()`.
    assert result.references == ()
    assert _single_record_state(result, "pkg/mod.py") == UnresolvedState.RESOLVED
    assert _single_record_state(result, "pkg/helper.py") == UnresolvedState.RESOLVED


# ---------------------------------------------------------------------------
# SP-1: dynamic import, star import, ambiguous binding, and re-export stay
# typed-unresolved -- never executed, never guessed as resolved.
# ---------------------------------------------------------------------------


def test_dynamic_import_via_builtin_is_typed_unresolved() -> None:
    result = resolve_consumer(consumer_root=_consumer("dynamic_import_builtin"), import_roots=_WIDGETLIB_ROOTS)

    assert result.references == ()
    assert _single_record_state(result, "app.py") == UnresolvedState.DYNAMIC_IMPORT


def test_dynamic_import_via_importlib_is_typed_unresolved() -> None:
    result = resolve_consumer(consumer_root=_consumer("dynamic_import_importlib"), import_roots=_WIDGETLIB_ROOTS)

    assert result.references == ()
    assert _single_record_state(result, "app.py") == UnresolvedState.DYNAMIC_IMPORT


def test_star_import_is_typed_unresolved_and_suppresses_all_references() -> None:
    result = resolve_consumer(consumer_root=_consumer("star_import"), import_roots=_WIDGETLIB_ROOTS)

    assert result.references == ()
    assert _single_record_state(result, "app.py") == UnresolvedState.STAR_IMPORT


def test_ambiguous_conditional_import_is_typed_unresolved() -> None:
    import_roots = {"widgetlib": "widgetlib", "fastwidget": "widgetlib-fast"}

    result = resolve_consumer(consumer_root=_consumer("ambiguous_conditional_import"), import_roots=import_roots)

    assert result.references == ()
    assert _single_record_state(result, "app.py") == UnresolvedState.AMBIGUOUS_BINDING


def test_try_except_importerror_fallback_with_different_distributions_is_ambiguous() -> None:
    import_roots = {"widgetlib": "widgetlib", "cwidgetlib": "widgetlib-c-ext"}

    result = resolve_consumer(consumer_root=_consumer("try_except_importerror_fallback"), import_roots=import_roots)

    assert result.references == ()
    assert _single_record_state(result, "app.py") == UnresolvedState.AMBIGUOUS_BINDING


def test_reexport_through_a_local_proxy_module_is_typed_unresolved() -> None:
    result = resolve_consumer(consumer_root=_consumer("reexport_via_local_proxy"), import_roots=_WIDGETLIB_ROOTS)

    assert result.references == ()
    assert _single_record_state(result, "app.py") == UnresolvedState.RE_EXPORT
    # The proxy module itself is examined too: it directly imports the
    # tracked distribution, so it resolves cleanly on its own.
    assert _single_record_state(result, "pkgproxy/__init__.py") == UnresolvedState.RESOLVED


def test_reexport_through_two_local_hops_is_typed_unresolved_not_resolved() -> None:
    # Regression for a coverage-honesty bug: app.py -> proxy_of_proxy.py ->
    # actual_proxy.py -> widgetlib. Only the FIRST hop (actual_proxy.py's
    # direct `import widgetlib as w`) is a tracked provider import;
    # proxy_of_proxy.py re-exports it via another *local* module (a
    # two-hop chain), which the resolver's shallow, one-hop cross-file scan
    # cannot follow. No reference may be guessed for `w.use()` in app.py --
    # but app.py's coverage record must NOT be misreported as fully
    # RESOLVED either: it must explicitly carry RE_EXPORT.
    result = resolve_consumer(consumer_root=_consumer("reexport_through_two_local_hops"), import_roots=_WIDGETLIB_ROOTS)

    assert result.references == ()
    assert _single_record_state(result, "app.py") == UnresolvedState.RE_EXPORT


def test_syntax_error_is_unsupported_syntax_and_does_not_raise() -> None:
    # Named app.txt (not app.py) so ruff's default *.py glob does not try to
    # lint deliberately-invalid syntax; passed explicitly via `files=`.
    result = resolve_consumer(consumer_root=_consumer("syntax_error"), import_roots=_WIDGETLIB_ROOTS, files=["app.txt"])

    assert result.references == ()
    assert _single_record_state(result, "app.txt") == UnresolvedState.UNSUPPORTED_SYNTAX


def test_cap_exceeded_continues_the_run_and_types_the_state() -> None:
    result = resolve_consumer(
        consumer_root=_consumer("plain_import"), import_roots=_WIDGETLIB_ROOTS, max_ast_nodes_per_file=1
    )

    assert result.references == ()
    assert _single_record_state(result, "app.py") == UnresolvedState.CAP_EXCEEDED
    assert result.coverage.capped is True


def test_file_count_cap_excludes_files_and_continues() -> None:
    result = resolve_consumer(
        consumer_root=_consumer("call_attribution"),
        import_roots=_WIDGETLIB_ROOTS,
        files=["app.py"],
        max_files=0,
    )

    assert result.coverage.records == ()
    assert result.coverage.exclusions == ("app.py",)
    assert result.coverage.capped is True


# ---------------------------------------------------------------------------
# Determinism: output must be stable across runs and independent of input
# ordering (never relying on set/dict iteration order for output ordering).
# ---------------------------------------------------------------------------


def test_output_is_byte_stable_across_repeated_runs() -> None:
    first = resolve_consumer(consumer_root=_consumer("call_attribution"), import_roots=_WIDGETLIB_ROOTS)
    second = resolve_consumer(consumer_root=_consumer("call_attribution"), import_roots=_WIDGETLIB_ROOTS)

    assert first.references == second.references
    assert first.coverage == second.coverage


def test_output_is_independent_of_input_file_and_mapping_order() -> None:
    consumer_root = _consumer("call_attribution")
    forward = resolve_consumer(
        consumer_root=consumer_root, import_roots={"widgetlib": "widgetlib"}, files=["app.py"]
    )
    reordered_roots = dict(reversed(list({"other": "other-dist", "widgetlib": "widgetlib"}.items())))
    backward = resolve_consumer(consumer_root=consumer_root, import_roots=reordered_roots, files=["app.py"])

    assert forward.references == backward.references
    assert forward.coverage.records == backward.coverage.records


def test_resolver_result_and_coverage_summary_round_trip_through_canonical_json() -> None:
    result = resolve_consumer(consumer_root=_consumer("plain_import"), import_roots=_WIDGETLIB_ROOTS)

    payload = {
        "schema_version": result.schema_version,
        "references": [reference.to_dict() for reference in result.references],
        "coverage": result.coverage.to_dict(),
    }
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    reencoded = json.dumps(json.loads(encoded), sort_keys=True, separators=(",", ":")).encode("utf-8")
    assert encoded == reencoded


def test_resolver_result_rejects_a_foreign_schema_version() -> None:
    result = resolve_consumer(consumer_root=_consumer("plain_import"), import_roots=_WIDGETLIB_ROOTS)

    with pytest.raises(ValueError, match="schema_version"):
        ResolverResult(schema_version="not-the-real-version", references=result.references, coverage=result.coverage)


def test_resolve_consumer_rejects_a_missing_consumer_root(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="consumer_root"):
        resolve_consumer(consumer_root=tmp_path / "does-not-exist", import_roots=_WIDGETLIB_ROOTS)


def test_declared_coverage_cap_is_reported_and_within_bounds() -> None:
    result = resolve_consumer(consumer_root=_consumer("plain_import"), import_roots=_WIDGETLIB_ROOTS)

    assert result.coverage.cap == MAX_RESOLVER_COVERAGE_RECORDS
    assert len(result.coverage.records) <= result.coverage.cap
