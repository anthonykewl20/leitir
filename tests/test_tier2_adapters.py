from __future__ import annotations

import json
import os
import subprocess
import sys

import pytest

from leitir.adapters import MatchMethod
from leitir.adapters._tier2 import (
    CAdapter,
    CppAdapter,
    JavaAdapter,
    JavaScriptAdapter,
    Tier2RegexAdapter,
    TypeScriptAdapter,
)
from leitir.adapters.registry import build_adapters
from leitir.engine import score_content
from leitir.search import Predicate, PredicateKind


def _predicate(kind: PredicateKind, value: str) -> tuple[Predicate, ...]:
    return (Predicate(kind, value),)


@pytest.mark.parametrize(
    ("adapter", "source", "import_value"),
    (
        (
            JavaScriptAdapter(),
            'import { helper } from "./dep";\nexport function build() {}\nbuild();\nconst text = "function ghost() {}";\n// function ghost() {}\n',
            "helper",
        ),
        (
            TypeScriptAdapter(),
            'import { helper } from "./dep";\nexport function build(): void {}\nbuild();\nconst text: string = "function ghost() {}";\n// function ghost() {}\n',
            "helper",
        ),
        (
            JavaAdapter(),
            'import java.util.List;\nclass Service {\n  int build() { return 1; }\n  void run() { build(); }\n  String text = "int ghost() {";\n  // int ghost() {\n}\n',
            "java.util",
        ),
        (
            CAdapter(),
            '#include <stdio.h>\nint build(void) { return 1; }\nint main(void) { return build(); }\nconst char *text = "int ghost(void) {";\n// int ghost(void) {\n',
            "stdio",
        ),
        (
            CppAdapter(),
            '#include <vector>\nint build() { return 1; }\nint main() { return build(); }\nconst char *text = "int ghost() {";\n// int ghost() {\n',
            "vector",
        ),
    ),
    ids=("javascript", "typescript", "java", "c", "cpp"),
)
def test_tier2_predicates_are_masked_heuristic_and_deterministic(
    adapter: Tier2RegexAdapter,
    source: str,
    import_value: str,
) -> None:
    results = {
        kind: adapter.find_matches(source, _predicate(kind, value))
        for kind, value in (
            (PredicateKind.SYMBOL_DEFINITION, "build"),
            (PredicateKind.CALL, "build"),
            (PredicateKind.IMPORT, import_value),
            (PredicateKind.SYMBOL_REFERENCE, "build"),
        )
    }

    assert all(results.values())
    assert all(
        span.method is MatchMethod.HEURISTIC
        for spans in results.values()
        for span in spans
    )
    assert all(
        tuple(span.start_line for span in spans)
        == tuple(sorted(span.start_line for span in spans))
        for spans in results.values()
    )
    assert adapter.find_matches(
        source, _predicate(PredicateKind.SYMBOL_DEFINITION, "ghost")
    ) == ()
    assert adapter.find_matches_ex(
        source, _predicate(PredicateKind.SYMBOL_DEFINITION, "build")
    ).parser_unavailable is False


def test_tier2_default_registry_and_extension_routing() -> None:
    adapters = build_adapters()

    assert tuple(adapter.language for adapter in adapters) == (
        "python",
        "rust",
        "go",
        "javascript",
        "typescript",
        "java",
        "c",
        "cpp",
    )
    assert next(adapter.language for adapter in adapters if adapter.eligible("src/a.c")) == "c"
    assert next(adapter.language for adapter in adapters if adapter.eligible("src/a.cpp")) == "cpp"


def test_javascript_dollar_identifier_definition_call_and_reference() -> None:
    source = "function $build() {}\n$build();\n"
    adapter = JavaScriptAdapter()

    assert adapter.find_matches(
        source, _predicate(PredicateKind.SYMBOL_DEFINITION, "$build")
    )
    assert adapter.find_matches(source, _predicate(PredicateKind.CALL, "$build"))
    assert adapter.find_matches(
        source, _predicate(PredicateKind.SYMBOL_REFERENCE, "$build")
    )


@pytest.mark.parametrize(
    ("adapter", "definition"),
    (
        (JavaScriptAdapter(), "function build() {}"),
        (TypeScriptAdapter(), "function build(): void {}"),
        (JavaAdapter(), "int build() { return 1; }"),
        (CAdapter(), "int build(void) { return 1; }"),
        (CppAdapter(), "int build() { return 1; }"),
    ),
    ids=("javascript", "typescript", "java", "c", "cpp"),
)
def test_tier2_whole_file_matches_required_evidence_on_different_lines(
    adapter: Tier2RegexAdapter, definition: str
) -> None:
    content = "\n".join((definition, *("" for _ in range(48)), "run();"))
    predicates = (
        Predicate(PredicateKind.SYMBOL_DEFINITION, "build"),
        Predicate(PredicateKind.CALL, "run"),
    )

    assert adapter.find_matches(content, predicates) == ()
    matches = adapter.find_matches(content, predicates, whole_file=True)
    assert tuple(
        (match.start_line, match.end_line, match.matched_kinds) for match in matches
    ) == (
        (1, 1, (PredicateKind.SYMBOL_DEFINITION,)),
        (50, 50, (PredicateKind.CALL,)),
    )


@pytest.mark.parametrize(
    "adapter",
    (
        JavaScriptAdapter(),
        TypeScriptAdapter(),
        JavaAdapter(),
        CAdapter(),
        CppAdapter(),
    ),
    ids=("javascript", "typescript", "java", "c", "cpp"),
)
def test_tier2_whole_file_rejects_missing_required_predicate(
    adapter: Tier2RegexAdapter,
) -> None:
    predicates = (
        Predicate(PredicateKind.IDENTIFIER, "present"),
        Predicate(PredicateKind.IDENTIFIER, "missing"),
    )

    assert adapter.find_matches("present\n", predicates, whole_file=True) == ()


@pytest.mark.parametrize(
    ("adapter", "content"),
    (
        (JavaScriptAdapter(), "function build() { run(); }\nrun();\n"),
        (TypeScriptAdapter(), "function build(): void { run(); }\nrun();\n"),
        (JavaAdapter(), "int build() { run(); return 1; }\nrun();\n"),
        (CAdapter(), "int build(void) { run(); return 1; }\nrun();\n"),
        (CppAdapter(), "int build() { run(); return 1; }\nrun();\n"),
    ),
    ids=("javascript", "typescript", "java", "c", "cpp"),
)
def test_tier2_whole_file_deduplicates_evidence_in_stable_order(
    adapter: Tier2RegexAdapter, content: str
) -> None:
    matches = adapter.find_matches(
        content,
        (
            Predicate(PredicateKind.SYMBOL_DEFINITION, "build"),
            Predicate(PredicateKind.CALL, "run"),
            Predicate(PredicateKind.CALL, "run"),
        ),
        whole_file=True,
    )

    assert tuple((match.start_line, match.matched_kinds) for match in matches) == (
        (1, (PredicateKind.CALL, PredicateKind.SYMBOL_DEFINITION)),
        (2, (PredicateKind.CALL,)),
    )


@pytest.fixture(
    params=(
        (
            JavaScriptAdapter(),
            "src/build.js",
            "function build() {}\nconst boost = true;\nboost();\nforbidden();\nrun();\n",
        ),
        (
            JavaAdapter(),
            "src/Build.java",
            "int build() { return 1; }\nboolean boost = true;\nboost();\nforbidden();\nrun();\n",
        ),
    ),
    ids=("javascript", "java"),
)
def tier2_whole_file_fixture(
    request: pytest.FixtureRequest,
) -> tuple[Tier2RegexAdapter, str, str]:
    adapter, path, content = request.param
    return adapter, path, content


def test_tier2_whole_file_fixture_scores_should_once_and_orders_matches(
    tier2_whole_file_fixture: tuple[Tier2RegexAdapter, str, str],
) -> None:
    adapter, path, content = tier2_whole_file_fixture
    matches = score_content(
        content,
        adapter,
        "owner/repo",
        "a" * 40,
        path,
        "b" * 40,
        (
            Predicate(PredicateKind.SYMBOL_DEFINITION, "build"),
            Predicate(PredicateKind.CALL, "run"),
        ),
        (Predicate(PredicateKind.IDENTIFIER, "boost"),),
        (),
        whole_file=True,
    )

    assert tuple(
        (match.source.start_line, match.score, match.matched_kinds)
        for match in matches
    ) == (
        (
            1,
            3.0,
            (PredicateKind.IDENTIFIER, PredicateKind.SYMBOL_DEFINITION),
        ),
        (5, 3.0, (PredicateKind.CALL, PredicateKind.IDENTIFIER)),
    )


def test_tier2_whole_file_fixture_must_not_excludes_any_occurrence(
    tier2_whole_file_fixture: tuple[Tier2RegexAdapter, str, str],
) -> None:
    adapter, path, content = tier2_whole_file_fixture

    assert score_content(
        content,
        adapter,
        "owner/repo",
        "a" * 40,
        path,
        "b" * 40,
        (
            Predicate(PredicateKind.SYMBOL_DEFINITION, "build"),
            Predicate(PredicateKind.CALL, "run"),
        ),
        (),
        (Predicate(PredicateKind.CALL, "forbidden"),),
        whole_file=True,
    ) == []


def test_tier2_search_is_hash_seed_independent() -> None:
    script = (
        "import json; "
        "from leitir.adapters._tier2 import TypeScriptAdapter; "
        "from leitir.search import Predicate, PredicateKind; "
        "spans=TypeScriptAdapter().find_matches("
        "'export function build(): void {}\\nbuild();\\n', "
        "(Predicate(PredicateKind.CALL, 'build'),), whole_file=True); "
        "print(json.dumps([(s.start_line, [k.value for k in s.matched_kinds], s.method.value) for s in spans]))"
    )
    outputs: list[bytes] = []
    for seed in ("0", "1", "42"):
        environment = os.environ.copy()
        environment["PYTHONHASHSEED"] = seed
        environment["PYTHONPATH"] = "src"
        outputs.append(subprocess.check_output([sys.executable, "-c", script], env=environment))

    assert outputs[0] == outputs[1] == outputs[2]
    assert json.loads(outputs[0]) == [[1, ["call"], "heuristic"], [2, ["call"], "heuristic"]]


def test_tier2_regex_predicate_over_length_cap_is_incomplete_not_hung():
    """ReDoS regression (BUG2): mirrors the same guarantee for the tier-2 (JS/TS/Java/C/C++)
    regex adapters, which have their own copy of the predicate-matching loop.
    """
    long_line = "a" * 5000
    content = f"first line\n{long_line}\nlast line\n"
    predicate = Predicate(PredicateKind.REGEX, r"^(a|a)*b")
    result = JavaScriptAdapter().find_matches_ex(content, (predicate,))
    assert result.spans == ()
    assert result.parser_unavailable is True


def test_tier2_regex_predicate_under_cap_is_unaffected():
    content = "needle here\nno match on this line\n"
    predicate = Predicate(PredicateKind.REGEX, r"needle")
    result = JavaScriptAdapter().find_matches_ex(content, (predicate,))
    assert result.parser_unavailable is False
    assert [span.start_line for span in result.spans] == [1]
