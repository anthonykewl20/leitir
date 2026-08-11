from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

import leitir.adapters.python_ast as python_ast_module
from leitir.adapters import MatchMethod, PythonAdapter
from leitir.adapters.python_ast import (
    LexicalClassification,
    PythonAstAdapter,
    PythonAstSpanMatch,
)
from leitir.adapters.registry import build_adapters
from leitir.apisurface import extract_api_surface
from leitir.engine import ScopedSearcher
from leitir.search import (
    CoverageStatus,
    Predicate,
    PredicateKind,
    RepoScope,
    SearchMode,
    SearchSpec,
)
from leitir.tree import BlobEntry

SHA = "a" * 40


def _predicate(kind: PredicateKind, value: str) -> Predicate:
    return Predicate(kind, value)


class _Tree:
    def __init__(self, content: str) -> None:
        self._data = content.encode()
        self._blob_sha = hashlib.sha1(
            b"blob %d\x00" % len(self._data) + self._data
        ).hexdigest()

    def list_blobs_ex(
        self, slug: str, commit_sha: str
    ) -> tuple[tuple[BlobEntry, ...], bool]:
        return (
            (BlobEntry("sample.py", self._blob_sha, len(self._data)),),
            False,
        )

    def read_blob(self, slug: str, blob_sha: str) -> bytes:
        return self._data


def _ast_adapter() -> PythonAstAdapter:
    return PythonAstAdapter(PythonAdapter())


def _search(content: str, predicate: Predicate) -> object:
    searcher = ScopedSearcher(_Tree(content), (_ast_adapter(),))
    return searcher.search(
        SearchSpec(
            mode=SearchMode.SCOPED_EXHAUSTIVE,
            must=(predicate,),
            scopes=(RepoScope("owner/repo", SHA),),
        )
    )


def test_structural_matches_have_ast_provenance_and_stable_positions() -> None:
    content = textwrap.dedent(
        """\
        import pathlib
        from os import path

        def build(value: str = "x") -> str:
            result = path.join(value, "y")
            return result

        build("z")
        """
    )
    cases = (
        (PredicateKind.IMPORT, "pathlib", 1),
        (PredicateKind.SIGNATURE, '(value: str = \'x\') -> str', 4),
        (PredicateKind.SYMBOL_DEFINITION, "build", 4),
        (PredicateKind.SYMBOL_REFERENCE, "result", 6),
        (PredicateKind.CALL, "build", 8),
    )
    observed: list[tuple[int, int | None, str]] = []
    for kind, value, line in cases:
        result = _ast_adapter().find_matches_ex(
            content, (_predicate(kind, value),)
        )
        assert result.parser_unavailable is False
        assert result.spans
        assert all(span.method is MatchMethod.AST for span in result.spans)
        assert all(span.start_line == span.end_line for span in result.spans)
        assert result.spans[0].start_line == line
        observed.extend(
            (span.start_line, span.start_col, span.matched_kinds[0].value)
            for span in result.spans
        )
    assert observed == sorted(
        observed, key=lambda item: (item[0], item[1] or -1, item[2])
    )


def test_loaded_names_have_per_scope_symtable_classification() -> None:
    content = textwrap.dedent(
        """\
        import os
        module_value = 1
        module_result = module_value
        def outer(parameter):
            local_value = parameter
            def inner():
                return parameter + module_value + len([]) + os.sep + missing
            return local_value
        class Holder:
            class_value = 2
            reflected = class_value
        """
    )

    expected = {
        ("module_value", 3): LexicalClassification.LOCAL_ASSIGNED,
        ("parameter", 5): LexicalClassification.PARAMETER,
        ("parameter", 7): LexicalClassification.FREE,
        ("module_value", 7): LexicalClassification.GLOBAL,
        ("len", 7): LexicalClassification.BUILTIN,
        ("os", 7): LexicalClassification.IMPORTED,
        ("missing", 7): LexicalClassification.GLOBAL,
        ("local_value", 8): LexicalClassification.LOCAL_ASSIGNED,
        ("class_value", 11): LexicalClassification.LOCAL_ASSIGNED,
    }
    for (name, line), classification in expected.items():
        result = _ast_adapter().find_matches_ex(
            content, (_predicate(PredicateKind.SYMBOL_REFERENCE, name),)
        )
        span = next(span for span in result.spans if span.start_line == line)
        assert isinstance(span, PythonAstSpanMatch)
        assert span.method is MatchMethod.AST
        assert [
            detail.classification
            for detail in span.reference_provenance
            if detail.name == name
        ] == [classification]


def test_symtable_failure_keeps_ast_references_unknown_and_marks_partial(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fail_symtable(content: str, filename: str = "<unknown>") -> object:
        raise RuntimeError("injected symtable failure")

    monkeypatch.setattr(python_ast_module, "python_symtable", fail_symtable)
    content = "result = target\n"
    predicate = _predicate(PredicateKind.SYMBOL_REFERENCE, "target")

    result = _ast_adapter().find_matches_ex(content, (predicate,))
    assert result.parser_unavailable is True
    assert len(result.spans) == 1
    span = result.spans[0]
    assert isinstance(span, PythonAstSpanMatch)
    assert span.method is MatchMethod.AST
    assert tuple(
        detail.classification for detail in span.reference_provenance
    ) == (LexicalClassification.UNKNOWN,)
    report = _search(content, predicate)
    assert report.coverage.status is CoverageStatus.PARTIAL
    assert report.matches


def test_symtable_helper_keeps_apisurface_json_byte_compatible(tmp_path: Path) -> None:
    (tmp_path / "sample.py").write_text(
        "def public(value: int = 1) -> str:\n    return str(value)\n",
        encoding="utf-8",
    )

    encoded = json.dumps(
        extract_api_surface(tmp_path, "python"),
        sort_keys=True,
        separators=(",", ":"),
    )

    assert encoded == (
        '{"methods":["ast"],"modules":[{"docstring":null,"method":"ast",'
        '"name":"sample","path":"sample.py"}],"schema_version":1,"symbols":'
        '[{"docstring":null,"kind":"function","line":1,"method":"ast",'
        '"module":"sample","name":"public","path":"sample.py",'
        '"qualified_name":"sample.public","signature":"(value: int = 1) -> str"}]}'
    )


def test_syntax_error_falls_back_with_hits_and_marks_scope_partial() -> None:
    content = "target()\nif (\n"
    predicate = _predicate(PredicateKind.CALL, "target")
    result = _ast_adapter().find_matches_ex(content, (predicate,))
    assert result.parser_unavailable is True
    assert result.spans
    assert all(span.method is MatchMethod.HEURISTIC for span in result.spans)
    report = _search(content, predicate)
    assert report.coverage.status is CoverageStatus.PARTIAL
    assert report.coverage.incomplete_results is True
    assert report.coverage.files_excluded >= 1
    assert report.matches


def test_syntax_error_without_fallback_hits_marks_scope_partial() -> None:
    content = "if (\n"
    predicate = _predicate(PredicateKind.CALL, "missing")
    result = _ast_adapter().find_matches_ex(content, (predicate,))
    assert result.parser_unavailable is True
    assert result.spans == ()
    report = _search(content, predicate)
    assert report.coverage.status is CoverageStatus.PARTIAL
    assert report.coverage.incomplete_results is True
    assert report.coverage.files_excluded >= 1
    assert report.matches == ()


def test_same_line_ast_nodes_merge_without_duplicate_source_identity() -> None:
    predicates = (
        _predicate(PredicateKind.SYMBOL_DEFINITION, "result"),
        _predicate(PredicateKind.CALL, "build"),
    )
    result = _ast_adapter().find_matches_ex("result = build()\n", predicates)
    assert len(result.spans) == 1
    assert result.spans[0].matched_kinds == (
        PredicateKind.CALL,
        PredicateKind.SYMBOL_DEFINITION,
    )
    searcher = ScopedSearcher(_Tree("result = build()\n"), (_ast_adapter(),))
    report = searcher.search(
        SearchSpec(
            mode=SearchMode.SCOPED_EXHAUSTIVE,
            must=predicates,
            scopes=(RepoScope("owner/repo", SHA),),
        )
    )
    assert len(report.matches) == 1


def test_text_and_structural_predicates_use_per_predicate_matching() -> None:
    content = "def handler():\n    handler()\n"
    identifier = _predicate(PredicateKind.IDENTIFIER, "handler")
    call = _predicate(PredicateKind.CALL, "handler")

    text_result = _ast_adapter().find_matches_ex(content, (identifier,))
    assert text_result.parser_unavailable is False
    assert text_result.spans
    assert all(span.method is MatchMethod.HEURISTIC for span in text_result.spans)
    text_report = _search(content, identifier)
    assert text_report.coverage.status is CoverageStatus.COMPLETE_FOR_DECLARED_UNIVERSE
    assert text_report.matches

    call_result = _ast_adapter().find_matches_ex(content, (call,))
    assert call_result.spans[0].start_line == 2
    assert call_result.spans[0].method is MatchMethod.AST

    mixed = _ast_adapter().find_matches_ex(content, (identifier, call))
    assert len(mixed.spans) == 1
    assert mixed.spans[0].start_line == 2
    assert mixed.spans[0].matched_kinds == (
        PredicateKind.CALL,
        PredicateKind.IDENTIFIER,
    )
    assert mixed.spans[0].method is MatchMethod.HEURISTIC


def test_imports_are_symbol_definitions() -> None:
    result = _ast_adapter().find_matches_ex(
        "import os\nfrom module import value\n",
        (_predicate(PredicateKind.SYMBOL_DEFINITION, "os"),),
    )
    assert len(result.spans) == 1
    assert result.spans[0].start_line == 1
    assert result.spans[0].method is MatchMethod.AST


def test_multiline_ast_node_does_not_mix_end_column_lines() -> None:
    result = _ast_adapter().find_matches_ex(
        "result = build(\n    value,\n)\n",
        (_predicate(PredicateKind.CALL, "build"),),
    )
    assert len(result.spans) == 1
    assert result.spans[0].start_col == 9
    assert result.spans[0].end_col is None


def test_registry_selects_ast_adapter_without_changing_default_order() -> None:
    default_languages = tuple(adapter.language for adapter in build_adapters())
    ast_adapters = build_adapters(ast_python=True)

    assert default_languages == (
        "python",
        "rust",
        "go",
        "javascript",
        "typescript",
        "java",
        "c",
        "cpp",
    )
    assert isinstance(ast_adapters[0], PythonAstAdapter)
    assert tuple(adapter.language for adapter in ast_adapters) == default_languages


def test_symtable_classification_is_hash_seed_independent() -> None:
    script = textwrap.dedent(
        """\
        import hashlib
        from leitir.adapters import PythonAdapter
        from leitir.adapters.python_ast import PythonAstAdapter
        from leitir.engine import ScopedSearcher
        import leitir.engine
        from leitir.search import Predicate, PredicateKind, RepoScope, SearchMode, SearchSpec
        from leitir.tree import BlobEntry

        import json

        content = b"import os\\ndef build(value):\\n    return len(value) + os.sep\\nbuild([])\\n"
        blob = hashlib.sha1(b"blob %d\\x00" % len(content) + content).hexdigest()
        class Tree:
            def list_blobs_ex(self, slug, commit_sha):
                return ((BlobEntry("x.py", blob, len(content)),), False)
            def read_blob(self, slug, blob_sha):
                return content
        leitir.engine._utc_now = lambda: "2026-08-10T00:00:00Z"
        adapter = PythonAstAdapter(PythonAdapter())
        report = ScopedSearcher(Tree(), (adapter,)).search(
            SearchSpec(
                mode=SearchMode.SCOPED_EXHAUSTIVE,
                must=(Predicate(PredicateKind.CALL, "build"),),
                scopes=(RepoScope("owner/repo", "a" * 40),),
            )
        )
        lexical = []
        for name in ("len", "os", "value"):
            result = adapter.find_matches_ex(
                content.decode(),
                (Predicate(PredicateKind.SYMBOL_REFERENCE, name),),
            )
            lexical.extend(
                (detail.name, detail.classification.value, detail.start_col)
                for span in result.spans
                for detail in span.reference_provenance
            )
        print(json.dumps({"report": json.loads(report.to_json(indent=None)), "lexical": lexical}))
        """
    )
    outputs = []
    for seed in ("0", "1", "42"):
        env = dict(os.environ, PYTHONHASHSEED=seed)
        completed = subprocess.run(
            [sys.executable, "-c", script],
            check=True,
            capture_output=True,
            text=True,
            env=env,
        )
        outputs.append(json.loads(completed.stdout))
    assert outputs[1:] == outputs[:-1]
