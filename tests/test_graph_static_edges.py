from __future__ import annotations

import os
import subprocess
import symtable
import sys
import textwrap

import pytest

from leitir.bts_errors import BTSError, BTSRejectReason
from leitir.graph.model import EdgeKind, NodeKind, NodeOrigin
from leitir.graph.python import GRAMMAR_ID, extract_static_edges


def _extract(source: str, *, path: str = "src/pkg/mod.py"):
    return extract_static_edges(
        textwrap.dedent(source).lstrip().encode(),
        slug="owner/repo",
        commit_sha="a" * 40,
        path=path,
        blob_sha="b" * 40,
        package_root="src",
    )


def _edges(result, kind: EdgeKind):
    return [edge for edge in result.edges if edge.kind is kind]


class _GlobalSymbol:
    def is_parameter(self) -> bool:
        return False

    def is_imported(self) -> bool:
        return False

    def is_local(self) -> bool:
        return False

    def is_assigned(self) -> bool:
        return False

    def is_global(self) -> bool:
        return True


class _TableWithoutComprehensionChildren:
    """Proxy a symtable while simulating PEP 709's inlined comprehension table."""

    def __init__(self, table: symtable.SymbolTable, omitted_name: str, class_globals: frozenset[str]) -> None:
        self._table = table
        self._omitted_name = omitted_name
        self._class_globals = class_globals

    def get_children(self):
        return tuple(
            _TableWithoutComprehensionChildren(child, self._omitted_name, self._class_globals)
            for child in self._table.get_children()
            if not (self._table.get_type() == "class" and child.get_name() == self._omitted_name)
        )

    def lookup(self, name: str):
        try:
            return self._table.lookup(name)
        except KeyError:
            if self._table.get_type() == "class" and name in self._class_globals:
                return _GlobalSymbol()
            raise

    def __getattr__(self, name: str):
        return getattr(self._table, name)


def _inline_class_comprehension(
    monkeypatch: pytest.MonkeyPatch, name: str = "listcomp", class_globals: frozenset[str] = frozenset(),
) -> None:
    original = symtable.symtable
    monkeypatch.setattr(
        "leitir.graph.python.symtable.symtable",
        lambda *args: _TableWithoutComprehensionChildren(original(*args), name, class_globals),
    )


def test_plain_aliased_and_from_imports_retain_binding_evidence():
    result = _extract(
        """
        import alpha
        import beta.gamma as bg
        from delta import Item as Renamed
        """
    )
    imports = _edges(result, EdgeKind.IMPORTS)
    assert [edge.target.qualified_name for edge in imports] == ["alpha", "beta.gamma", "delta"]
    assert all(edge.source.qualified_name == "pkg.mod" for edge in imports)
    assert all(edge.provenance.binding is not None for edge in imports)
    assert {edge.provenance.resolution_rule for edge in imports} == {
        "import_statement_v1;binding=alpha;alias=",
        "import_statement_v1;binding=bg;alias=bg",
        "from_import_statement_v1;binding=Renamed;alias=Renamed;symbol=Item",
    }


def test_relative_import_is_normalized_against_explicit_package_root():
    result = _extract("from ..shared.errors import Failure\n", path="src/pkg/sub/mod.py")
    edge = _edges(result, EdgeKind.IMPORTS)[0]
    assert edge.target.qualified_name == "pkg.shared.errors"


def test_imported_dotted_module_attribute_chain_resolves_without_guessing():
    result = _extract(
        """
        import framework.models.base
        class Child(framework.models.base.Parent):
            pass
        """
    )
    edge = _edges(result, EdgeKind.INHERITS)[0]
    assert edge.target.qualified_name == "framework.models.base.Parent"
    assert edge.provenance.binding is not None
    assert edge.provenance.binding.start_line == 1


def test_single_multiple_and_protocol_bases_are_exactly_one_edge_per_expression():
    result = _extract(
        """
        from typing import Protocol
        class LocalBase: pass
        class One(LocalBase): pass
        class Many(LocalBase, Protocol): pass
        """
    )
    edges = _edges(result, EdgeKind.INHERITS)
    assert {(edge.source.qualified_name, edge.target.qualified_name) for edge in edges} == {
        ("pkg.mod.Many", "pkg.mod.LocalBase"),
        ("pkg.mod.Many", "typing.Protocol"),
        ("pkg.mod.One", "pkg.mod.LocalBase"),
    }
    assert [edge.target.qualified_name for edge in edges if edge.provenance.protocol_base] == ["typing.Protocol"]


def test_named_qualified_constructed_and_chained_raises_have_lexical_owners():
    result = _extract(
        """
        import remote.errors as errors
        class LocalError(Exception): pass
        def run():
            raise LocalError("bad") from errors.Cause
        """
    )
    raises = _edges(result, EdgeKind.RAISES)
    assert {(edge.source.qualified_name, edge.target.qualified_name) for edge in raises} == {
        ("pkg.mod.run", "pkg.mod.LocalError"),
        ("pkg.mod.run", "remote.errors.Cause"),
    }
    assert next(edge for edge in raises if edge.target.qualified_name == "pkg.mod.LocalError").target.origin is NodeOrigin.DONOR


def test_bare_raise_resolves_only_from_one_resolved_handler_type():
    result = _extract(
        """
        def run():
            try:
                work()
            except KeyError:
                raise
        """
    )
    edge = _edges(result, EdgeKind.RAISES)[0]
    assert edge.target.qualified_name == "builtins.KeyError"
    assert edge.target.origin is NodeOrigin.STDLIB
    assert not [item for item in result.unresolved if item.kind is EdgeKind.RAISES]


@pytest.mark.parametrize(
    ("source", "kind", "detail"),
    [
        ("from pkg import *\n", EdgeKind.IMPORTS, "star_import_v1"),
        ("import importlib\nimportlib.import_module(name)\n", EdgeKind.IMPORTS, "dynamic_import_v1"),
        ("from importlib import import_module\nimport_module(name)\n", EdgeKind.IMPORTS, "dynamic_import_v1"),
        ("class C(factory()): pass\n", EdgeKind.INHERITS, "dynamic_base_v1"),
        ("class C(metaclass=Meta): pass\n", EdgeKind.INHERITS, "metaclass_keyword_v1"),
        ("def f():\n    raise\n", EdgeKind.RAISES, "bare_raise_unresolved_handler_v1"),
        ("def f():\n    try: pass\n    except (KeyError, ValueError): raise\n", EdgeKind.RAISES, "bare_raise_unresolved_handler_v1"),
    ],
)
def test_unsupported_and_unresolved_sites_are_recorded_without_synthesized_edges(source, kind, detail):
    result = _extract(source)
    matching = [item for item in result.unresolved if item.detail_code == detail]
    assert len(matching) == 1
    assert matching[0].kind is kind
    expected_reason = (
        BTSRejectReason.REJECT_UNRESOLVED_EDGE
        if detail == "bare_raise_unresolved_handler_v1"
        else BTSRejectReason.REJECT_UNSUPPORTED_CONSTRUCT
    )
    assert matching[0].reason is expected_reason
    assert not any(edge.provenance.site == matching[0].provenance.site for edge in result.edges)
    assert any(blocker.detail_code == detail for blocker in result.coverage.blockers)


def test_conditional_and_fallback_imports_are_unsupported_and_not_bindings():
    result = _extract(
        """
        try:
            from first import Base
        except ImportError:
            from second import Base
        class Child(Base): pass
        """
    )
    assert not _edges(result, EdgeKind.IMPORTS)
    assert not _edges(result, EdgeKind.INHERITS)
    assert [item.detail_code for item in result.unresolved].count("conditional_import_v1") == 2
    assert any(item.detail_code == "ambiguous_base_binding_v1" for item in result.unresolved)


def test_whole_block_symtable_shadowing_prevents_statement_order_guess():
    result = _extract(
        """
        from errors import Failure
        def run():
            raise Failure
            Failure = replacement
        """
    )
    assert not _edges(result, EdgeKind.RAISES)
    assert any(item.detail_code == "unresolved_exception_binding_v1" for item in result.unresolved)


def test_type_checking_import_is_type_only_not_runtime_or_unsupported():
    result = _extract(
        """
        from typing import TYPE_CHECKING
        if TYPE_CHECKING:
            from optional import Thing
        """
    )
    assert [edge.target.qualified_name for edge in _edges(result, EdgeKind.IMPORTS)] == ["typing"]
    assert result.unresolved == ()


@pytest.mark.parametrize(
    ("source", "detail"),
    [
        (b"type Alias = int\n", "pep695_type_alias_v1"),
        (b"class Box[T]: pass\n", "pep695_type_parameters_v1"),
        (b"def identity[T](value: T) -> T: return value\n", "pep695_type_parameters_v1"),
    ],
)
def test_pep695_is_rejected_by_python_311_gate_on_every_host(source: bytes, detail: str):
    result = extract_static_edges(
        source,
        slug="owner/repo",
        commit_sha="a" * 40,
        path="src/pkg/mod.py",
        blob_sha="b" * 40,
        package_root="src",
    )
    assert result.grammar_id == GRAMMAR_ID
    assert result.coverage.parsed_files == ()
    assert result.unresolved[0].reason is BTSRejectReason.REJECT_UNSUPPORTED_CONSTRUCT
    assert result.unresolved[0].detail_code == detail


def test_conflicting_bindings_never_synthesize_a_likely_edge():
    result = _extract(
        """
        from one import Error
        from two import Error
        def run():
            raise Error
        """
    )
    assert not _edges(result, EdgeKind.RAISES)
    assert any(item.detail_code == "unresolved_exception_binding_v1" for item in result.unresolved)


@pytest.mark.parametrize("seed", ["0", "1", "42"])
def test_static_graph_rendering_is_byte_identical_across_hash_seeds(seed: str):
    script = textwrap.dedent(
        """
        from leitir.graph.python import extract_static_edges
        source = b'import a.b.c\\nfrom .errors import Failure as F\\nclass A(a.b.c.Base): pass\\ndef run():\\n    raise F from ValueError\\n'
        result = extract_static_edges(source, slug='owner/repo', commit_sha='a'*40,
            path='src/pkg/mod.py', blob_sha='b'*40, package_root='src')
        print(result.to_graph().to_json(), end='')
        """
    )
    env = {**os.environ, "PYTHONHASHSEED": seed}
    actual = subprocess.check_output([sys.executable, "-c", script], env=env)
    baseline = subprocess.check_output([sys.executable, "-c", script], env={**os.environ, "PYTHONHASHSEED": "0"})
    assert actual == baseline


def test_nested_method_raise_uses_method_node_and_byte_columns():
    result = _extract("class Service:\n    def run(self):\n        raise ValueError\n")
    edge = _edges(result, EdgeKind.RAISES)[0]
    assert edge.source.kind is NodeKind.METHOD
    assert edge.source.qualified_name == "pkg.mod.Service.run"
    assert edge.provenance.site.start_col == 14


def test_comprehension_scopes_resolve_outer_closures_and_same_line_genexprs() -> None:
    result = _extract(
        """
        def helper(value):
            return value

        def run(values):
            first = (helper(value) for value in values)
            listed = [helper(value) for value in first]
            setted = {helper(value) for value in listed}
            mapped = {value: helper(value) for value in setted}
            return any(helper(value) for value in mapped) or any(helper(value) for value in mapped)
        """
    )
    calls = _edges(result, EdgeKind.CALLS)
    assert len([edge for edge in calls if edge.target.qualified_name == "pkg.mod.helper"]) == 6
    assert not [item for item in result.unresolved if item.detail_code == "symtable_scope_mismatch"]


def test_inlined_class_comprehension_does_not_inherit_class_bindings(monkeypatch: pytest.MonkeyPatch) -> None:
    _inline_class_comprehension(monkeypatch)
    result = _extract(
        """
        class C:
            class_local = 1
            values = [class_local for item in range(1)]
        """
    )
    assert not [edge for edge in _edges(result, EdgeKind.READS) if edge.target.qualified_name == "pkg.mod.C.class_local"]
    assert not [item for item in result.unresolved if item.detail_code == "symtable_scope_mismatch"]


def test_inlined_class_comprehension_still_resolves_module_bindings(monkeypatch: pytest.MonkeyPatch) -> None:
    _inline_class_comprehension(monkeypatch, class_globals=frozenset({"module_value"}))
    result = _extract(
        """
        module_value = 1
        class C:
            values = [module_value for item in range(1)]
        """
    )
    reads = _edges(result, EdgeKind.READS)
    assert [edge.target.qualified_name for edge in reads] == ["pkg.mod.module_value"]


def test_unmatched_genexpr_scope_remains_fail_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    _inline_class_comprehension(monkeypatch, "genexpr")
    with pytest.raises(BTSError) as caught:
        _extract("class C:\n    values = (item for item in range(1))\n")
    assert caught.value.evidence.detail_code == "symtable_scope_mismatch"


def test_async_comprehension_resolves_outer_binding() -> None:
    result = _extract(
        """
        async def helper(value):
            return value

        async def run(values):
            return [helper(value) async for value in values]
        """
    )
    assert [edge.target.qualified_name for edge in _edges(result, EdgeKind.CALLS)] == ["pkg.mod.helper"]


def test_walrus_in_comprehension_resolves_outer_binding() -> None:
    result = _extract(
        """
        def helper(value):
            return value

        def run(values):
            return [(result := helper(value)) for value in values]
        """
    )
    assert [edge.target.qualified_name for edge in _edges(result, EdgeKind.CALLS)] == ["pkg.mod.helper"]
