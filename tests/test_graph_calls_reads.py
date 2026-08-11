from __future__ import annotations

import os
import subprocess
import sys
import textwrap

import pytest

from leitir.bts_errors import BTSRejectReason
from leitir.graph.model import EdgeKind, NodeKind, NodeOrigin
from leitir.graph.python import extract_static_edges


def _extract(source: str):
    return extract_static_edges(
        textwrap.dedent(source).lstrip().encode(),
        slug="owner/repo",
        commit_sha="a" * 40,
        path="src/pkg/mod.py",
        blob_sha="b" * 40,
        package_root="src",
    )


def _edges(result, kind: EdgeKind):
    return [edge for edge in result.edges if edge.kind is kind]


def test_direct_calls_resolve_import_alias_from_import_module_and_local_defs():
    result = _extract(
        """
        import remote.api as api
        from remote.helpers import consume as use

        def module_helper(): pass
        def outer():
            def local_helper(): pass
            api.fetch()
            use()
            module_helper()
            local_helper()
        """
    )
    calls = _edges(result, EdgeKind.CALLS)
    assert {(edge.source.qualified_name, edge.target.qualified_name) for edge in calls} == {
        ("pkg.mod.outer", "remote.api.fetch"),
        ("pkg.mod.outer", "remote.helpers.consume"),
        ("pkg.mod.outer", "pkg.mod.module_helper"),
        ("pkg.mod.outer", "pkg.mod.outer.local_helper"),
    }
    assert all(edge.provenance.binding is not None for edge in calls)


def test_nested_calls_lambda_and_comprehension_keep_nearest_graph_owner():
    result = _extract(
        """
        def inner(value=None): return value
        def outer(items):
            callback = lambda value: inner(value)
            return inner([inner(item) for item in items])
        """
    )
    calls = _edges(result, EdgeKind.CALLS)
    assert len(calls) == 3
    assert {edge.source.qualified_name for edge in calls} == {"pkg.mod.outer"}
    assert {edge.target.qualified_name for edge in calls} == {"pkg.mod.inner"}
    assert not [item for item in result.unresolved if item.expression == "item"]


def test_instantiation_replaces_call_and_constructor_dependencies_are_extracted():
    result = _extract(
        """
        def prepare(): pass
        class Service:
            def __init__(self):
                prepare()
        def build():
            return Service()
        """
    )
    instantiates = _edges(result, EdgeKind.INSTANTIATES)
    assert [(edge.source.qualified_name, edge.target.qualified_name) for edge in instantiates] == [
        ("pkg.mod.build", "pkg.mod.Service")
    ]
    assert not [edge for edge in _edges(result, EdgeKind.CALLS) if edge.provenance.site.start_line == 6]
    assert ("pkg.mod.Service.__init__", "pkg.mod.prepare") in {
        (edge.source.qualified_name, edge.target.qualified_name) for edge in _edges(result, EdgeKind.CALLS)
    }


def test_complete_runtime_reads_cover_types_exceptions_callbacks_constants_and_class_values():
    result = _extract(
        """
        from donor.errors import DonorError
        CONST = 7
        class DonorType: pass
        def helper(): pass
        def consume(value): return value
        def run(value):
            try:
                if isinstance(value, DonorType):
                    consume(helper)
                    return CONST, DonorType
            except DonorError:
                return None
        """
    )
    reads = _edges(result, EdgeKind.READS)
    targets = [edge.target.qualified_name for edge in reads]
    assert targets.count("pkg.mod.DonorType") == 2
    assert "donor.errors.DonorError" in targets
    assert "pkg.mod.helper" in targets
    assert "pkg.mod.CONST" in targets
    assert not [edge for edge in reads if edge.target.qualified_name == "pkg.mod.consume"]
    error_edge = next(edge for edge in reads if edge.target.qualified_name == "donor.errors.DonorError")
    assert error_edge.target.kind is NodeKind.CLASS
    assert error_edge.provenance.binding is not None


def test_match_class_is_a_runtime_class_read():
    result = _extract(
        """
        class Point: pass
        def classify(value):
            match value:
                case Point(): return True
            return False
        """
    )
    assert [(edge.source.qualified_name, edge.target.qualified_name) for edge in _edges(result, EdgeKind.READS)] == [
        ("pkg.mod.classify", "pkg.mod.Point")
    ]


@pytest.mark.parametrize("receiver", ["self", "cls", "service"])
def test_receiver_dispatch_is_rejected_even_when_receiver_type_looks_proved(receiver: str):
    prefix = "class Child(Base):\n    def run(self, cls, service: Base):\n        "
    expression = f"{receiver}.run()"
    result = _extract("class Base:\n    def run(self): pass\n" + prefix + expression + "\n")
    unresolved = [item for item in result.unresolved if item.expression == expression[:-2]]
    assert len(unresolved) == 1
    assert unresolved[0].kind is EdgeKind.CALLS
    assert unresolved[0].reason is BTSRejectReason.REJECT_UNSUPPORTED_CONSTRUCT
    assert unresolved[0].detail_code == "receiver_dispatch_v1"
    assert not [edge for edge in _edges(result, EdgeKind.CALLS) if edge.target.qualified_name.endswith("Base.run")]


def test_subclass_override_does_not_make_self_dispatch_resolve_to_base_method():
    result = _extract(
        """
        class Base:
            def action(self): pass
            def invoke(self): self.action()
        class Child(Base):
            def action(self): pass
        """
    )
    assert not _edges(result, EdgeKind.CALLS)
    assert any(item.detail_code == "receiver_dispatch_v1" for item in result.unresolved)


def test_unproved_nonlocal_runtime_load_is_a_terminal_blocker():
    result = _extract("def run(local):\n    return local, missing\n")
    unresolved = [item for item in result.unresolved if item.expression == "missing"]
    assert len(unresolved) == 1
    assert unresolved[0].kind is EdgeKind.READS
    assert unresolved[0].reason is BTSRejectReason.REJECT_UNRESOLVED_EDGE
    assert unresolved[0].detail_code == "unresolved_nonlocal_load_v1"
    assert any(blocker.detail_code == "unresolved_nonlocal_load_v1" for blocker in result.coverage.blockers)


@pytest.mark.parametrize(
    ("source", "detail"),
    [
        ("def run(obj): return getattr(obj, 'work')()\n", "dynamic_dispatch_v1"),
        ("registry = {}\ndef run(key): return registry[key]()\n", "dynamic_dispatch_v1"),
        ("def helper(): pass\nalias = helper\ndef run(): alias()\n", "assignment_dispatch_v1"),
        ("def __getattr__(name): return name\n", "dynamic_getattr_v1"),
        ("class C: pass\nC.work = lambda: None\n", "monkeypatch_v1"),
        ("def run(): return open('data.txt').read()\n", "implicit_resource_v1"),
    ],
)
def test_dynamic_dispatch_and_implicit_resources_are_unresolved_never_guessed(source: str, detail: str):
    result = _extract(source)
    matching = [item for item in result.unresolved if item.detail_code == detail]
    assert matching
    assert all(item.reason is BTSRejectReason.REJECT_UNSUPPORTED_CONSTRUCT for item in matching)


@pytest.mark.parametrize("seed", ["0", "1", "42"])
def test_calls_reads_graph_is_byte_identical_across_hash_seeds(seed: str):
    script = textwrap.dedent(
        """
        from leitir.graph.python import extract_static_edges
        source = b'from ext import consume\\nCONST = 3\\nclass C: pass\\ndef helper(): pass\\ndef run(x):\\n    consume(helper)\\n    return C() if isinstance(x, C) else CONST\\n'
        result = extract_static_edges(source, slug='owner/repo', commit_sha='a'*40,
            path='src/pkg/mod.py', blob_sha='b'*40, package_root='src')
        print(result.to_graph().to_json(), end='')
        """
    )
    env = {**os.environ, "PYTHONHASHSEED": seed}
    actual = subprocess.check_output([sys.executable, "-c", script], env=env)
    baseline = subprocess.check_output(
        [sys.executable, "-c", script], env={**os.environ, "PYTHONHASHSEED": "0"}
    )
    assert actual == baseline


def test_imported_runtime_values_are_declared_external_not_host_discovered():
    result = _extract("from remote import callback\ndef run(): return callback\n")
    edge = _edges(result, EdgeKind.READS)[0]
    assert edge.target.origin is NodeOrigin.DECLARED_EXTERNAL
    assert edge.target.qualified_name == "remote.callback"
