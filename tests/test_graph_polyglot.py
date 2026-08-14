from __future__ import annotations

import importlib
import importlib.util
import os
import subprocess
import sys
import textwrap
import tomllib
import types
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

import pytest

import leitir.graph.registry as graph_registry
from leitir.bts import DonorSnapshot
from leitir.bts_errors import BTSError, BTSRejectReason
from leitir.graph import (
    GraphExtractionPolicy,
    GraphExtractionRequest,
    make_graph_provider,
    register_graph_extractor,
)
from leitir.graph.javascript import QUERY_ID, QUERY_TEXT
from leitir.graph.model import SourceRef
from leitir.graph.policy import (
    GRAPH_EXTRACTION_POLICY_SCHEMA_VERSION,
    SOURCE_SELECTION_VERSION,
    TREE_SITTER_PINS,
    assert_platform_wheel_coverage,
    build_graph_extraction_policy,
    compute_policy_digest,
    require_tree_sitter_extra,
    requirements_lock_digest,
)
from leitir.graph.ts_kernel import (
    DEFAULT_MAX_EDGES,
    DEFAULT_MAX_FILE_BYTES,
    DEFAULT_MAX_FILES,
    DEFAULT_MAX_QUERY_MATCHES,
    DEFAULT_MAX_SYMBOLS,
    DEFAULT_MAX_TREE_NODES_PER_FILE,
    DEFAULT_MAX_WORK_UNITS,
    byte_offset,
    byte_point,
    query_sha256,
    source_ref,
)
from leitir.treehash import FULL, TREE_HASH_ALGORITHM, compute_materialized_tree_hash


def _policy(language: str = "javascript", **overrides: object) -> GraphExtractionPolicy:
    grammar_versions = {
        "javascript": "0.25.0",
        "typescript": "0.23.2",
        "rust": "0.24.2",
        "go": "0.25.0",
    }
    grammar_factories = {
        "javascript": "language",
        "typescript": "language_typescript",
        "rust": "language",
        "go": "language",
    }
    grammar_abi_versions = {
        "javascript": 15,
        "typescript": 14,
        "rust": 15,
        "go": 15,
    }
    values: dict[str, object] = {
        "schema_version": GRAPH_EXTRACTION_POLICY_SCHEMA_VERSION,
        "authority": "leitir-test",
        "policy_id": "polyglot-test-v1",
        "language": language,
        "requirements_lock_digest": "1" * 64,
        "runtime_distribution": "tree-sitter",
        "runtime_version": "0.25.2",
        "grammar_distribution": f"tree-sitter-{language}",
        "grammar_version": grammar_versions[language],
        "grammar_factory": grammar_factories[language],
        "grammar_abi_version": grammar_abi_versions[language],
        "query_id": QUERY_ID if language == "javascript" else "test-query-v1",
        "query_sha256": query_sha256(QUERY_TEXT) if language == "javascript" else "2" * 64,
        "producer_id": f"leitir.graph.{language}",
        "producer_version": "stage-2-v1",
        "resolution_rule_version": f"{language}_tree_sitter_resolution_v1",
        "source_selection_version": SOURCE_SELECTION_VERSION,
        "max_files": 10,
        "max_file_bytes": 1024,
        "max_tree_nodes_per_file": 100,
        "max_query_matches": 100,
        "max_symbols": 100,
        "max_edges": 100,
        "max_work_units": 100,
    }
    values.update(overrides)
    return build_graph_extraction_policy(**values)


def _source(path: str = "src/example.js") -> SourceRef:
    return SourceRef("owner/repo", "a" * 40, path, "b" * 40, 1, 0, 1, 0)


def _snapshot(tmp_path: Path, files: dict[str, bytes]) -> DonorSnapshot:
    source_root = tmp_path / "materialized"
    for relative, content in files.items():
        target = source_root / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(content)
    tree_hash, scope = compute_materialized_tree_hash(source_root)
    assert scope == FULL
    return DonorSnapshot(
        "owner/repo",
        "a" * 40,
        "git-commit",
        "exact",
        tree_hash,
        TREE_HASH_ALGORITHM,
        FULL,
        tmp_path,
        source_root,
    )


def _lock() -> str:
    return "\n".join(
        f"{name}=={version} \\\n+    --hash=sha256:{index:064x}"
        for index, (name, version) in enumerate(sorted(TREE_SITTER_PINS.items()), start=1)
    ).replace("\n+", "\n")


@contextmanager
def _native_tree_sitter_stubs() -> Iterator[None]:
    """Inject native bindings only for wheel-independent ordering tests."""

    names = (
        "tree_sitter",
        "tree_sitter_javascript",
        "tree_sitter_typescript",
        "tree_sitter_rust",
        "tree_sitter_go",
    )
    absent = object()
    previous = {name: sys.modules.get(name, absent) for name in names}
    runtime = types.ModuleType("tree_sitter")
    runtime.Language = type("Language", (), {})
    runtime.Parser = type("Parser", (), {})
    grammar_modules = {
        "tree_sitter_javascript": ("language",),
        "tree_sitter_typescript": ("language_typescript",),
        "tree_sitter_rust": ("language",),
        "tree_sitter_go": ("language",),
    }
    sys.modules["tree_sitter"] = runtime
    for name, factories in grammar_modules.items():
        module = types.ModuleType(name)
        for factory in factories:
            setattr(module, factory, lambda: 1)
        sys.modules[name] = module
    try:
        yield
    finally:
        for name, value in previous.items():
            if value is absent:
                sys.modules.pop(name, None)
            else:
                sys.modules[name] = value


def test_import_is_stdlib_only_in_a_clean_subprocess() -> None:
    script = "import sys; import leitir; import leitir.graph; assert not any(name == 'tree_sitter' or name.startswith('tree_sitter_') for name in sys.modules); print('ok')"
    environment = {"PYTHONPATH": str(Path(__file__).parents[1] / "src")}

    assert subprocess.check_output([sys.executable, "-S", "-c", script], env=environment).replace(b"\r\n", b"\n") == b"ok\n"


def test_tree_sitter_extra_is_exact_and_runtime_dependencies_stay_empty() -> None:
    text = (Path(__file__).parents[1] / "pyproject.toml").read_text(encoding="utf-8")

    assert "dependencies = []" in text
    assert TREE_SITTER_PINS == {
        "tree-sitter": "0.25.2",
        "tree-sitter-javascript": "0.25.0",
        "tree-sitter-typescript": "0.23.2",
        "tree-sitter-rust": "0.24.2",
        "tree-sitter-go": "0.25.0",
    }
    for name, version in TREE_SITTER_PINS.items():
        assert f'"{name}=={version}"' in text


def test_registry_normalizes_aliases_returns_previous_and_rejects_non_callables() -> None:
    def first(request: GraphExtractionRequest):
        raise AssertionError(request)

    def second(request: GraphExtractionRequest):
        raise AssertionError(request)

    previous_fixture = register_graph_extractor("stage1-fixture", first)
    previous_javascript = register_graph_extractor("js", second)
    try:
        assert previous_fixture is None
        assert previous_javascript is not None
        assert register_graph_extractor("javascript", first) is second
        with pytest.raises(TypeError):
            register_graph_extractor("javascript", object())  # type: ignore[arg-type]
    finally:
        assert previous_javascript is not None
        register_graph_extractor("javascript", previous_javascript)
        graph_registry._EXTRACTORS.pop("stage1-fixture", None)


def test_provider_rejects_unknown_and_mismatched_languages_before_selection(tmp_path: Path) -> None:
    snapshot = _snapshot(tmp_path, {"src/example.js": b"export const x = 1;\n"})

    with pytest.raises(BTSError) as unknown:
        make_graph_provider(snapshot, "kotlin", _policy())
    assert unknown.value.reason is BTSRejectReason.REJECT_UNSUPPORTED_CONSTRUCT
    with pytest.raises(BTSError) as mismatch:
        make_graph_provider(snapshot, "typescript", _policy("javascript"))
    assert mismatch.value.reason is BTSRejectReason.REJECT_PROVENANCE_MISMATCH


def test_provider_never_uses_a_different_language_producer(tmp_path: Path) -> None:
    called = False

    def javascript_only(request: GraphExtractionRequest):
        nonlocal called
        called = True
        raise AssertionError(request)

    previous = register_graph_extractor("javascript", javascript_only)
    try:
        snapshot = _snapshot(tmp_path, {"src/example.ts": b"export const x = 1;\n"})
        provider = make_graph_provider(snapshot, "typescript", _policy("typescript"))
        with pytest.raises(BTSError):
            provider(snapshot.source_root)
        assert not called
    finally:
        assert previous is not None
        register_graph_extractor("javascript", previous)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("schema_version", "unknown"),
        ("requirements_lock_digest", "not-a-digest"),
        ("query_sha256", "A" * 64),
        ("max_files", True),
        ("max_files", 0),
        ("max_edges", -1),
    ],
)
def test_policy_rejects_malformed_identity_and_limits(field: str, value: object) -> None:
    # Rebuild from the public builder so every mutation is validated at the
    # same construction boundary as production policy loading.
    base = {
        name: getattr(_policy(), name)
        for name in GraphExtractionPolicy.__dataclass_fields__
        if name != "policy_digest"
    }
    base[field] = value
    with pytest.raises(BTSError):
        build_graph_extraction_policy(**base)


def test_policy_digest_is_canonical_and_tampering_is_rejected() -> None:
    policy = _policy()
    assert compute_policy_digest(policy) == policy.policy_digest
    values = {
        name: getattr(policy, name)
        for name in GraphExtractionPolicy.__dataclass_fields__
        if name != "policy_digest"
    }
    values["max_edges"] = 101
    with pytest.raises(BTSError) as rejected:
        GraphExtractionPolicy(**values, policy_digest=policy.policy_digest)
    assert rejected.value.evidence.detail_code == "tree_sitter_policy_digest_mismatch_v1"


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("runtime_version", "0.25.1"),
        ("grammar_version", "0.24.9"),
        ("grammar_factory", "language_typescript"),
    ],
)
def test_policy_rejects_identity_that_does_not_match_the_pinned_tuple(field: str, value: object) -> None:
    with pytest.raises(BTSError) as rejected:
        _policy(**{field: value})

    assert rejected.value.reason is BTSRejectReason.REJECT_PROVENANCE_MISMATCH
    assert rejected.value.evidence.detail_code == "tree_sitter_policy_tuple_mismatch_v1"


def test_policy_matching_the_pinned_tuple_is_accepted() -> None:
    assert _policy().runtime_version == TREE_SITTER_PINS["tree-sitter"]


def test_policy_rejects_runtime_distribution_mismatch_without_wheels() -> None:
    with pytest.raises(BTSError) as rejected:
        _policy(runtime_distribution="caller-selected-runtime")
    assert rejected.value.evidence.detail_code == "tree_sitter_policy_distribution_mismatch_v1"


def test_policy_rejects_grammar_distribution_mismatch_without_wheels() -> None:
    with pytest.raises(BTSError) as rejected:
        _policy(grammar_distribution="caller-selected-grammar")
    assert rejected.value.evidence.detail_code == "tree_sitter_policy_distribution_mismatch_v1"


def test_request_rejects_unmatched_duplicate_unsorted_empty_and_non_source_records(tmp_path: Path) -> None:
    policy = _policy()
    with pytest.raises(BTSError):
        GraphExtractionRequest("typescript", tmp_path, (_source(),), policy)
    with pytest.raises(BTSError):
        GraphExtractionRequest("javascript", tmp_path, (_source(), _source()), policy)
    with pytest.raises(BTSError):
        GraphExtractionRequest("javascript", tmp_path, (_source("z.js"), _source("a.js")), policy)
    with pytest.raises(BTSError):
        GraphExtractionRequest("javascript", tmp_path, (), policy)
    with pytest.raises(BTSError):
        GraphExtractionRequest("javascript", tmp_path, (_source(), object()), policy)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    ("language", "path"),
    [("javascript", "src/example.js"), ("typescript", "src/example.ts"), ("rust", "src/example.rs"), ("go", "src/example.go")],
)
def test_missing_tree_sitter_extra_is_a_distinct_typed_failure(tmp_path: Path, language: str, path: str) -> None:
    snapshot = _snapshot(tmp_path, {path: b"placeholder\n"})
    provider = make_graph_provider(snapshot, language, _policy(language))

    if importlib.util.find_spec("tree_sitter") is None:
        with pytest.raises(BTSError) as rejected:
            provider(snapshot.source_root)
        assert rejected.value.reason is BTSRejectReason.REJECT_UNSUPPORTED_EXTRA
        assert rejected.value.evidence.detail_code == "tree_sitter_extra_missing_v1"
    else:
        # Test-only stubs make this independent of host grammar installation.
        with _native_tree_sitter_stubs(), pytest.raises(BTSError) as rejected:
            provider(snapshot.source_root)
        assert rejected.value.reason is BTSRejectReason.REJECT_PROVENANCE_MISMATCH
        assert rejected.value.evidence.detail_code == "tree_sitter_lock_unavailable_v1"


def test_validation_then_producer_identity_then_extra_lock_digest_coverage_and_extract_ordering(tmp_path: Path) -> None:
    lock_text = _lock()
    policy = _policy(requirements_lock_digest=requirements_lock_digest(lock_text))
    snapshot = _snapshot(tmp_path, {"src/example.js": b"export const x = 1;\n"})

    with _native_tree_sitter_stubs():
        # The built-in module is stdlib-safe to import, so a producer mismatch
        # now rejects before optional-native loading and every lock stage.
        with pytest.raises(BTSError) as identity:
            make_graph_provider(snapshot, "javascript", _policy(producer_version="wrong"))(snapshot.source_root)
        assert identity.value.evidence.detail_code == "tree_sitter_policy_producer_mismatch_v1"
        with pytest.raises(BTSError) as no_lock:
            make_graph_provider(snapshot, "javascript", policy)(snapshot.source_root)
        assert no_lock.value.evidence.detail_code == "tree_sitter_lock_unavailable_v1"
        with pytest.raises(BTSError) as wrong_digest:
            make_graph_provider(snapshot, "javascript", policy, requirements_lock_text="wrong")(snapshot.source_root)
        assert wrong_digest.value.evidence.detail_code == "tree_sitter_lock_digest_mismatch_v1"
        with pytest.raises(BTSError) as staged_boundary:
            make_graph_provider(snapshot, "javascript", policy, requirements_lock_text=lock_text)(snapshot.source_root)
    if importlib.util.find_spec("tree_sitter") is None:
        assert staged_boundary.value.reason is BTSRejectReason.REJECT_PROVENANCE_MISMATCH
        assert staged_boundary.value.evidence.detail_code == "tree_sitter_runtime_version_mismatch_v1"
    else:
        assert staged_boundary.value.reason is BTSRejectReason.REJECT_UNSUPPORTED_EXTRA
        assert staged_boundary.value.evidence.detail_code == "tree_sitter_extra_broken_v1"


def test_broken_optional_extra_import_is_typed_and_preserves_cause(monkeypatch: pytest.MonkeyPatch) -> None:
    cause = RuntimeError("broken native binding")

    def broken_import(_name: str):
        raise cause

    monkeypatch.setattr(importlib, "import_module", broken_import)
    with pytest.raises(BTSError) as rejected:
        require_tree_sitter_extra("javascript")
    assert rejected.value.reason is BTSRejectReason.REJECT_UNSUPPORTED_EXTRA
    assert rejected.value.evidence.detail_code == "tree_sitter_extra_broken_v1"
    assert rejected.value.__cause__ is cause


def test_platform_lock_preflight_accepts_complete_tuple_and_rejects_gaps() -> None:
    complete = _lock()
    assert_platform_wheel_coverage(complete, python_tag="cp311", platform_tags=("manylinux_2_17_x86_64",))
    missing = complete.replace("tree-sitter-go==0.25.0", "tree-sitter-go-missing==0.25.0")
    no_hash = complete.replace("    --hash=sha256:0000000000000000000000000000000000000000000000000000000000000001", "")
    wrong_version = complete.replace("tree-sitter==0.25.2", "tree-sitter==9.9.9")
    for candidate in (missing, no_hash, wrong_version):
        with pytest.raises(BTSError) as rejected:
            assert_platform_wheel_coverage(candidate, python_tag="cp311", platform_tags=("manylinux_2_17_x86_64",))
        assert rejected.value.reason is BTSRejectReason.REJECT_PROVENANCE_MISMATCH
        assert rejected.value.evidence.detail_code == "tree_sitter_platform_hash_unavailable_v1"


def test_platform_lock_preflight_accepts_single_line_hashes() -> None:
    lock_text = "\n".join(
        f"{name}=={version} --hash=sha256:{index:064x}"
        for index, (name, version) in enumerate(sorted(TREE_SITTER_PINS.items()), start=1)
    )

    assert_platform_wheel_coverage(lock_text, python_tag="cp311", platform_tags=("manylinux_2_17_x86_64",))


def test_platform_lock_preflight_accepts_mixed_same_line_and_continuation_hashes() -> None:
    lock_text = "\n".join(
        (
            f"{name}=={version} \\\n+    --hash=sha256:{index:064x}"
            if index % 2
            else f"{name}=={version} --hash=sha256:{index:064x}"
        )
        for index, (name, version) in enumerate(sorted(TREE_SITTER_PINS.items()), start=1)
    ).replace("\n+", "\n")

    assert_platform_wheel_coverage(lock_text, python_tag="cp311", platform_tags=("manylinux_2_17_x86_64",))


def test_platform_lock_preflight_rejects_inline_comment_only_hash() -> None:
    lines = [
        f"{name}=={version} --hash=sha256:{index:064x}"
        for index, (name, version) in enumerate(sorted(TREE_SITTER_PINS.items()), start=1)
    ]
    lines[0] = f"tree-sitter=={TREE_SITTER_PINS['tree-sitter']} # --hash=sha256:{1:064x}"

    with pytest.raises(BTSError) as rejected:
        assert_platform_wheel_coverage("\n".join(lines), python_tag="cp311", platform_tags=("manylinux_2_17_x86_64",))

    assert rejected.value.reason is BTSRejectReason.REJECT_PROVENANCE_MISMATCH
    assert rejected.value.evidence.detail_code == "tree_sitter_platform_hash_unavailable_v1"


def test_platform_lock_preflight_rejects_new_requirement_inside_open_continuation() -> None:
    lines = [
        f"tree-sitter=={TREE_SITTER_PINS['tree-sitter']} --hash=sha256:{1:064x} \\",
        f"tree-sitter-javascript=={TREE_SITTER_PINS['tree-sitter-javascript']} --hash=sha256:{2:064x}",
        *(
            f"{name}=={version} --hash=sha256:{index:064x}"
            for index, (name, version) in enumerate(sorted(TREE_SITTER_PINS.items()), start=3)
            if name not in {"tree-sitter", "tree-sitter-javascript"}
        ),
    ]

    with pytest.raises(BTSError) as rejected:
        assert_platform_wheel_coverage("\n".join(lines), python_tag="cp311", platform_tags=("manylinux_2_17_x86_64",))

    assert rejected.value.reason is BTSRejectReason.REJECT_PROVENANCE_MISMATCH
    assert rejected.value.evidence.detail_code == "tree_sitter_platform_hash_unavailable_v1"


def test_platform_lock_preflight_rejects_orphan_hash_line() -> None:
    lock_text = "\n".join(
        f"{name}=={version} --hash=sha256:{index:064x}"
        for index, (name, version) in enumerate(sorted(TREE_SITTER_PINS.items()), start=1)
    )
    lock_text += f"\n--hash=sha256:{99:064x}"

    with pytest.raises(BTSError) as rejected:
        assert_platform_wheel_coverage(lock_text, python_tag="cp311", platform_tags=("manylinux_2_17_x86_64",))

    assert rejected.value.reason is BTSRejectReason.REJECT_PROVENANCE_MISMATCH
    assert rejected.value.evidence.detail_code == "tree_sitter_platform_hash_unavailable_v1"


def test_real_tree_sitter_lock_and_extra_match_the_pinned_tuple() -> None:
    root = Path(__file__).parents[1]
    lock_text = (root / "requirements-tree-sitter.lock").read_text(encoding="utf-8")
    project = tomllib.loads((root / "pyproject.toml").read_text(encoding="utf-8"))
    extra = project["project"]["optional-dependencies"]["tree-sitter"]
    lock_pins = {
        line.split("==", 1)[0]: line.split("==", 1)[1].split(maxsplit=1)[0]
        for line in lock_text.splitlines()
        if "==" in line and not line.startswith("#")
    }
    extra_pins = {item.split("==", 1)[0]: item.split("==", 1)[1] for item in extra}

    assert lock_pins == extra_pins == TREE_SITTER_PINS
    assert_platform_wheel_coverage(lock_text, python_tag="cp311", platform_tags=("manylinux_2_17_x86_64",)) is None
    assert requirements_lock_digest(lock_text) == "1ebafa0eab2f6e47956ff88886eeddf61fe706cc20c411f3bd8b9866616953ee"


@pytest.mark.parametrize("seed", ["0", "1", "42"])
def test_scope_construction_is_byte_identical_across_hash_seeds(seed: str) -> None:
    script = textwrap.dedent(
        """
        import json
        import tempfile
        from pathlib import Path
        from leitir.bts import DonorSnapshot
        from leitir.graph.policy import GRAPH_EXTRACTION_POLICY_SCHEMA_VERSION, SOURCE_SELECTION_VERSION, build_graph_extraction_policy
        from leitir.graph.registry import _build_request
        from leitir.treehash import FULL, TREE_HASH_ALGORITHM, compute_materialized_tree_hash
        root = Path(tempfile.mkdtemp())
        source = root / 'source'
        for name in ('z.js', 'a.js'):
            target = source / 'src' / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(b'export const value = 1;\\n')
        digest, scope = compute_materialized_tree_hash(source)
        snapshot = DonorSnapshot('owner/repo', 'a'*40, 'git-commit', 'exact', digest, TREE_HASH_ALGORITHM, FULL, root, source)
        policy = build_graph_extraction_policy(schema_version=GRAPH_EXTRACTION_POLICY_SCHEMA_VERSION, authority='a', policy_id='p', language='javascript', requirements_lock_digest='1'*64, runtime_distribution='tree-sitter', runtime_version='0.25.2', grammar_distribution='tree-sitter-javascript', grammar_version='0.25.0', grammar_factory='language', grammar_abi_version=15, query_id='q', query_sha256='2'*64, producer_id='p', producer_version='1', resolution_rule_version='r', source_selection_version=SOURCE_SELECTION_VERSION, max_files=10, max_file_bytes=100, max_tree_nodes_per_file=10, max_query_matches=10, max_symbols=10, max_edges=10, max_work_units=10)
        request = _build_request(snapshot, 'javascript', policy)
        print(json.dumps([item.path for item in request.source_files], separators=(',', ':')))
        """
    )
    environment = {**os.environ, "PYTHONHASHSEED": seed}
    actual = subprocess.check_output([sys.executable, "-c", script], env=environment).replace(b"\r\n", b"\n")
    baseline = subprocess.check_output([sys.executable, "-c", script], env={**os.environ, "PYTHONHASHSEED": "0"}).replace(b"\r\n", b"\n")
    assert actual == baseline == b'["src/a.js","src/z.js"]\n'


def test_scope_file_cap_rejects_without_partial_graph(tmp_path: Path) -> None:
    snapshot = _snapshot(tmp_path, {"src/a.js": b"a\n", "src/b.js": b"b\n"})
    provider = make_graph_provider(snapshot, "javascript", _policy(max_files=1))

    with pytest.raises(BTSError) as rejected:
        provider(snapshot.source_root)

    assert rejected.value.reason is BTSRejectReason.REJECT_EXTRACTION_BUDGET
    assert rejected.value.evidence.detail_code == "tree_sitter_max_files_v1"


def test_scope_byte_cap_rejects_without_partial_graph(tmp_path: Path) -> None:
    snapshot = _snapshot(tmp_path, {"src/too-large.js": b"0123456789"})
    provider = make_graph_provider(snapshot, "javascript", _policy(max_file_bytes=9))

    with pytest.raises(BTSError) as rejected:
        provider(snapshot.source_root)

    assert rejected.value.reason is BTSRejectReason.REJECT_EXTRACTION_BUDGET
    assert rejected.value.evidence.detail_code == "tree_sitter_max_file_bytes_v1"


@pytest.mark.parametrize("link_name", ["0-directory-link", "z-directory-link"])
def test_scope_rejects_symlinked_directory_deterministically(tmp_path: Path, link_name: str) -> None:
    snapshot = _snapshot(tmp_path, {"src/example.js": b"export const x = 1;\n"})
    outside = tmp_path / "outside-directory"
    outside.mkdir()
    try:
        (snapshot.source_root / link_name).symlink_to(outside, target_is_directory=True)
    except OSError as exc:
        pytest.skip(f"symlinks unavailable: {exc}")
    provider = make_graph_provider(snapshot, "javascript", _policy())

    with pytest.raises(BTSError) as rejected:
        provider(snapshot.source_root)

    assert rejected.value.reason is BTSRejectReason.REJECT_PROVENANCE_MISMATCH
    assert rejected.value.evidence.detail_code == "tree_sitter_source_symlink_v1"


@pytest.mark.parametrize("link_name", ["0-file-link.js", "z-file-link.js"])
def test_scope_rejects_symlinked_file_deterministically(tmp_path: Path, link_name: str) -> None:
    snapshot = _snapshot(tmp_path, {"src/example.js": b"export const x = 1;\n"})
    outside = tmp_path / "outside-file.js"
    outside.write_bytes(b"outside\n")
    try:
        (snapshot.source_root / link_name).symlink_to(outside)
    except OSError as exc:
        pytest.skip(f"symlinks unavailable: {exc}")
    provider = make_graph_provider(snapshot, "javascript", _policy())

    with pytest.raises(BTSError) as rejected:
        provider(snapshot.source_root)

    assert rejected.value.reason is BTSRejectReason.REJECT_PROVENANCE_MISMATCH
    assert rejected.value.evidence.detail_code == "tree_sitter_source_symlink_v1"


def test_scope_rejects_a_symlinked_source_root(tmp_path: Path) -> None:
    materialized_root = tmp_path / "materialized"
    real_root = materialized_root / "real-source"
    real_root.mkdir(parents=True)
    (real_root / "example.js").write_bytes(b"export const x = 1;\n")
    tree_hash, scope = compute_materialized_tree_hash(real_root)
    source_root = materialized_root / "source"
    try:
        source_root.symlink_to(real_root, target_is_directory=True)
    except OSError as exc:
        pytest.skip(f"symlinks unavailable: {exc}")
    snapshot = DonorSnapshot(
        "owner/repo", "a" * 40, "git-commit", "exact", tree_hash,
        TREE_HASH_ALGORITHM, scope, materialized_root, source_root,
    )

    with pytest.raises(BTSError) as rejected:
        make_graph_provider(snapshot, "javascript", _policy())(snapshot.source_root)

    assert rejected.value.reason is BTSRejectReason.REJECT_PROVENANCE_MISMATCH
    assert rejected.value.evidence.detail_code == "tree_sitter_source_symlink_v1"


def test_unsupported_extra_reason_round_trips_through_bts_json() -> None:
    original = BTSError(BTSRejectReason.REJECT_UNSUPPORTED_EXTRA, "missing optional extra", detail_code="tree_sitter_extra_missing_v1")

    assert BTSError.from_json(original.to_json()) == original


# Stage-2 JavaScript kernel and exemplar.  Native parsing tests remain gated so
# the default stdlib-only CI job does not import optional wheels.
_TREE_SITTER = pytest.mark.skipif(importlib.util.find_spec("tree_sitter") is None, reason="requires tree-sitter extra")
_JAVASCRIPT_FIXTURE = Path(__file__).parent / "fixtures" / "graph" / "javascript"
_JAVASCRIPT_GOLDEN = _JAVASCRIPT_FIXTURE / "golden.json"


def test_javascript_query_identity_and_fixture_utf8_are_stable() -> None:
    assert QUERY_ID == "javascript-graph-query-v1"
    assert query_sha256(QUERY_TEXT) == "1f4f5077a0fe5920f52785a5cf81eac089f8259d1a5912fb90d52cd32b4488f6"
    for path in sorted(_JAVASCRIPT_FIXTURE.glob("*.js")):
        path.read_text(encoding="utf-8")


def test_tree_sitter_byte_coordinates_preserve_utf8_bytes() -> None:
    # b"é" occupies columns 1..3 and b"😀" occupies columns 4..8, not one
    # Unicode code-point column each.  The inverse proves no decode occurred.
    source = "aé😀\nZ".encode()
    assert byte_point(source, 0) == (1, 0)
    assert byte_point(source, 3) == (1, 3)
    assert byte_point(source, 7) == (1, 7)
    assert byte_point(source, 8) == (2, 0)
    assert all(byte_offset(source, *byte_point(source, offset)) == offset for offset in range(len(source) + 1))
    base = SourceRef("owner/repo", "a" * 40, "src/emoji.js", "b" * 40, 1, 0, 1, 0)
    assert source_ref(base, source, 1, 7).start_col == 1
    assert source_ref(base, source, 1, 7).end_col == 7


def test_tree_sitter_byte_coordinates_preserve_crlf_bytes() -> None:
    source = b"a\r\nb"
    # ADR-0012 defines byte columns: CR is a byte on line one, and LF starts
    # the next line rather than making CR disappear from the preceding column.
    assert byte_point(source, 1) == (1, 1)
    assert byte_point(source, 2) == (1, 2)
    assert byte_point(source, 3) == (2, 0)
    assert byte_offset(source, 1, 2) == 2
    assert byte_offset(source, 2, 0) == 3


def test_tree_sitter_kernel_defaults_match_adr_0012_oq3_table() -> None:
    # ADR-0012 OQ3's ratified limits table is the normative source.
    assert (
        DEFAULT_MAX_FILES,
        DEFAULT_MAX_FILE_BYTES,
        DEFAULT_MAX_TREE_NODES_PER_FILE,
        DEFAULT_MAX_QUERY_MATCHES,
        DEFAULT_MAX_SYMBOLS,
        DEFAULT_MAX_EDGES,
        DEFAULT_MAX_WORK_UNITS,
    ) == (2_000, 2_097_152, 250_000, 1_100_000, 200_000, 900_000, 10_000)


def test_javascript_query_drift_rejects_before_native_import(tmp_path: Path) -> None:
    request = GraphExtractionRequest("javascript", tmp_path, (_source(),), _policy(query_sha256=query_sha256("(identifier) @x\n")))
    from leitir.graph.javascript import extract_graph

    with pytest.raises(BTSError) as rejected:
        extract_graph(request)
    assert rejected.value.reason is BTSRejectReason.REJECT_PROVENANCE_MISMATCH
    assert rejected.value.evidence.detail_code == "tree_sitter_query_identity_mismatch_v1"


def test_javascript_producer_policy_mismatch_rejects_before_native_import(tmp_path: Path) -> None:
    request = GraphExtractionRequest("javascript", tmp_path, (_source(),), _policy(producer_version="wrong"))
    from leitir.graph.javascript import extract_graph

    with pytest.raises(BTSError) as rejected:
        extract_graph(request)
    assert rejected.value.evidence.detail_code == "tree_sitter_policy_producer_mismatch_v1"


def _fixture_provider(tmp_path: Path, **policy_overrides: object):
    files = {path.name: path.read_bytes() for path in sorted(_JAVASCRIPT_FIXTURE.glob("*.js"))}
    snapshot = _snapshot(tmp_path, files)
    lock = _lock()
    limits: dict[str, object] = {
        "max_file_bytes": 10_000,
        "max_tree_nodes_per_file": 10_000,
        "max_query_matches": 10_000,
        "max_symbols": 10_000,
        "max_edges": 10_000,
    }
    limits.update(policy_overrides)
    policy = _policy(requirements_lock_digest=requirements_lock_digest(lock), **limits)
    return snapshot, make_graph_provider(snapshot, "javascript", policy, requirements_lock_text=lock)


def _fixture_graph(tmp_path: Path, files: dict[str, bytes] | None = None):
    if files is None:
        return _fixture_provider(tmp_path)
    snapshot = _snapshot(tmp_path, files)
    lock = _lock()
    policy = _policy(requirements_lock_digest=requirements_lock_digest(lock), max_file_bytes=10_000, max_tree_nodes_per_file=10_000, max_query_matches=10_000, max_symbols=10_000, max_edges=10_000)
    return snapshot, make_graph_provider(snapshot, "javascript", policy, requirements_lock_text=lock)


@_TREE_SITTER
def test_javascript_fixture_extracts_proven_edges_and_pairs_negative_evidence(tmp_path: Path) -> None:
    snapshot, provider = _fixture_provider(tmp_path)
    graph = provider(snapshot.source_root)
    assert {(edge.kind.value, edge.source.qualified_name, edge.target.qualified_name) for edge in graph.edges} == {
        ("imports", "child", "base"),
        ("imports", "shadow", "base"),
        ("inherits", "child.Child", "base.Base"),
        ("calls", "child.Child.method", "base.greet"),
        ("raises", "child.Child.method", "base.Base"),
        ("instantiates", "child.Child.method", "base.Base"),
        ("calls", "shadow.control", "base.greet"),
        ("instantiates", "shadow.control", "base.Base"),
        ("instantiates", "shadow.another", "base.Base"),
        ("instantiates", "shadow.nested", "base.Base"),
    }
    assert {node.id.qualified_name for node in graph.nodes if node.id.kind.value == "module"} == {"base", "child", "negative", "shadow"}
    details = {item.detail_code for item in graph.unresolved}
    assert {"tree_sitter_star_import_v1", "tree_sitter_reexport_v1", "tree_sitter_dynamic_import_v1", "tree_sitter_receiver_dispatch_v1", "tree_sitter_dynamic_base_v1", "tree_sitter_unresolved_throw_v1", "tree_sitter_ambiguous_callee_binding_v1", "tree_sitter_dynamic_instantiation_v1"} <= details
    assert {(item.detail_code, item.provenance.site.path) for item in graph.unresolved} == {(item.detail_code, item.path) for item in graph.coverage.blockers}
    assert tuple(item.path for item in graph.coverage.files) == ("base.js", "child.js", "negative.js", "shadow.js")
    assert graph.coverage.parsed_files == graph.coverage.files
    assert sum(edge.kind.value == "imports" and edge.provenance.site.start_line == 2 for edge in graph.edges) == 1
    instantiates = next(edge for edge in graph.edges if edge.kind.value == "instantiates")
    assert (instantiates.provenance.site.path, instantiates.provenance.site.start_line, instantiates.provenance.site.start_col) == ("child.js", 7, 8)
    assert (instantiates.provenance.binding.path, instantiates.provenance.binding.start_line) == ("child.js", 1)
    assert {(item.kind.value, item.detail_code, item.provenance.site.path, item.provenance.site.start_line) for item in graph.unresolved if item.kind.value == "instantiates"} == {
        ("instantiates", "tree_sitter_dynamic_instantiation_v1", "negative.js", 9),
        ("instantiates", "tree_sitter_unresolved_instantiation_v1", "negative.js", 10),
        ("instantiates", "tree_sitter_unresolved_instantiation_v1", "negative.js", 13),
        ("instantiates", "tree_sitter_shadowed_binding_v1", "shadow.js", 3),
        ("instantiates", "tree_sitter_shadowed_binding_v1", "shadow.js", 4),
        ("instantiates", "tree_sitter_shadowed_binding_v1", "shadow.js", 9),
        ("instantiates", "tree_sitter_shadowed_binding_v1", "shadow.js", 10),
        ("instantiates", "tree_sitter_shadowed_binding_v1", "shadow.js", 11),
    }


@_TREE_SITTER
def test_javascript_fixture_matches_golden_graph(tmp_path: Path) -> None:
    # Regenerate: PYTHONPATH=src /tmp/opencode/tsint-venv/bin/python -c 'import runpy,tempfile;from pathlib import Path;v=runpy.run_path("tests/test_graph_polyglot.py");s,p=v["_fixture_provider"](Path(tempfile.mkdtemp()));Path("tests/fixtures/graph/javascript/golden.json").write_text(p(s.source_root).to_json(),encoding="utf-8")'
    snapshot, provider = _fixture_provider(tmp_path)
    assert provider(snapshot.source_root).to_json() == _JAVASCRIPT_GOLDEN.read_text(encoding="utf-8")


@_TREE_SITTER
def test_javascript_fixture_tamper_changes_golden_in_expected_way(tmp_path: Path) -> None:
    files = {path.name: path.read_bytes() for path in sorted(_JAVASCRIPT_FIXTURE.glob("*.js"))}
    files["child.js"] += b'\nimport { Base as AnotherBase } from "./base.js";\n'
    snapshot, provider = _fixture_graph(tmp_path, files)
    graph = provider(snapshot.source_root)
    assert graph.to_json() != _JAVASCRIPT_GOLDEN.read_text(encoding="utf-8")
    assert sum(edge.kind.value == "imports" and edge.source.qualified_name == "child" and edge.target.qualified_name == "base" for edge in graph.edges) == 3


@_TREE_SITTER
def test_javascript_fixture_json_is_hash_seed_deterministic() -> None:
    script = textwrap.dedent(
        f"""
        import runpy
        import tempfile
        from pathlib import Path
        values = runpy.run_path({str(Path(__file__).resolve())!r})
        snapshot, provider = values["_fixture_provider"](Path(tempfile.mkdtemp()))
        print(provider(snapshot.source_root).to_json(), end="")
        """
    )
    outputs = [
        subprocess.check_output([sys.executable, "-c", script], env={**os.environ, "PYTHONHASHSEED": seed})
        for seed in ("0", "1", "42")
    ]
    assert outputs[0] == outputs[1] == outputs[2] == _JAVASCRIPT_GOLDEN.read_bytes()


@_TREE_SITTER
@pytest.mark.parametrize(("field", "value", "detail"), [("max_tree_nodes_per_file", 1, "tree_sitter_max_tree_nodes_v1"), ("max_query_matches", 1, "tree_sitter_max_query_matches_v1"), ("max_edges", 1, "tree_sitter_max_edges_v1")])
def test_javascript_budgets_fail_without_partial_graph(tmp_path: Path, field: str, value: int, detail: str) -> None:
    snapshot, provider = _fixture_provider(tmp_path, **{field: value})
    with pytest.raises(BTSError) as rejected:
        provider(snapshot.source_root)
    assert rejected.value.reason is BTSRejectReason.REJECT_EXTRACTION_BUDGET
    assert rejected.value.evidence.detail_code == detail


@_TREE_SITTER
def test_javascript_unresolved_output_budget_fails_without_partial_graph(tmp_path: Path) -> None:
    files = {
        "base.js": b"export function f() {}\n",
        "child.js": b'import { f } from "./base.js";\nfunction caller() { receiver.f(); receiver.f(); receiver.f(); }\n',
    }
    snapshot, provider = _fixture_graph(tmp_path, files)
    # Rebuild only to lower the output-record budget: the static import plus two
    # unresolved member calls consumes the whole budget before the third call.
    lock = _lock()
    provider = make_graph_provider(snapshot, "javascript", _policy(requirements_lock_digest=requirements_lock_digest(lock), max_file_bytes=10_000, max_tree_nodes_per_file=10_000, max_query_matches=10_000, max_symbols=10_000, max_edges=2), requirements_lock_text=lock)
    with pytest.raises(BTSError) as rejected:
        provider(snapshot.source_root)
    assert rejected.value.evidence.detail_code == "tree_sitter_max_edges_v1"


@_TREE_SITTER
def test_javascript_tampered_declared_bytes_reject_before_parsing(tmp_path: Path) -> None:
    snapshot, _provider = _fixture_provider(tmp_path)
    policy = _policy(requirements_lock_digest=requirements_lock_digest(_lock()), max_file_bytes=10_000, max_tree_nodes_per_file=10_000, max_query_matches=10_000, max_symbols=10_000, max_edges=10_000)
    request = graph_registry._build_request(snapshot, "javascript", policy)
    (snapshot.source_root / "child.js").write_bytes(b"export function changed() {}\n")
    from leitir.graph.javascript import extract_graph

    with pytest.raises(BTSError) as rejected:
        extract_graph(request)
    assert rejected.value.evidence.detail_code == "tree_sitter_source_bytes_changed_v1"


@_TREE_SITTER
@pytest.mark.parametrize(("distribution", "version", "detail"), [
    ("tree-sitter", "wrong", "tree_sitter_runtime_version_mismatch_v1"),
    ("tree-sitter-javascript", "wrong", "tree_sitter_grammar_version_mismatch_v1"),
])
def test_javascript_native_distribution_identity_is_enforced(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, distribution: str, version: str, detail: str) -> None:
    snapshot, provider = _fixture_provider(tmp_path)
    import leitir.graph.ts_kernel as kernel

    actual_version = kernel.importlib.metadata.version
    monkeypatch.setattr(kernel.importlib.metadata, "version", lambda name: version if name == distribution else actual_version(name))
    with pytest.raises(BTSError) as rejected:
        provider(snapshot.source_root)
    assert rejected.value.evidence.detail_code == detail


@_TREE_SITTER
def test_javascript_shadowed_bindings_never_resolve_imports(tmp_path: Path) -> None:
    files = {
        "base.js": b"export class Base {}\nexport function greet() {}\n",
        "child.js": b'''import { Base, greet } from "./base.js";
function param(Base) { new Base(); greet(); }
function local() { let Base; new Base(); }
function callShadow(greet) { greet(); }
function throwShadow(Base) { throw new Base(); }
function control() { new Base(); greet(); }
function outer() { let Base; class Local extends Base {} }
''',
    }
    snapshot, provider = _fixture_graph(tmp_path, files)
    graph = provider(snapshot.source_root)
    assert sum(edge.kind.value == "instantiates" and edge.target.qualified_name == "base.Base" for edge in graph.edges) == 1
    assert sum(edge.kind.value == "calls" and edge.target.qualified_name == "base.greet" for edge in graph.edges) == 2
    shadowed = [item for item in graph.unresolved if item.detail_code == "tree_sitter_shadowed_binding_v1"]
    assert {item.kind.value for item in shadowed} == {"calls", "inherits", "instantiates", "raises"}


@_TREE_SITTER
def test_javascript_block_shadow_named_expression_and_inner_wins(tmp_path: Path) -> None:
    snapshot, provider = _fixture_provider(tmp_path)
    graph = provider(snapshot.source_root)
    shadowed_lines = {
        item.provenance.site.start_line
        for item in graph.unresolved
        if item.kind.value == "instantiates" and item.detail_code == "tree_sitter_shadowed_binding_v1" and item.provenance.site.path == "shadow.js"
    }
    # Root block (9), named function-expression own name (10), and the inner
    # of nested blocks (11) must all win over the imported Base.  `another`
    # proves function-local bindings do not leak into a sibling function.
    assert {9, 10, 11} <= shadowed_lines
    assert ("instantiates", "shadow.another", "base.Base") in {
        (edge.kind.value, edge.source.qualified_name, edge.target.qualified_name)
        for edge in graph.edges
    }


@_TREE_SITTER
def test_javascript_generator_parameters_shadow_imported_calls(tmp_path: Path) -> None:
    snapshot, provider = _fixture_graph(tmp_path, {
        "base.js": b"export function greet() {}\n",
        "child.js": b"import { greet } from './base.js';\nfunction* w(greet) { greet(); }\nasync function* aw(greet) { greet(); }\n",
    })
    graph = provider(snapshot.source_root)
    assert not any(edge.kind.value == "calls" for edge in graph.edges)
    expected_sites = {("child.js", 2), ("child.js", 3)}
    unresolved_sites = [
        (item.provenance.site.path, item.provenance.site.start_line)
        for item in graph.unresolved
        if item.kind.value == "calls" and item.detail_code == "tree_sitter_shadowed_binding_v1"
    ]
    blocker_sites = [
        (item.path, item.start_line)
        for item in graph.coverage.blockers
        if item.detail_code == "tree_sitter_shadowed_binding_v1"
    ]
    assert set(unresolved_sites) == expected_sites
    assert set(blocker_sites) == expected_sites
    assert all(unresolved_sites.count(site) == 1 for site in expected_sites)
    assert all(blocker_sites.count(site) == 1 for site in expected_sites)


@_TREE_SITTER
def test_javascript_abi_mismatch_is_typed(tmp_path: Path) -> None:
    snapshot, provider = _fixture_provider(tmp_path, grammar_abi_version=99)
    with pytest.raises(BTSError) as rejected:
        provider(snapshot.source_root)
    assert rejected.value.evidence.detail_code == "tree_sitter_grammar_abi_mismatch_v1"


@_TREE_SITTER
def test_javascript_parse_error_excludes_file_from_parsed_coverage(tmp_path: Path) -> None:
    snapshot = _snapshot(tmp_path, {"bad.js": b"function broken( {\n"})
    lock = _lock()
    policy = _policy(requirements_lock_digest=requirements_lock_digest(lock), max_file_bytes=10_000)
    graph = make_graph_provider(snapshot, "javascript", policy, requirements_lock_text=lock)(snapshot.source_root)
    assert not graph.nodes
    assert not graph.coverage.parsed_files
    assert [item.detail_code for item in graph.coverage.blockers] == ["tree_sitter_parse_error_v1"]
