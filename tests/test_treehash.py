"""Offline unit tests for leitir.treehash.

Mirrors leitir's existing pytest style (plain functions, tmp_path fixture,
monkeypatch).  No network; all fixtures are built in tmp_path.
"""
from __future__ import annotations

import base64
import hashlib
import os
from pathlib import Path
import sys

import pytest

from leitir import treehash
from leitir.treehash import (
    TreeHashError,
    TreeHashFormatError,
    TreeHashMismatchError,
    TreeHashStructureError,
)


def _make_tree(tmp_path: Path, files: dict[str, bytes]) -> Path:
    root = tmp_path / "src"
    root.mkdir(parents=True)
    for rel, content in files.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(content)
    return root


def _manual_h1(
    root: Path, files: dict[str, bytes], symlinks: dict[str, str] | None = None
) -> str:
    summary = hashlib.sha256()
    symlinks = symlinks or {}
    for rel in sorted(set(files) | set(symlinks)):
        if rel in symlinks:
            linkname = symlinks[rel].encode("utf-8")
            summary.update(hashlib.sha256(linkname).hexdigest().encode("ascii"))
            summary.update(b" -> ")
            summary.update(linkname)
        else:
            summary.update(hashlib.sha256(files[rel]).hexdigest().encode("ascii"))
        summary.update(b"  ")
        summary.update(rel.encode("utf-8"))
        summary.update(b"\n")
    return "h1:" + base64.standard_b64encode(summary.digest()).decode("ascii")


def test_empty_tree_has_stable_digest(tmp_path):
    root = tmp_path / "empty"
    root.mkdir()
    h, scope = treehash.compute_materialized_tree_hash(root)
    assert scope == treehash.FULL
    assert h.startswith("h1:")
    # empty summary -> sha256("") base64
    expected = "h1:" + base64.standard_b64encode(hashlib.sha256(b"").digest()).decode("ascii")
    assert h == expected


def test_single_file_matches_manual_spec(tmp_path):
    files = {"README.md": b"hello world\n"}
    root = _make_tree(tmp_path, files)
    assert treehash.compute_materialized_tree_hash(root) == (
        _manual_h1(root, files), treehash.FULL
    )


def test_nested_files_match_manual_spec(tmp_path):
    files = {
        "README.md": b"hello\n",
        "src/a/b/c.py": b"print('c')\n",
        "src/a/b/__init__.py": b"",
        "src/a.py": b"print('a')\n",
    }
    root = _make_tree(tmp_path, files)
    assert treehash.compute_materialized_tree_hash(root) == (
        _manual_h1(root, files), treehash.FULL
    )


def test_sort_order_is_lexicographic_on_posix_paths(tmp_path):
    # On disk these may enumerate in any order; digest must be stable.
    files_a = {"z.txt": b"z", "a.txt": b"a", "m/b.txt": b"b", "m/a.txt": b"a2"}
    files_b = dict(reversed(list(files_a.items())))
    root_a = _make_tree(tmp_path / "a", files_a)
    root_b = _make_tree(tmp_path / "b", files_b)
    assert treehash.compute_materialized_tree_hash(root_a) == \
           treehash.compute_materialized_tree_hash(root_b)


def test_root_manifest_is_excluded(tmp_path):
    root = tmp_path / "src"
    root.mkdir()
    root.joinpath("file.txt").write_bytes(b"x")
    root.joinpath("leitir-manifest.json").write_bytes(b'{"verified": true}')
    files = {"file.txt": b"x"}
    assert treehash.compute_materialized_tree_hash(root) == (
        _manual_h1(root, files), treehash.FULL
    )


def test_subdir_named_manifest_is_included(tmp_path):
    root = tmp_path / "src"
    root.mkdir()
    root.joinpath("file.txt").write_bytes(b"x")
    root.joinpath("sub").mkdir()
    # A manifest-named file NOT at the root is real source content.
    root.joinpath("sub", "leitir-manifest.json").write_bytes(b"nested")
    files = {"file.txt": b"x", "sub/leitir-manifest.json": b"nested"}
    assert treehash.compute_materialized_tree_hash(root) == (
        _manual_h1(root, files), treehash.FULL
    )


def test_verify_accepts_clean_tree(tmp_path):
    files = {"a.txt": b"a", "b/c.txt": b"c"}
    root = _make_tree(tmp_path, files)
    expected, _scope = treehash.compute_materialized_tree_hash(root)
    treehash.verify_materialized_tree_hash(root, expected)  # no raise


def test_verify_detects_byte_flip(tmp_path):
    files = {"a.txt": b"a", "b/c.txt": b"c"}
    root = _make_tree(tmp_path, files)
    expected, _scope = treehash.compute_materialized_tree_hash(root)
    root.joinpath("a.txt").write_bytes(b"X")
    with pytest.raises(TreeHashMismatchError):
        treehash.verify_materialized_tree_hash(root, expected)


def test_verify_detects_truncation(tmp_path):
    files = {"big.bin": b"0123456789" * 1000}
    root = _make_tree(tmp_path, files)
    expected, _scope = treehash.compute_materialized_tree_hash(root)
    root.joinpath("big.bin").write_bytes(b"0")
    with pytest.raises(TreeHashMismatchError):
        treehash.verify_materialized_tree_hash(root, expected)


def test_verify_detects_added_file(tmp_path):
    files = {"a.txt": b"a"}
    root = _make_tree(tmp_path, files)
    expected, _scope = treehash.compute_materialized_tree_hash(root)
    root.joinpath("injected.txt").write_bytes(b"evil")
    with pytest.raises(TreeHashMismatchError):
        treehash.verify_materialized_tree_hash(root, expected)


def test_verify_detects_deleted_file(tmp_path):
    files = {"a.txt": b"a", "b.txt": b"b"}
    root = _make_tree(tmp_path, files)
    expected, _scope = treehash.compute_materialized_tree_hash(root)
    root.joinpath("b.txt").unlink()
    with pytest.raises(TreeHashMismatchError):
        treehash.verify_materialized_tree_hash(root, expected)


def test_verify_rejects_missing_prefix(tmp_path):
    root = _make_tree(tmp_path, {"a.txt": b"a"})
    with pytest.raises(TreeHashFormatError):
        treehash.verify_materialized_tree_hash(root, "sha256:abcdef")


def test_verify_rejects_none(tmp_path):
    root = _make_tree(tmp_path, {"a.txt": b"a"})
    with pytest.raises(TreeHashFormatError):
        treehash.verify_materialized_tree_hash(root, None)  # type: ignore[arg-type]


def test_verify_rejects_non_string(tmp_path):
    root = _make_tree(tmp_path, {"a.txt": b"a"})
    with pytest.raises(TreeHashFormatError):
        treehash.verify_materialized_tree_hash(root, 123)  # type: ignore[arg-type]


def test_verify_rejects_malformed_base64(tmp_path):
    root = _make_tree(tmp_path, {"a.txt": b"a"})
    with pytest.raises(TreeHashFormatError):
        treehash.verify_materialized_tree_hash(root, "h1:not-base64!!!")


def test_verify_rejects_non_canonical_base64(tmp_path):
    root = _make_tree(tmp_path, {"a.txt": b"a"})
    # Same bytes encoded with non-standard altchars or extra whitespace.
    real, _scope = treehash.compute_materialized_tree_hash(root)
    bad = "h1:" + real[3:].replace("+", "-").replace("/", "_")
    with pytest.raises(TreeHashFormatError):
        treehash.verify_materialized_tree_hash(root, bad)


def test_verify_rejects_wrong_but_well_formed_digest(tmp_path):
    root = _make_tree(tmp_path, {"a.txt": b"a"})
    bogus = "h1:" + base64.standard_b64encode(b"\x00" * 32).decode("ascii")
    with pytest.raises(TreeHashMismatchError):
        treehash.verify_materialized_tree_hash(root, bogus)


def test_symlink_inside_tree_matches_extended_manual_format(tmp_path):
    root = _make_tree(tmp_path, {"a.txt": b"a"})
    (root / "link.txt").symlink_to("a.txt")
    assert treehash.compute_materialized_tree_hash(root) == (
        _manual_h1(root, {"a.txt": b"a"}, {"link.txt": "a.txt"}),
        treehash.FULL,
    )


def test_symlinked_directory_is_hashed_without_following_it(tmp_path):
    root = _make_tree(tmp_path, {"a.txt": b"a"})
    target = tmp_path / "external"
    target.mkdir()
    target.joinpath("secret.txt").write_bytes(b"exfiltrated")
    (root / "sub").symlink_to(target)
    assert treehash.compute_materialized_tree_hash(root) == (
        _manual_h1(root, {"a.txt": b"a"}, {"sub": str(target)}),
        treehash.FULL,
    )


def test_symlink_target_tampering_is_detected(tmp_path):
    root = _make_tree(tmp_path, {"a.txt": b"a", "b.txt": b"b"})
    link = root / "link.txt"
    link.symlink_to("a.txt")
    expected, _scope = treehash.compute_materialized_tree_hash(root)
    link.unlink()
    link.symlink_to("b.txt")
    with pytest.raises(TreeHashMismatchError):
        treehash.verify_materialized_tree_hash(root, expected)


def test_empty_symlink_target_is_supported_by_record_format(tmp_path, monkeypatch):
    root = _make_tree(tmp_path, {"a.txt": b"a"})
    link = root / "link.txt"
    link.symlink_to("a.txt")
    real_readlink = os.readlink
    monkeypatch.setattr(
        os,
        "readlink",
        lambda path: "" if Path(os.fsdecode(path)) == link else real_readlink(path),
    )
    assert treehash.compute_materialized_tree_hash(root) == (
        _manual_h1(root, {"a.txt": b"a"}, {"link.txt": ""}),
        treehash.FULL,
    )


def test_symlink_target_with_newline_is_rejected(tmp_path, monkeypatch):
    root = _make_tree(tmp_path, {"a.txt": b"a"})
    link = root / "link.txt"
    link.symlink_to("a.txt")
    monkeypatch.setattr(os, "readlink", lambda _path: "a\nb")
    with pytest.raises(TreeHashStructureError, match="linkname contains a newline"):
        treehash.compute_materialized_tree_hash(root)


def test_symlink_target_with_non_utf8_bytes_is_wrapped(tmp_path):
    if sys.platform == "win32":
        pytest.skip(
            "non-UTF-8 filenames are not representable on Windows via the standard Python API"
        )
    root = _make_tree(tmp_path, {"a.txt": b"a"})
    link = root / "link.txt"
    try:
        os.symlink(b"\xff", os.fsencode(link))
    except (OSError, TypeError):
        pytest.skip("filesystem does not support byte-valued symbolic links")
    with pytest.raises(TreeHashStructureError, match="non-UTF-8"):
        treehash.compute_materialized_tree_hash(root)


def test_fifo_or_special_file_is_rejected(tmp_path):
    if not hasattr(os, "mkfifo"):
        pytest.skip("platform has no FIFO API")
    root = tmp_path / "src"
    root.mkdir()
    root.joinpath("a.txt").write_bytes(b"a")
    try:
        os.mkfifo(root / "pipe")
    except (OSError, PermissionError):
        pytest.skip("cannot create fifo on this platform")
    with pytest.raises(TreeHashStructureError):
        treehash.compute_materialized_tree_hash(root)


def test_path_with_newline_is_rejected(tmp_path):
    root = tmp_path / "src"
    root.mkdir()
    # Filesystems rarely allow newline-in-filename but it's legal on POSIX.
    try:
        (root / "a\nb.txt").write_bytes(b"x")
    except OSError:
        pytest.skip("filesystem rejects newline in filename")
    with pytest.raises(TreeHashStructureError):
        treehash.compute_materialized_tree_hash(root)


def test_missing_directory_raises(tmp_path):
    with pytest.raises(TreeHashStructureError):
        treehash.compute_materialized_tree_hash(tmp_path / "does-not-exist")


def test_unreadable_file_error_is_wrapped(tmp_path, monkeypatch):
    root = _make_tree(tmp_path, {"a.txt": b"a"})
    real_open = Path.open

    def denied(path, *args, **kwargs):
        if path == root / "a.txt":
            raise PermissionError("denied")
        return real_open(path, *args, **kwargs)

    monkeypatch.setattr(Path, "open", denied)
    with pytest.raises(TreeHashStructureError, match="cannot read entry"):
        treehash.compute_materialized_tree_hash(root)


def test_non_utf8_filename_is_wrapped(tmp_path):
    if sys.platform == "win32":
        pytest.skip(
            "non-UTF-8 filenames are not representable on Windows via the standard Python API"
        )
    root = _make_tree(tmp_path, {"a.txt": b"a"})
    bad = os.fsencode(root) + b"/bad-\xff"
    try:
        fd = os.open(bad, os.O_CREAT | os.O_WRONLY, 0o600)
        os.close(fd)
    except OSError:
        pytest.skip("filesystem does not support non-UTF-8 names")
    with pytest.raises(TreeHashStructureError, match="non-UTF-8"):
        treehash.compute_materialized_tree_hash(root)


def test_verify_rejects_unknown_algorithm(tmp_path):
    root = _make_tree(tmp_path, {"a.txt": b"a"})
    digest, _scope = treehash.compute_materialized_tree_hash(root)
    with pytest.raises(TreeHashFormatError, match="unsupported.*algorithm"):
        treehash.verify_materialized_tree_hash(root, digest, algorithm="future-v2")


def test_large_file_streamed_constant_memory(tmp_path, monkeypatch):
    # 32 MiB file; we just assert it doesn't crash and digest matches manual.
    data = os.urandom(32 * 1024 * 1024)
    root = _make_tree(tmp_path, {"big.bin": data})
    expected = _manual_h1(root, {"big.bin": data})
    assert treehash.compute_materialized_tree_hash(root) == (expected, treehash.FULL)


def test_deterministic_across_invocations(tmp_path):
    files = {f"file_{i:03d}.txt": bytes([i]) * 100 for i in range(50)}
    root = _make_tree(tmp_path, files)
    h1 = treehash.compute_materialized_tree_hash(root)
    h2 = treehash.compute_materialized_tree_hash(root)
    h3 = treehash.compute_materialized_tree_hash(root)
    assert h1 == h2 == h3


def test_manifest_digest_fields_helper():
    fields = treehash.manifest_digest_fields("h1:abc=", scope=treehash.SAMPLED)
    assert fields == {
        "materialized_tree_hash_algorithm": "dirhash-h1-sha256-v1",
        "materialized_tree_hash": "h1:abc=",
        "materialized_tree_hash_scope": "sampled",
    }


def test_small_tree_hashed_in_full(tmp_path):
    root = _make_tree(tmp_path, {"a": b"a", "b": b"b"})
    _digest, scope = treehash.compute_materialized_tree_hash(root)
    assert scope == treehash.FULL


def test_many_files_tree_sampled(tmp_path, monkeypatch):
    monkeypatch.setattr(treehash, "MAX_FILES", 3)
    root = _make_tree(tmp_path, {f"f{i}": str(i).encode() for i in range(5)})
    first = treehash.compute_materialized_tree_hash(root)
    second = treehash.compute_materialized_tree_hash(root)
    assert first == second
    assert first[1] == treehash.SAMPLED
    assert first[0] != _manual_h1(root, {})


def test_large_bytes_tree_sampled(tmp_path, monkeypatch):
    monkeypatch.setattr(treehash, "MAX_BYTES", 3)
    root = _make_tree(tmp_path, {"a": b"aa", "b": b"bb"})
    _digest, scope = treehash.compute_materialized_tree_hash(root)
    assert scope == treehash.SAMPLED


def test_single_oversized_file_is_full(tmp_path, monkeypatch):
    monkeypatch.setattr(treehash, "MAX_BYTES", 1)
    root = _make_tree(tmp_path, {"only": b"oversized"})
    _digest, scope = treehash.compute_materialized_tree_hash(root)
    assert scope == treehash.FULL


def test_sampled_subset_is_deterministic_by_content(tmp_path, monkeypatch):
    monkeypatch.setattr(treehash, "MAX_FILES", 2)
    files = {"z": b"same-z", "a": b"same-a", "m": b"same-m"}
    root_a = _make_tree(tmp_path / "one", files)
    root_b = _make_tree(tmp_path / "two", dict(reversed(list(files.items()))))
    assert treehash.compute_materialized_tree_hash(root_a) == \
        treehash.compute_materialized_tree_hash(root_b)


def test_sampled_rejects_full_verification(tmp_path, monkeypatch):
    monkeypatch.setattr(treehash, "MAX_FILES", 1)
    root = _make_tree(tmp_path, {"a": b"a", "b": b"b"})
    digest, scope = treehash.compute_materialized_tree_hash(root)
    assert scope == treehash.SAMPLED
    with pytest.raises(TreeHashFormatError, match="scope"):
        treehash.verify_materialized_tree_hash(root, digest, scope=treehash.FULL)


def test_legacy_full_digest_over_current_caps_verifies(tmp_path, monkeypatch):
    files = {"a": b"a", "b": b"b"}
    root = _make_tree(tmp_path, files)
    expected = _manual_h1(root, files)
    monkeypatch.setattr(treehash, "MAX_FILES", 1)
    treehash.verify_materialized_tree_hash(root, expected)


def test_sampled_verify_round_trip(tmp_path, monkeypatch):
    monkeypatch.setattr(treehash, "MAX_FILES", 1)
    root = _make_tree(tmp_path, {"a": b"a", "b": b"b"})
    digest, scope = treehash.compute_materialized_tree_hash(root)
    treehash.verify_materialized_tree_hash(root, digest, scope=scope)
    assert treehash.compute_materialized_tree_hash(root) == (digest, treehash.SAMPLED)


def test_empty_tree_is_full_scope(tmp_path):
    root = tmp_path / "empty-again"
    root.mkdir()
    digest, scope = treehash.compute_materialized_tree_hash(root)
    assert scope == treehash.FULL
    assert digest == _manual_h1(root, {})
