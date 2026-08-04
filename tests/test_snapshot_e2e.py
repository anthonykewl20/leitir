from __future__ import annotations

import json

from leitir.corpus import load_sources
from leitir.snapshot import export_corpus, import_corpus, tree_sha
from test_snapshot import make_corpus


def test_offline_snapshot_restores_complete_corpus(tmp_path):
    original = tmp_path / "original"
    make_corpus(original)
    expected_index = (original / "sources.json").read_bytes()
    expected_pointers = (original / "POINTERS.md").read_bytes()
    expected_manifests = {
        entry["path"]: (original / entry["path"] / "leitir-manifest.json").read_bytes()
        for entry in load_sources(original)
    }
    expected_trees = {
        entry["path"]: tree_sha(original / entry["path"])
        for entry in load_sources(original)
    }
    lock, _tarball = export_corpus(tmp_path / "offline.lock", root=original)
    restored = tmp_path / "restored"
    imported = import_corpus(lock, root=restored)
    assert json.loads((restored / "sources.json").read_text(encoding="utf-8")) == imported
    assert (restored / "sources.json").read_bytes() == expected_index
    assert (restored / "POINTERS.md").read_bytes() == expected_pointers
    assert {
        entry["path"]: (restored / entry["path"] / "leitir-manifest.json").read_bytes()
        for entry in imported
    } == expected_manifests
    assert {entry["path"]: tree_sha(restored / entry["path"]) for entry in imported} == expected_trees
