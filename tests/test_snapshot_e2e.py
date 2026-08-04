from __future__ import annotations

import json
import io
import tarfile

from leitir.corpus import (
    enumerate_shelved_sources,
    load_sources,
    materialize_source,
    remove_source,
)
from leitir.search import RepoScope
from leitir.snapshot import export_corpus, import_corpus, tree_sha
from leitir.tree import BlobEntry, GitHubTreeSource
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


def test_gitlab_subgroup_snapshot_round_trip_and_removal(tmp_path):
    slug = "group/subgroup/project"
    sha = "a" * 40
    content = b"subgroup snapshot\n"
    archive_bytes = io.BytesIO()
    with tarfile.open(fileobj=archive_bytes, mode="w:gz") as archive:
        member = tarfile.TarInfo(f"project-{sha}/README.md")
        member.size = len(content)
        member.mode = 0o644
        archive.addfile(member, io.BytesIO(content))

    class Resolver:
        def archive_url(self, requested_slug, commit_sha):
            assert (requested_slug, commit_sha) == (slug, sha)
            return "https://gitlab.com/archive"

        def _get_bytes(self, _url):
            return archive_bytes.getvalue()

        def list_blobs(self, requested_slug, commit_sha):
            assert (requested_slug, commit_sha) == (slug, sha)
            return (
                BlobEntry(
                    "README.md",
                    GitHubTreeSource.git_blob_sha(content),
                    len(content),
                    "100644",
                ),
            )

    original = tmp_path / "original-subgroup"
    target = materialize_source(
        f"gitlab:{slug}@{sha}",
        RepoScope(slug, sha),
        root=original,
        host="gitlab.com",
        repository_resolver=Resolver(),
    )
    assert target == original / "repos/gitlab.com/group/subgroup/project" / sha
    entry = load_sources(original)[0]
    assert (entry["owner"], entry["repo"]) == ("group/subgroup", "project")

    lock, _tarball = export_corpus(tmp_path / "subgroup.lock", root=original)
    restored = tmp_path / "restored-subgroup"
    imported = import_corpus(lock, root=restored)
    assert imported == [entry]
    assert enumerate_shelved_sources(restored)[0][1]["owner"] == "group/subgroup"
    assert remove_source(
        restored, "group", "subgroup/project", sha, host="gitlab.com"
    )
    assert load_sources(restored) == []
