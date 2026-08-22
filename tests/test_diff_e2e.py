from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from leitir.corpus import load_sources, write_sources
from leitir.diff import diff_packages
from leitir.resolver import ResolvedPackage
from leitir.search import RepoScope


class _Resolver:
    def resolve(self, ref):
        digit = "1" if ref.version == "1.0.0" else "2"
        return ResolvedPackage(
            ref,
            RepoScope("acme/demo", digit * 40),
            f"v{ref.version}",
            f"https://example.invalid/demo/{ref.version}",
        )


def _materializer(spec, resolved, *, root, name, **options):
    root = Path(root)
    sha = resolved.scope.commit_sha
    target = root / "repos" / "github.com" / "acme" / "demo" / sha
    target.mkdir(parents=True, exist_ok=True)
    if resolved.ref.version == "1.0.0":
        (target / "demo.py").write_text(
            "def public(value: int):\n    return value\n\ndef old():\n    pass\n",
            encoding="utf-8",
        )
    else:
        (target / "demo.py").write_text(
            "def public(value: str):\n    return value\n\ndef new():\n    pass\n",
            encoding="utf-8",
        )
        (target / "added.txt").write_text("added\n", encoding="utf-8")
    manifest = {
        "ecosystem": "pypi",
        "version": resolved.ref.version,
        "fetched_at": "2026-08-04T00:00:00Z",
    }
    (target / "leitir-manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    entries = []
    index_path = root / "sources.json"
    if index_path.exists():
        entries = json.loads(index_path.read_text(encoding="utf-8"))
    entries.append(
        {
            "name": name,
            "host": "github.com",
            "owner": "acme",
            "repo": "demo",
            "commit_sha": sha,
            "path": target.relative_to(root).as_posix(),
            "fetched_at": manifest["fetched_at"],
        }
    )
    write_sources(root, entries)
    return target


def test_offline_materialize_two_versions_then_diff(tmp_path):
    report = diff_packages(
        "pypi:demo@1.0.0",
        "pypi:demo@2.0.0",
        corpus_root=tmp_path,
        resolver=_Resolver(),
        heads=object(),
        materializer=_materializer,
    )

    assert report.files.added == ("added.txt",)
    assert report.files.modified == ("demo.py",)
    assert [item["qualified_name"] for item in report.api.added] == ["demo.new"]
    assert [item["qualified_name"] for item in report.api.removed] == ["demo.old"]
    assert [item.qualified_name for item in report.api.changed] == ["demo.public"]
    assert (tmp_path / "api/pypi/demo/1.0.0/index.json").is_file()
    assert (tmp_path / "api/pypi/demo/2.0.0/index.json").is_file()


def test_unavailable_release_notes_never_fail_diff(tmp_path):
    class Unavailable:
        def fetch(self, repository, tag, version):
            raise OSError("offline")

    report = diff_packages(
        "pypi:demo@1.0.0",
        "pypi:demo@2.0.0",
        corpus_root=tmp_path,
        resolver=_Resolver(),
        heads=object(),
        materializer=_materializer,
        release_notes=Unavailable(),
    )
    assert report.release_notes == ()
    assert "release_notes" not in report.as_dict()


@pytest.mark.live
@pytest.mark.skipif(
    os.environ.get("LEITIR_ENABLE_LIVE_E2E") != "1",
    reason="set LEITIR_ENABLE_LIVE_E2E=1 to enable live diff coverage",
)
def test_live_two_public_pypi_versions(tmp_path):
    from leitir.cli import _build_default_code_search, _build_default_resolver, _github_token

    token = _github_token()
    report = diff_packages(
        "pypi:tomli@2.0.1",
        "pypi:tomli@2.0.2",
        corpus_root=tmp_path,
        resolver=_build_default_resolver(token),
        heads=_build_default_code_search(token),
        release_notes=None,
    )
    assert report.before.commit_sha != report.after.commit_sha
    assert report.before.name == report.after.name == "tomli"


@pytest.mark.skipif(
    os.environ.get("LEITIR_ENABLE_LIVE_E2E") != "1",
    reason="set LEITIR_ENABLE_LIVE_E2E=1 to enable live diff coverage",
)
def test_live_cli_tag_diff_identity_matches_manifest_pins(tmp_path):
    """G-3/G-4 live journey (issue #218): run the real CLI diff journey
    against stable public tag specs, then read each materialized shelf's
    manifest and require both report identities to equal the manifest
    pins. Persistence is TMP-only; the remote is read-only."""
    import io

    from leitir.cli import ExitCode, main

    stdout = io.StringIO()
    stderr = io.StringIO()
    code = main(
        [
            "diff",
            "hukkin/tomli@2.0.1",
            "hukkin/tomli@2.0.2",
            "--json",
            "--root",
            str(tmp_path),
        ],
        stdout=stdout,
        stderr=stderr,
    )
    assert code == ExitCode.SUCCESS
    report = json.loads(stdout.getvalue())

    shelves = [
        entry
        for entry in load_sources(tmp_path)
        if (entry["owner"], entry["repo"]) == ("hukkin", "tomli")
    ]
    assert len(shelves) == 2
    pins = set()
    for entry in shelves:
        manifest = json.loads(
            (tmp_path / str(entry["path"]) / "leitir-manifest.json").read_text(
                encoding="utf-8"
            )
        )
        assert manifest["commit_sha"] == entry["commit_sha"]
        pins.add(str(manifest["commit_sha"]))

    assert report["before"]["commit_sha"] in pins
    assert report["after"]["commit_sha"] in pins
    assert report["before"]["commit_sha"] != report["after"]["commit_sha"]
