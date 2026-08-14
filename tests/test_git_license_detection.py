from __future__ import annotations

import io
import json
import tarfile

import pytest
from _http_server import scripted_server

from leitir.corpus import record_trust, write_sources
from leitir.info import build_info
from leitir.materialize import MANIFEST_NAME, materialize_github_repo
from leitir.sbom import license_manifest_fields

SHA = "d" * 40
SPEC = f"example/demo@{SHA}"


def _tarball(files: dict[str, bytes]) -> bytes:
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w:gz") as archive:
        root = tarfile.TarInfo(f"demo-{SHA}")
        root.type = tarfile.DIRTYPE
        archive.addfile(root)
        for name, data in sorted(files.items()):
            member = tarfile.TarInfo(f"demo-{SHA}/{name}")
            member.size = len(data)
            archive.addfile(member, io.BytesIO(data))
    return output.getvalue()


def _materialize(tmp_path, files: dict[str, bytes]):
    with scripted_server([(200, {}, _tarball(files))]) as server:
        target = materialize_github_repo(
            tmp_path,
            SPEC,
            "example",
            "demo",
            SHA,
            base_url=server.base_url,
            max_attempts=1,
            verify=False,
        )
    return target


def _entry(target, manifest):
    del target
    return {
        "name": "example/demo",
        "host": "github.com",
        "owner": "example",
        "repo": "demo",
        "commit_sha": SHA,
        "path": f"repos/github.com/example/demo/{SHA}",
        "fetched_at": manifest["fetched_at"],
    }


@pytest.mark.parametrize(
    ("files", "expected"),
    [
        (
            {"LICENSE": b"Apache License\nVersion 2.0, January 2004\n"},
            {"license_identifier": "Apache-2.0", "license_method": "license-file", "license_confidence": "high"},
        ),
        (
            {"LICENSE.txt": b"Permission is hereby granted, free of charge, to any person obtaining a copy\n"},
            {"license_identifier": "MIT", "license_method": "license-file", "license_confidence": "high"},
        ),
        (
            {"COPYING": b"Neither the name of the copyright holder nor the names of its contributors may be used to endorse or promote products derived from this software without specific prior written permission.\n"},
            {"license_identifier": "BSD-3-Clause", "license_method": "copying-file", "license_confidence": "high"},
        ),
        (
            {"package.py": b"value = 1\n"},
            {"license_identifier": None, "license_method": "unknown", "license_confidence": "low"},
        ),
        (
            {
                "LICENSE": b"Apache License\nVersion 2.0, January 2004\n",
                "COPYING": b"Permission is hereby granted, free of charge, to any person obtaining a copy\n",
            },
            {"license_identifier": None, "license_method": "unknown", "license_confidence": "low"},
        ),
    ],
)
def test_git_materialization_persists_root_license_evidence(tmp_path, files, expected):
    target = _materialize(tmp_path, files)
    manifest = json.loads((target / MANIFEST_NAME).read_text(encoding="utf-8"))

    assert {field: manifest[field] for field in expected} == expected


def test_info_renders_persisted_git_license_evidence(tmp_path):
    target = _materialize(
        tmp_path, {"LICENSE": b"Apache License\nVersion 2.0, January 2004\n"}
    )
    manifest = json.loads((target / MANIFEST_NAME).read_text(encoding="utf-8"))
    write_sources(tmp_path, [_entry(target, manifest)])

    document = build_info(SPEC, corpus_root=tmp_path)

    assert document["license"] == {
        "identifier": "Apache-2.0",
        "method": "license-file",
        "confidence": "high",
    }


def test_trust_recomputes_license_evidence_without_fetching(tmp_path):
    target = _materialize(
        tmp_path, {"LICENSE": b"Apache License\nVersion 2.0, January 2004\n"}
    )
    manifest_path = target / MANIFEST_NAME
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    for field in ("license_identifier", "license_method", "license_confidence"):
        manifest.pop(field)
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    write_sources(tmp_path, [_entry(target, manifest)])

    entry, trust, refreshed_target = record_trust(SPEC, tmp_path)
    refreshed = json.loads(manifest_path.read_text(encoding="utf-8"))
    license_factor = next(
        item for item in trust.breakdown if item["factor"] == "license"
    )

    assert refreshed["license_identifier"] == "Apache-2.0"
    assert refreshed["license_method"] == "license-file"
    assert refreshed["license_confidence"] == "high"
    assert license_factor["evidence"]["method"] == "license-file"
    assert entry["name"] == "example/demo"
    assert refreshed_target == target


def test_git_license_detection_is_byte_deterministic(tmp_path):
    target = tmp_path / "shelf"
    target.mkdir()
    (target / "LICENSE").write_bytes(
        b"Apache License\nVersion 2.0, January 2004\n"
    )
    manifest = {"source": "git-commit"}

    assert license_manifest_fields(manifest, target) == license_manifest_fields(
        manifest, target
    )
