from __future__ import annotations

import json
import re

from leitir.corpus import write_sources
from leitir.sbom import generate_sbom


def _fixture(tmp_path):
    corpus = tmp_path / "corpus"
    project = tmp_path / "project"
    project.mkdir()
    (project / "package-lock.json").write_text(json.dumps({
        "lockfileVersion": 3,
        "packages": {"node_modules/demo": {"version": "1.2.3"}},
    }))
    sha = "a" * 40
    relative = f"repos/github.com/acme/demo/{sha}"
    target = corpus / relative
    target.mkdir(parents=True)
    manifest = {
        "spec": "npm:demo@1.2.3", "host": "github.com", "owner": "acme", "repo": "demo",
        "commit_sha": sha, "repo_url": "https://github.com/acme/demo",
        "fetched_at": "2026-08-03T00:00:00Z", "fetch_method": "registry-artifact",
        "source": "registry-artifact", "artifact_kind": "npm-tarball",
        "artifact_checksum": "sha256:" + "b" * 64, "verified": True,
        "verified_at": "2026-08-03T00:00:00Z", "version": "1.2.3", "ecosystem": "npm",
        "license": "MIT", "parity": "exact",
    }
    (target / "leitir-manifest.json").write_text(json.dumps(manifest))
    write_sources(corpus, [{
        "name": "demo", "host": "github.com", "owner": "acme", "repo": "demo",
        "commit_sha": sha, "path": relative, "fetched_at": manifest["fetched_at"],
    }])
    return corpus, project


def test_spdx_23_document_fields_and_closure_relationships(tmp_path):
    corpus, project = _fixture(tmp_path)
    document = generate_sbom(corpus, project, "spdx")
    assert document["spdxVersion"] == "SPDX-2.3"
    assert document["dataLicense"] == "CC0-1.0"
    assert document["documentDescribes"] == [document["packages"][0]["SPDXID"]]
    package = document["packages"][0]
    assert re.fullmatch(r"SPDXRef-[A-Za-z0-9.-]+", package["SPDXID"])
    assert package["versionInfo"] == "1.2.3"
    assert package["downloadLocation"] == "https://github.com/acme/demo"
    assert package["licenseDeclared"] == package["licenseConcluded"] == "MIT"
    assert {item["algorithm"] for item in package["checksums"]} == {"SHA1", "SHA256"}
    assert any(item["relationshipType"] == "DEPENDS_ON" for item in document["relationships"])


def test_spdx_generation_is_deterministic(tmp_path):
    corpus, project = _fixture(tmp_path)
    assert generate_sbom(corpus, project) == generate_sbom(corpus, project)
