from __future__ import annotations

from test_sbom_spdx import _fixture

from leitir.sbom import generate_sbom


def test_cyclonedx_15_components_and_dependencies(tmp_path):
    corpus, project = _fixture(tmp_path)
    document = generate_sbom(corpus, project, "cyclonedx")
    assert document["bomFormat"] == "CycloneDX"
    assert document["specVersion"] == "1.5"
    assert document["metadata"]["tools"] == [{"vendor": "leitir", "name": "leitir"}]
    component = document["components"][0]
    assert component["type"] == "library"
    assert component["purl"] == "pkg:npm/demo@1.2.3"
    assert {item["alg"] for item in component["hashes"]} == {"SHA-1", "SHA-256"}
    assert component["licenses"] == [{"license": {"id": "MIT"}}]
    properties = {item["name"]: item["value"] for item in component["properties"]}
    assert properties == {
        "leitir:license_method": "manifest",
        "leitir:license_confidence": "high",
        "leitir:source": "registry-artifact",
        "leitir:parity": "exact",
    }
    assert document["dependencies"][0]["dependsOn"] == [component["bom-ref"]]
