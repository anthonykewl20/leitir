"""Deterministic SPDX and CycloneDX documents for a materialized corpus."""

from __future__ import annotations

import base64
import binascii
import hashlib
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import quote

from .corpus import enumerate_shelved_sources
from .lockfiles import dependency_closures

_TIMESTAMP = "1970-01-01T00:00:00Z"
_SPDX_MARKER = re.compile(
    r"(?im)^\s*(?:[#*/;<!-]+\s*)?SPDX-License-Identifier:\s*([^\r\n*<>]+)"
)
_SPDX_TOKEN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.+-]*$")
_SPDX_OPERATORS = {"AND", "OR", "WITH"}
_KNOWN_LICENSES = {
    "0BSD",
    "AGPL-3.0-only",
    "AGPL-3.0-or-later",
    "Apache-2.0",
    "Artistic-2.0",
    "BSD-2-Clause",
    "BSD-3-Clause",
    "BSL-1.0",
    "CC-BY-4.0",
    "CC0-1.0",
    "EPL-1.0",
    "EPL-2.0",
    "GPL-2.0-only",
    "GPL-2.0-or-later",
    "GPL-3.0-only",
    "GPL-3.0-or-later",
    "ISC",
    "LGPL-2.1-only",
    "LGPL-2.1-or-later",
    "LGPL-3.0-only",
    "LGPL-3.0-or-later",
    "MIT",
    "MPL-2.0",
    "Python-2.0",
    "Unlicense",
    "Zlib",
}
_LICENSE_NAMES = re.compile(r"^(?:LICENSE|LICENCE)(?:[._-].*)?$", re.IGNORECASE)
_COPYING_NAMES = re.compile(r"^COPYING(?:[._-].*)?$", re.IGNORECASE)
_FILENAME_LICENSES = {
    "0BSD": "0BSD",
    "AGPL-3.0": "AGPL-3.0-only",
    "AGPL3": "AGPL-3.0-only",
    "APACHE": "Apache-2.0",
    "APACHE-2.0": "Apache-2.0",
    "BSD-2-CLAUSE": "BSD-2-Clause",
    "BSD-3-CLAUSE": "BSD-3-Clause",
    "CC0": "CC0-1.0",
    "GPL-2.0": "GPL-2.0-only",
    "GPL-3.0": "GPL-3.0-only",
    "GPL2": "GPL-2.0-only",
    "GPL3": "GPL-3.0-only",
    "ISC": "ISC",
    "LGPL-2.1": "LGPL-2.1-only",
    "LGPL-3.0": "LGPL-3.0-only",
    "MIT": "MIT",
    "MPL-2.0": "MPL-2.0",
    "UNLICENSE": "Unlicense",
}
_ALIASES = {
    "Apache 2": "Apache-2.0",
    "Apache License 2.0": "Apache-2.0",
    "MIT License": "MIT",
    "The Unlicense": "Unlicense",
}


@dataclass(frozen=True, slots=True)
class LicenseResult:
    """One auditable license inference result."""

    identifier: str | None
    method: str
    confidence: str


@dataclass(frozen=True, slots=True)
class _Package:
    entry: dict[str, Any]
    manifest: dict[str, object]
    license: LicenseResult
    identity: str
    spdx_id: str
    bom_ref: str
    purl: str | None


def _spdx_expression(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    candidate = value.strip()
    if not candidate:
        return None
    candidate = _ALIASES.get(candidate, candidate)
    words = candidate.replace("(", " ( ").replace(")", " ) ").split()
    if not words:
        return None
    identifiers = 0
    balance = 0
    expect_operand = True
    for word in words:
        if word == "(":
            if not expect_operand:
                return None
            balance += 1
        elif word == ")":
            if expect_operand:
                return None
            balance -= 1
            if balance < 0:
                return None
        elif word.upper() in {"AND", "OR"} or word.upper() == "WITH":
            if expect_operand:
                return None
            expect_operand = True
        elif _SPDX_TOKEN.fullmatch(word):
            if not expect_operand or not (
                word in _KNOWN_LICENSES
                or word.startswith("LicenseRef-")
                or ":LicenseRef-" in word
            ):
                return None
            identifiers += 1
            expect_operand = False
        else:
            return None
    return candidate if identifiers and balance == 0 and not expect_operand else None


def _license_value(value: object) -> str | None:
    if isinstance(value, dict):
        for key in ("spdx_id", "spdxId", "type", "id", "key", "name"):
            result = _spdx_expression(value.get(key))
            if result is not None and result.upper() not in {"NOASSERTION", "OTHER"}:
                return result
        return None
    if isinstance(value, list):
        values = sorted({result for item in value if (result := _license_value(item))})
        return " OR ".join(values) if values else None
    result = _spdx_expression(value)
    return result if result is not None and result.upper() not in {"NOASSERTION", "OTHER"} else None


def _manifest_license(manifest: dict[str, object]) -> str | None:
    candidates: list[object] = [manifest.get("license"), manifest.get("licenses")]
    for key in ("info", "metadata", "github", "repository"):
        nested = manifest.get(key)
        if isinstance(nested, dict):
            candidates.extend((nested.get("license"), nested.get("licenses")))
    candidates.extend((manifest.get("license_info"), manifest.get("repository_license")))
    for candidate in candidates:
        result = _license_value(candidate)
        if result is not None:
            return result
    return None


def _license_files(target_path: Path) -> list[Path]:
    try:
        candidates = [
            path
            for path in target_path.rglob("*")
            if path.is_file()
            and (_LICENSE_NAMES.fullmatch(path.name) or _COPYING_NAMES.fullmatch(path.name))
        ]
    except OSError:
        return []
    return sorted(candidates, key=lambda path: path.relative_to(target_path).as_posix())


def _filename_license(name: str) -> str | None:
    upper = name.upper()
    for prefix in ("LICENSE", "LICENCE", "COPYING"):
        if upper == prefix:
            return None
        marker = upper.removeprefix(prefix).lstrip("._-")
        if marker != upper:
            return _FILENAME_LICENSES.get(marker)
    return None


def infer_license(manifest: dict[str, object], target_path: Path) -> LicenseResult:
    """Infer a license through metadata, explicit file content, then filename."""

    declared = _manifest_license(manifest)
    if declared is not None:
        return LicenseResult(declared, "manifest", "high")
    files = _license_files(Path(target_path))
    for path in files:
        try:
            text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeError):
            continue
        marker = _SPDX_MARKER.search(text[:262144])
        expression = _spdx_expression(marker.group(1).strip()) if marker else None
        if expression is not None:
            method = "copying-file" if _COPYING_NAMES.fullmatch(path.name) else "license-file"
            return LicenseResult(expression, method, "high")
    for path in files:
        inferred = _filename_license(path.name)
        if inferred is not None:
            return LicenseResult(inferred, "filename", "medium")
    return LicenseResult(None, "unknown", "low")


def _safe(value: str) -> str:
    rendered = re.sub(r"[^A-Za-z0-9.-]+", "-", value).strip("-.")
    return rendered or "package"


def _purl(ecosystem: object, name: str, version: str) -> str | None:
    if ecosystem == "npm":
        if name.startswith("@") and "/" in name:
            namespace, package = name.split("/", 1)
            path = f"{quote(namespace, safe='')}/{quote(package, safe='')}"
        else:
            path = quote(name, safe="")
        return f"pkg:npm/{path}@{quote(version, safe='.-_~')}"
    purl_types: dict[object, str] = {
        "pypi": "pypi",
        "crates": "cargo",
        "go": "golang",
    }
    purl_type = purl_types.get(ecosystem)
    if purl_type is None:
        return None
    safe = "/" if ecosystem == "go" else ""
    return f"pkg:{purl_type}/{quote(name, safe=safe)}@{quote(version, safe='.-_~')}"


def _checksum(checksum: object) -> tuple[str, str] | None:
    if not isinstance(checksum, str):
        return None
    match = re.fullmatch(r"(?i)(sha(?:1|256|384|512))[: -](.+)", checksum.strip())
    if match is None:
        return None
    algorithm, digest = match.groups()
    if checksum.lower().startswith(algorithm.lower() + "-"):
        try:
            digest = base64.b64decode(digest, validate=True).hex()
        except (binascii.Error, ValueError):
            pass
    return algorithm.upper(), digest.lower()


def _checksums(package: _Package) -> list[tuple[str, str]]:
    checksums: set[tuple[str, str]] = set()
    artifact = _checksum(package.manifest.get("artifact_checksum"))
    if artifact is not None:
        checksums.add(artifact)
    commit = package.entry.get("commit_sha")
    if isinstance(commit, str) and re.fullmatch(r"(?i)[0-9a-f]{40}", commit):
        checksums.add(("SHA1", commit.lower()))
    return sorted(checksums)


def _packages(corpus_root: str | Path) -> list[_Package]:
    result: list[_Package] = []
    for entry, manifest, target in enumerate_shelved_sources(corpus_root):
        name = str(entry["name"])
        version = str(manifest.get("version") or entry["commit_sha"])
        ecosystem = manifest.get("ecosystem")
        identity = f"{ecosystem or 'git'}:{name}@{version}"
        suffix = _safe(f"{ecosystem or 'git'}-{name}-{version}-{entry['commit_sha']}")
        result.append(
            _Package(
                entry,
                manifest,
                infer_license(manifest, target),
                identity,
                f"SPDXRef-Package-{suffix}",
                f"pkg:{suffix}",
                _purl(ecosystem, name, version),
            )
        )
    return sorted(result, key=lambda package: package.identity)


def _closure_refs(packages: list[_Package], directory: str | Path) -> list[_Package]:
    wanted: set[str] = set()
    for closure in dependency_closures(directory):
        wanted.update(edge.spec for edge in closure.deps)
    for package in packages:
        deps = package.manifest.get("deps")
        if isinstance(deps, list):
            wanted.update(
                str(dep["spec"])
                for dep in deps
                if isinstance(dep, dict) and isinstance(dep.get("spec"), str)
            )
    return [package for package in packages if package.identity in wanted]


def _spdx(packages: list[_Package], dependencies: list[_Package]) -> dict[str, object]:
    described = [package.spdx_id for package in packages]
    rendered_packages: list[dict[str, object]] = []
    for package in packages:
        license_id = package.license.identifier or "NOASSERTION"
        external_refs = []
        if package.purl is not None:
            external_refs.append(
                {
                    "referenceCategory": "PACKAGE-MANAGER",
                    "referenceType": "purl",
                    "referenceLocator": package.purl,
                }
            )
        rendered_packages.append(
            {
                "name": package.entry["name"],
                "SPDXID": package.spdx_id,
                "versionInfo": str(package.manifest.get("version") or package.entry["commit_sha"]),
                "downloadLocation": package.manifest.get("repo_url") or "NOASSERTION",
                "filesAnalyzed": False,
                "licenseConcluded": license_id,
                "licenseDeclared": license_id,
                "copyrightText": "NOASSERTION",
                "externalRefs": external_refs,
                "checksums": [
                    {"algorithm": algorithm, "checksumValue": digest}
                    for algorithm, digest in _checksums(package)
                ],
                "annotations": [
                    {
                        "annotationDate": _TIMESTAMP,
                        "annotationType": "OTHER",
                        "annotator": "Tool: leitir",
                        "comment": (
                            f"license_method={package.license.method};"
                            f"license_confidence={package.license.confidence}"
                        ),
                    }
                ],
            }
        )
    relationships = [
        {
            "spdxElementId": "SPDXRef-DOCUMENT",
            "relationshipType": "DESCRIBES",
            "relatedSpdxElement": package.spdx_id,
        }
        for package in packages
    ]
    relationships.extend(
        {
            "spdxElementId": "SPDXRef-DOCUMENT",
            "relationshipType": "DEPENDS_ON",
            "relatedSpdxElement": package.spdx_id,
        }
        for package in dependencies
    )
    relationships.sort(
        key=lambda item: (item["relationshipType"], item["relatedSpdxElement"])
    )
    namespace_input = "\n".join(package.identity + ":" + str(package.entry["commit_sha"]) for package in packages)
    namespace_digest = hashlib.sha256(namespace_input.encode("utf-8")).hexdigest()
    return {
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": "leitir-corpus",
        "documentNamespace": f"https://leitir.dev/spdx/corpus/{namespace_digest}",
        "creationInfo": {"created": _TIMESTAMP, "creators": ["Tool: leitir"]},
        "documentDescribes": described,
        "packages": rendered_packages,
        "relationships": relationships,
    }


def _cyclonedx(packages: list[_Package], dependencies: list[_Package]) -> dict[str, object]:
    components: list[dict[str, object]] = []
    for package in packages:
        component: dict[str, object] = {
            "type": "library",
            "bom-ref": package.bom_ref,
            "name": package.entry["name"],
            "version": str(package.manifest.get("version") or package.entry["commit_sha"]),
            "hashes": [
                {"alg": algorithm.replace("SHA", "SHA-"), "content": digest}
                for algorithm, digest in _checksums(package)
            ],
            "licenses": (
                [
                    {"expression": package.license.identifier}
                    if any(
                        token in package.license.identifier.split()
                        for token in _SPDX_OPERATORS
                    )
                    else {"license": {"id": package.license.identifier}}
                ]
                if package.license.identifier is not None
                else []
            ),
            "properties": [
                {"name": "leitir:license_method", "value": package.license.method},
                {"name": "leitir:license_confidence", "value": package.license.confidence},
                {"name": "leitir:source", "value": str(package.manifest.get("source", "unknown"))},
                {"name": "leitir:parity", "value": str(package.manifest.get("parity", "unknown"))},
            ],
        }
        if package.purl is not None:
            component["purl"] = package.purl
        components.append(component)
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "version": 1,
        "metadata": {
            "timestamp": _TIMESTAMP,
            "tools": [{"vendor": "leitir", "name": "leitir"}],
            "component": {"type": "application", "name": "project", "bom-ref": "leitir:project"},
        },
        "components": components,
        "dependencies": [
            {"ref": "leitir:project", "dependsOn": [package.bom_ref for package in dependencies]}
        ]
        + [{"ref": package.bom_ref, "dependsOn": []} for package in packages],
    }


def generate_sbom(
    corpus_root: str | Path, directory: str | Path, format: str = "spdx"
) -> dict[str, object]:
    """Generate one deterministic, network-independent SBOM document."""

    if format not in {"spdx", "cyclonedx"}:
        raise ValueError("format must be 'spdx' or 'cyclonedx'")
    packages = _packages(corpus_root)
    dependencies = _closure_refs(packages, directory)
    return _spdx(packages, dependencies) if format == "spdx" else _cyclonedx(packages, dependencies)


__all__ = ["LicenseResult", "generate_sbom", "infer_license"]
