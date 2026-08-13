from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from leitir.bts_errors import BTSRejectReason
from leitir.license_policy import (
    BundledSource,
    EvidenceStatus,
    EvidenceTier,
    LicenseDecisionStatus,
    RecipientLicensePolicy,
    ResolutionState,
    VerifiedBytes,
    canonicalize_spdx_expression,
    evaluate_license_policy,
    resolve_source_license,
)


def _source(name: str, expression: str | None, *, extra: tuple[VerifiedBytes, ...] = ()) -> BundledSource:
    marker = b"" if expression is None else f"# SPDX-License-Identifier: {expression}\n".encode()
    content = marker + b"# SPDX-FileCopyrightText: Example Authors\nprint('verified')\n"
    return BundledSource.create(
        source_record_id=name,
        packet_path=f"source/{name}.py",
        source_path=f"pkg/{name}.py",
        package_scope="pkg",
        source_bytes=content,
        verified_files=extra,
    )


def _recipient(
    allowed: tuple[str, ...] = ("Apache-2.0", "MIT"),
    prohibited: tuple[str, ...] = (),
) -> RecipientLicensePolicy:
    return RecipientLicensePolicy.create(
        policy_id="recipient",
        policy_version="v1",
        use_category="distribution",
        allowed_spdx_expressions=allowed,
        prohibited_spdx_expressions=prohibited,
    )


def test_permissive_sources_emit_authoritative_obligations_and_attribution() -> None:
    notice = VerifiedBytes.create("pkg/NOTICE", b"Apache component notice\n", "pkg")
    decision = evaluate_license_policy((_source("mit", "MIT"), _source("apache", "Apache-2.0", extra=(notice,))), _recipient())

    assert decision.status is LicenseDecisionStatus.PASS
    assert decision.reason is None
    assert decision.obligations_json is not None
    payload = json.loads(decision.obligations_json)
    assert payload["schema_version"] == "leitir-bts-obligations-v1"
    assert payload["obligations_digest"].startswith("sha256:")
    assert decision.attribution_md is not None
    assert b"Generated from authoritative `obligations.json`" in decision.attribution_md
    assert b"Apache component notice" in decision.attribution_md


@pytest.mark.parametrize("seed", ["0", "1", "42"])
def test_policy_outputs_are_hash_seed_independent(seed: str) -> None:
    script = """
from leitir.license_policy import BundledSource, RecipientLicensePolicy, evaluate_license_policy
def source(n, x):
 return BundledSource.create(source_record_id=n, packet_path=f'source/{n}.py', source_path=f'pkg/{n}.py', package_scope='pkg', source_bytes=f'# SPDX-License-Identifier: {x}\\n'.encode())
p=RecipientLicensePolicy.create(policy_id='recipient', policy_version='v1', use_category='distribution', allowed_spdx_expressions=('MIT','Apache-2.0'))
d=evaluate_license_policy((source('z','Apache-2.0'),source('a','MIT')),p)
assert d.obligations_json and d.attribution_md
import sys
sys.stdout.buffer.write(d.obligations_json + b'---\\n' + d.attribution_md)
"""
    environment = dict(os.environ, PYTHONHASHSEED=seed, PYTHONPATH="src")
    actual = subprocess.check_output([sys.executable, "-c", script], env=environment)
    baseline = subprocess.check_output([sys.executable, "-c", script], env={**environment, "PYTHONHASHSEED": "0"})
    assert actual == baseline


@pytest.mark.parametrize("expression", [None, "Not-A-Real-SPDX-License"])
def test_missing_or_malformed_evidence_is_unknown_and_rejected(expression: str | None) -> None:
    decision = evaluate_license_policy((_source("unknown", expression),), _recipient())

    assert not decision.accepted
    assert decision.reason is BTSRejectReason.REJECT_LICENSE_UNKNOWN
    assert decision.resolutions[0].state in {ResolutionState.MISSING, ResolutionState.MALFORMED}


def test_explicit_recipient_prohibition_precedes_deferred_catalog() -> None:
    decision = evaluate_license_policy(
        (_source("gpl", "GPL-3.0-only"),),
        _recipient(prohibited=("GPL-3.0-only",)),
    )

    assert decision.reason is BTSRejectReason.REJECT_LICENSE_INCOMPATIBLE
    assert "GPL-3.0-only" in decision.detail
    assert _recipient(prohibited=("GPL-3.0-only",)).content_digest in decision.detail


def test_duplicate_conflicting_file_headers_are_ambiguous() -> None:
    content = b"# SPDX-License-Identifier: MIT\n# SPDX-License-Identifier: Apache-2.0\n"
    source = BundledSource.create(
        source_record_id="conflict",
        packet_path="source/conflict.py",
        source_path="pkg/conflict.py",
        package_scope="pkg",
        source_bytes=content,
    )
    decision = evaluate_license_policy((source,), _recipient())

    assert decision.reason is BTSRejectReason.REJECT_LICENSE_UNKNOWN
    assert decision.detail_code == "duplicate_file_header"
    assert decision.resolutions[0].state is ResolutionState.AMBIGUOUS


@pytest.mark.parametrize(
    "expression",
    [
        "GPL-3.0-only",
        "MIT OR Apache-2.0",
        "MIT AND Apache-2.0",
        "GPL-2.0-only WITH Classpath-exception-2.0",
        "LicenseRef-Private",
    ],
)
def test_well_formed_but_deferred_expressions_are_unknown(expression: str) -> None:
    decision = evaluate_license_policy((_source("deferred", expression),), _recipient(allowed=(expression,)))

    assert decision.reason is BTSRejectReason.REJECT_LICENSE_UNKNOWN
    assert decision.detail_code == "compatibility_rule_missing"


def test_reuse_precedence_records_lower_evidence_as_shadowed() -> None:
    reuse = VerifiedBytes.create(
        "pkg/REUSE.toml",
        b'version = 1\n[[annotations]]\npath = ["*.py"]\nprecedence = "aggregate"\nSPDX-License-Identifier = "Apache-2.0"\n',
        "pkg",
    )
    source = _source("precedence", "MIT", extra=(reuse,))
    resolution = resolve_source_license(source)

    assert resolution.expression == "MIT"
    assert [(item.tier, item.status) for item in resolution.evidence] == [
        (EvidenceTier.FILE_HEADER, EvidenceStatus.SELECTED),
        (EvidenceTier.REUSE_TOML, EvidenceStatus.SHADOWED),
    ]


def test_adjacent_sidecar_precedes_reuse_and_dep5() -> None:
    sidecar = VerifiedBytes.create("pkg/plain.py.license", b"SPDX-License-Identifier: MIT\n", "pkg")
    reuse = VerifiedBytes.create(
        "pkg/REUSE.toml",
        b'version = 1\n[[annotations]]\npath = "plain.py"\nSPDX-License-Identifier = "Apache-2.0"\n',
        "pkg",
    )
    dep5 = VerifiedBytes.create("pkg/.reuse/dep5", b"Files: plain.py\nLicense: BSD-3-Clause\n", "pkg")
    source = BundledSource.create(
        source_record_id="plain",
        packet_path="source/plain.py",
        source_path="pkg/plain.py",
        package_scope="pkg",
        source_bytes=b"print('no header')\n",
        verified_files=(sidecar, reuse, dep5),
    )

    assert resolve_source_license(source).expression == "MIT"


def test_filenames_and_unlisted_host_files_have_no_authority(tmp_path: Path) -> None:
    # Even a compelling ambient filename is invisible: the API accepts bytes,
    # not a Path, and the verified package view does not list this host file.
    (tmp_path / "LICENSE-MIT").write_text("SPDX-License-Identifier: MIT\n")
    source = BundledSource.create(
        source_record_id="ambient",
        packet_path="source/ambient.py",
        source_path="pkg/ambient.py",
        package_scope="pkg",
        source_bytes=b"print('unknown')\n",
    )

    assert resolve_source_license(source).state is ResolutionState.MISSING


def test_spdx_parser_canonicalizes_precedence_and_rejects_unknown_ids() -> None:
    assert canonicalize_spdx_expression("((MIT)) OR (Apache-2.0 AND BSD-2-Clause)") == "MIT OR Apache-2.0 AND BSD-2-Clause"
    assert canonicalize_spdx_expression("GPL-2.0-only WITH Classpath-exception-2.0") == "GPL-2.0-only WITH Classpath-exception-2.0"
    with pytest.raises(ValueError):
        canonicalize_spdx_expression("Imaginary-9.9")


@pytest.mark.parametrize(
    "expression, message",
    [
        ("(MIT", "unclosed SPDX group"),
        ("MIT WITH Imaginary-exception", "unknown SPDX exception"),
        ("MIT+ WITH Classpath-exception-2.0", "WITH requires a simple license"),
        ("MIT OR(Apache-2.0)", "operators require whitespace"),
    ],
)
def test_spdx_parser_rejects_noncanonical_or_incomplete_expressions(expression: str, message: str) -> None:
    with pytest.raises(ValueError, match=message):
        canonicalize_spdx_expression(expression)


def test_reuse_annotation_materializes_all_typed_text_obligations() -> None:
    reuse = VerifiedBytes.create(
        "pkg/REUSE.toml",
        b'''version = 1
[[annotations]]
path = "annotated.py"
SPDX-License-Identifier = "MIT"
SPDX-FileCopyrightText = ["Example Authors", "Additional Author"]
SPDX-FileNotice = "Preserve this notice"
SPDX-FileContributor = "A Contributor"
SPDX-FileAttributionText = "An attribution"
''',
        "pkg",
    )
    source = BundledSource.create(
        source_record_id="annotated",
        packet_path="source/annotated.py",
        source_path="pkg/annotated.py",
        package_scope="pkg",
        source_bytes=b"print('licensed by metadata')\n",
        verified_files=(reuse,),
    )

    decision = evaluate_license_policy((source,), _recipient())

    assert decision.accepted
    assert decision.obligations_json is not None
    payload = json.loads(decision.obligations_json)
    text_records = [item for item in payload["obligations"] if item["kind"] in {"copyright", "notice", "contributor", "attribution"}]
    assert sorted((item["kind"], item["normalized_text"]) for item in text_records) == [
        ("attribution", "An attribution"),
        ("contributor", "A Contributor"),
        ("copyright", "Additional Author"),
        ("copyright", "Example Authors"),
        ("notice", "Preserve this notice"),
    ]


def test_dep5_copyright_and_apache_modification_are_materialized() -> None:
    dep5 = VerifiedBytes.create(
        "pkg/.reuse/dep5",
        b"Files: modified.py\nCopyright: 2026 Example Authors\nLicense: Apache-2.0\n",
        "pkg",
    )
    source = BundledSource.create(
        source_record_id="modified",
        packet_path="source/modified.py",
        source_path="pkg/modified.py",
        package_scope="pkg",
        source_bytes=b"print('modified')\n",
        verified_files=(dep5,),
        modified_from_sha256="sha256:" + "a" * 64,
    )

    decision = evaluate_license_policy((source,), _recipient())

    assert decision.accepted
    assert decision.obligations_json is not None
    payload = json.loads(decision.obligations_json)
    by_kind = {item["kind"]: item for item in payload["obligations"]}
    assert by_kind["copyright"]["normalized_text"] == "2026 Example Authors"
    assert by_kind["modification_marking"]["original_bytes_sha256"] == "sha256:" + "a" * 64


@pytest.mark.parametrize("notice", [b"", b"\xff"])
def test_empty_or_non_utf8_notice_rejects_obligation_materialization(notice: bytes) -> None:
    evidence = VerifiedBytes.create("pkg/plain.py.license", b"SPDX-License-Identifier: MIT\n", "pkg")
    notice_file = VerifiedBytes.create("pkg/NOTICE", notice, "pkg")
    source = BundledSource.create(
        source_record_id="plain",
        packet_path="source/plain.py",
        source_path="pkg/plain.py",
        package_scope="pkg",
        source_bytes=b"print('plain')\n",
        verified_files=(evidence, notice_file),
    )

    decision = evaluate_license_policy((source,), _recipient())

    assert decision.status is LicenseDecisionStatus.REJECT
    assert decision.reason is BTSRejectReason.REJECT_LICENSE_OBLIGATION_MISSING
    assert decision.detail_code == "typed_obligation_unmaterializable"
