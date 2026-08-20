from __future__ import annotations

import hashlib
import io
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from leitir.bts_errors import BTSRejectReason
from leitir.license_policy import (
    STUDY_ONLY,
    TRANSPLANT_OK,
    BundledSource,
    EvidenceStatus,
    EvidenceTier,
    LicenseDecisionStatus,
    RecipientLicensePolicy,
    ResolutionState,
    VerifiedBytes,
    canonicalize_spdx_expression,
    detect_routing_evidence,
    evaluate_license_policy,
    resolve_source_license,
    routing_for_source,
    validate_routing_policy_table,
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


# ---------------------------------------------------------------------------
# License routing guidance (issue #190): transplant-ok | study-only.
#
# Contract fixtures, pinned by digest (recorded in the PR):
#   GPL-3.0 text     sha256:55a770d01573c94c781516fd7067cf69fd409d2cf077a5d32ee1ae0641d96f22
#   proprietary text sha256:22ba638b3d6af392701b1ee636be5191d9555e7a564f4f4ad07e1fdc051652cd
#   ee/ marker file  sha256:f40addaadfaf50313e54dddad11b7d22b2bacb334225d10b5edbc538091fa967

GPL3_HEADER_FIXTURE = (
    b"                    GNU GENERAL PUBLIC LICENSE\n"
    b"                       Version 3, 29 June 2007\n"
    b"\n"
    b" Copyright (C) 2007 Free Software Foundation, Inc. <http://fsf.org/>\n"
    b" Everyone is permitted to copy and distribute verbatim copies\n"
    b" of this license document, but changing it is not allowed.\n"
)
PROPRIETARY_MARKER_FIXTURE = (
    b"Proprietary and Confidential\n"
    b"\n"
    b"This software is proprietary and confidential. All rights reserved.\n"
    b"Unauthorized copying, distribution, or use is strictly prohibited.\n"
)
ENTERPRISE_MARKER_FIXTURE = (
    b"// enterprise segment: separately licensed under the enterprise agreement\n"
)
ROUTING_FIXTURE_DIGESTS = {
    "gpl3": "sha256:55a770d01573c94c781516fd7067cf69fd409d2cf077a5d32ee1ae0641d96f22",
    "proprietary": "sha256:22ba638b3d6af392701b1ee636be5191d9555e7a564f4f4ad07e1fdc051652cd",
    "enterprise": "sha256:f40addaadfaf50313e54dddad11b7d22b2bacb334225d10b5edbc538091fa967",
}


def test_policy_table_routings() -> None:
    """G-0 node id (issue #190): routing over the maintained policy table."""

    # Fixtures are pinned by digest so the tested bytes are exactly the
    # recorded contract artifacts.
    assert hashlib.sha256(GPL3_HEADER_FIXTURE).hexdigest() == ROUTING_FIXTURE_DIGESTS["gpl3"].removeprefix("sha256:")
    assert hashlib.sha256(PROPRIETARY_MARKER_FIXTURE).hexdigest() == ROUTING_FIXTURE_DIGESTS["proprietary"].removeprefix("sha256:")
    assert hashlib.sha256(ENTERPRISE_MARKER_FIXTURE).hexdigest() == ROUTING_FIXTURE_DIGESTS["enterprise"].removeprefix("sha256:")

    # AC-1: GPL-3.0 evidence (detected from the canonical FSF header) routes
    # study-only with the machine-readable copyleft reason.
    detected, proprietary = detect_routing_evidence((GPL3_HEADER_FIXTURE,))
    assert detected == ("GPL-3.0",)
    assert proprietary is False
    assert routing_for_source(detected).as_field() == {"verdict": STUDY_ONLY, "reason": "copyleft:GPL-3.0"}

    # The same routing holds when the GPL family arrives as SPDX identifiers
    # (manifest or file-header detection) instead of header bytes.
    for expression in ("GPL-3.0", "GPL-3.0-only", "GPL-3.0-or-later", "GPL-2.0", "GPL-2.0-only", "AGPL-3.0-only", "LGPL-2.1-only", "LGPL-3.0-only", "MPL-2.0", "EPL-2.0"):
        routing = routing_for_source((expression,))
        assert routing.verdict == STUDY_ONLY
        assert routing.reason.startswith("copyleft:")
    assert routing_for_source(("GPL-3.0-only",)).reason == "copyleft:GPL-3.0-only"
    assert routing_for_source(("GPL-3.0",)).reason == "copyleft:GPL-3.0"

    # AC-2: proprietary text marker routes study-only/proprietary and never
    # transplant-ok, even alongside permissive evidence.
    detected, proprietary = detect_routing_evidence((PROPRIETARY_MARKER_FIXTURE,))
    assert proprietary is True
    assert routing_for_source(("MIT",), proprietary_marker=proprietary).as_field() == {"verdict": STUDY_ONLY, "reason": "proprietary"}

    # Copyleft texts legitimately mention proprietary works (GPLv3 §10);
    # quotations must not trip the marker — only declarations do.  Regression
    # observed live on tinode/chat's GPLv3 LICENSE.
    gpl_with_proprietary_mentions = GPL3_HEADER_FIXTURE + (
        b"\ninto proprietary programs.  If your program is a subroutine library, you\n"
        b"may consider it more useful to permit linking proprietary applications with\n"
        b"this Library would make it effectively proprietary.\n"
    )
    identifiers, proprietary = detect_routing_evidence((gpl_with_proprietary_mentions,))
    assert identifiers == ("GPL-3.0",)
    assert proprietary is False
    _, proprietary = detect_routing_evidence((b"Available under a proprietary license.\n",))
    assert proprietary is True

    # AC-3: an enterprise/carve-out tree segment forces the most restrictive
    # routing regardless of the permissive root license.
    assert routing_for_source(("MIT",), enterprise_carve_out=True).as_field() == {
        "verdict": STUDY_ONLY,
        "reason": "enterprise-tree-carve-out",
    }
    assert routing_for_source(("GPL-3.0",), enterprise_carve_out=True).as_field() == {
        "verdict": STUDY_ONLY,
        "reason": "enterprise-tree-carve-out",
    }

    # AC-4: permissive detected licenses route transplant-ok.
    for expression in ("MIT", "Apache-2.0", "BSD-2-Clause", "BSD-3-Clause", "ISC", "0BSD"):
        assert routing_for_source((expression,)).as_field() == {"verdict": TRANSPLANT_OK, "reason": f"permissive:{expression}"}
    assert routing_for_source(("MIT OR Apache-2.0",)).as_field() == {
        "verdict": TRANSPLANT_OK,
        "reason": "permissive:Apache-2.0,permissive:MIT",
    }

    # AC-8 / SP-1: inconclusive detection fail-closes to study-only with the
    # license-undetermined reason; there is no neutral routing value.
    assert routing_for_source((None,)).as_field() == {"verdict": STUDY_ONLY, "reason": "license-undetermined"}
    assert routing_for_source(()).as_field() == {"verdict": STUDY_ONLY, "reason": "license-undetermined"}

    # Detected but unclassified, or non-standard LicenseRef terms, also route
    # fail-closed study-only (never guessed permissive).
    for expression in ("CC-BY-4.0", "LicenseRef-Private", "LicenseRef-X AND MIT"):
        assert routing_for_source((expression,)).verdict == STUDY_ONLY

    # SP-2: malformed license payloads (non-text objects) degrade typed
    # instead of crashing the routing engine.
    assert routing_for_source((123, None)).as_field() == {"verdict": STUDY_ONLY, "reason": "license-undetermined"}

    # SP-3: conflicting licenses across tree segments — most restrictive wins
    # and the reason lists every contributor, deterministically.
    mixed = routing_for_source(("MIT", "GPL-3.0"))
    assert mixed.verdict == STUDY_ONLY
    assert mixed.reason == "copyleft:GPL-3.0,permissive:MIT"
    assert routing_for_source(("GPL-3.0", "MIT")).reason == mixed.reason

    # SP-4: a malformed policy table fails closed at load, naming the table.
    with pytest.raises(ValueError, match="license routing policy table is malformed: IDs in both routing classes"):
        validate_routing_policy_table(frozenset({"MIT"}), frozenset({"MIT"}))
    with pytest.raises(ValueError, match="license routing policy table is malformed: IDs outside the pinned SPDX catalog"):
        validate_routing_policy_table(frozenset({"MIT"}), frozenset({"Not-A-Real-SPDX-License"}))


def _routing_corpus_source(root: Path, name: str, files: dict[str, bytes]) -> tuple[str, str, dict[str, object]]:
    """Materialize one fixture source into a corpus; return (spec, sha, index entry)."""

    from leitir.materialize import MANIFEST_NAME
    from leitir.treehash import compute_materialized_tree_hash, manifest_digest_fields

    sha = hashlib.sha1(name.encode("utf-8")).hexdigest()
    spec = f"acme/{name}@{sha}"
    relative = f"repos/github.com/acme/{name}/{sha}"
    target = root / relative
    target.mkdir(parents=True)
    for path, content in sorted(files.items()):
        child = target / path
        child.parent.mkdir(parents=True, exist_ok=True)
        child.write_bytes(content)
    manifest = {
        "host": "github.com",
        "owner": "acme",
        "repo": name,
        "commit_sha": sha,
        "fetch_method": "codeload-tarball",
        "spec": spec,
        "repo_url": f"https://github.com/acme/{name}",
        "fetched_at": "2026-08-20T00:00:00Z",
        "verified": False,
        "verified_at": None,
        "source": "git-commit",
        "version": "1.0.0",
        "version_source": "explicit",
        "parity": "unknown",
        "files_compared": 0,
        "only_in_git": 0,
        "only_in_artifact": 0,
        "docs_urls": [],
        "entry_points": [],
    }
    digest, scope = compute_materialized_tree_hash(target)
    manifest.update(manifest_digest_fields(digest, scope=scope))
    (target / MANIFEST_NAME).write_text(json.dumps(manifest), encoding="utf-8")
    entry: dict[str, object] = {
        "name": f"acme/{name}",
        "host": "github.com",
        "owner": "acme",
        "repo": name,
        "commit_sha": sha,
        "path": relative,
        "fetched_at": manifest["fetched_at"],
    }
    return spec, sha, entry


def test_routing_field_present_in_outputs(tmp_path: Path) -> None:
    """G-0 node id (issue #190): corpus/info/search renderings carry the field."""

    from leitir.cli import _corpus_list, _corpus_routings, _write_summary
    from leitir.info import build_info
    from leitir.search import (
        Coverage,
        CoverageStatus,
        PredicateKind,
        Resolution,
        ResolutionStrategy,
        SearchReport,
        SourceMatch,
        SourceRef,
    )

    gpl_spec, gpl_sha, gpl_entry = _routing_corpus_source(
        tmp_path, "gpl", {"LICENSE": GPL3_HEADER_FIXTURE, "server.py": b"print('gpl')\n"}
    )
    mit_spec, mit_sha, mit_entry = _routing_corpus_source(
        tmp_path, "mit", {"LICENSE-MIT": b"SPDX-License-Identifier: MIT\n", "app.py": b"print('mit')\n"}
    )
    ee_spec, ee_sha, ee_entry = _routing_corpus_source(
        tmp_path,
        "double",
        {
            "LICENSE-MIT": b"SPDX-License-Identifier: MIT\n",
            "app.py": b"print('mixed')\n",
            "ee/enterprise.go": ENTERPRISE_MARKER_FIXTURE,
        },
    )
    from leitir.corpus import write_sources

    write_sources(tmp_path, [gpl_entry, mit_entry, ee_entry])

    # corpus list: every rendered entry carries routing=<verdict>/<reason>.
    out = io.StringIO()
    _corpus_list(tmp_path, as_json=False, out=out)
    lines = [line for line in out.getvalue().splitlines() if line.strip()]
    assert len(lines) == 3
    for line in lines:
        assert " routing=" in line
    by_repo = {line.split(" ")[2].split("@")[0].split("/")[1]: line for line in lines}
    assert "routing=study-only/copyleft:GPL-3.0" in by_repo["gpl"]
    assert "routing=transplant-ok/permissive:MIT" in by_repo["mit"]
    assert "routing=study-only/enterprise-tree-carve-out" in by_repo["double"]

    # corpus list JSON: every item carries the one stable routing key.
    out = io.StringIO()
    _corpus_list(tmp_path, as_json=True, out=out)
    payload = json.loads(out.getvalue())
    assert len(payload) == 3
    for item in payload:
        assert set(item["routing"]) == {"verdict", "reason"}
    json_routing = {item["repo"]: item["routing"] for item in payload}
    assert json_routing["gpl"] == {"verdict": "study-only", "reason": "copyleft:GPL-3.0"}
    assert json_routing["mit"] == {"verdict": "transplant-ok", "reason": "permissive:MIT"}
    assert json_routing["double"] == {"verdict": "study-only", "reason": "enterprise-tree-carve-out"}

    # info document: the license evidence keeps its shape; routing is a
    # stable sibling JSON key (issue #190).
    gpl_info = build_info(gpl_spec, corpus_root=tmp_path)
    mit_info = build_info(mit_spec, corpus_root=tmp_path)
    ee_info = build_info(ee_spec, corpus_root=tmp_path)
    assert gpl_info["license"] == {"identifier": None, "method": "unknown", "confidence": "low"}
    assert gpl_info["routing"] == {"verdict": "study-only", "reason": "copyleft:GPL-3.0"}
    assert mit_info["routing"] == {"verdict": "transplant-ok", "reason": "permissive:MIT"}
    assert ee_info["routing"] == {"verdict": "study-only", "reason": "enterprise-tree-carve-out"}

    # search rendering: corpus-backed matches carry derived routing; matches
    # without corpus license evidence fail closed to undetermined.
    def _match(slug: str, sha: str, path: str) -> SourceMatch:
        return SourceMatch(
            source=SourceRef(
                slug=slug,
                commit_sha=sha,
                path=path,
                blob_sha="0" * 40,
                start_line=1,
                end_line=1,
            ),
            score=1.0,
            matched_kinds=(PredicateKind.EXACT_TEXT,),
        )

    report = SearchReport(
        spec_digest="a" * 64,
        coverage=Coverage(status=CoverageStatus.INDETERMINATE_GLOBAL, files_eligible=3, files_indexed=3, files_excluded=0),
        matches=(
            _match("acme/gpl", gpl_sha, "server.py"),
            _match("acme/mit", mit_sha, "app.py"),
            _match("acme/unknown", "9" * 40, "x.py"),
        ),
        resolution=Resolution(strategy=ResolutionStrategy.INDEXED_COMMIT, as_of="2026-08-20T00:00:00Z"),
    )
    summary = io.StringIO()
    _write_summary(report, file=summary, routings=_corpus_routings(tmp_path))
    rendered = summary.getvalue()
    assert "routing=study-only/copyleft:GPL-3.0" in rendered
    assert "routing=transplant-ok/permissive:MIT" in rendered
    assert "routing=study-only/license-undetermined" in rendered

    # Without corpus context every search match still carries the field,
    # fail-closed (issue #190: search-time detection does not run).
    summary = io.StringIO()
    _write_summary(report, file=summary)
    assert summary.getvalue().count("routing=study-only/license-undetermined") == 3
