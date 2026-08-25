"""Contract tests for the usage evidence and offline replay schema (issue #255).

Assertions are at intent level per ``docs/testing.md``: exact typed error
classes, exact digests where stable, and byte-equality for replay and for
the canonical report encoding.
"""

from __future__ import annotations

import copy
import sys

import pytest
from test_usage_fixtures import CaseFixture, discover_cases

from leitir.usage import (
    CODE_REFERENCE_SCHEMA_VERSION,
    IDENTITY_SCHEMA_VERSION,
    REPORT_SCHEMA_VERSION,
    CoverageRecord,
    CoverageSummary,
    DependencyEvidence,
    Identity,
    ImportMapping,
    LicenseSnippetEvidence,
    SourceSpan,
    UnresolvedState,
    UsageMalformedError,
    UsageReport,
    UsageTamperError,
    UsageUnsupportedError,
    build_report,
    replay_report,
    report_from_dict,
    report_from_json_bytes,
)
from leitir.usage._canonical import digest_bytes, digest_value
from leitir.usage._io import read_portable_file

_MAX_REPORT_BYTES = 65_536


def _load_report_bytes(case: CaseFixture) -> bytes:
    report_path = case.directory / str(case.manifest["report_file"])
    return read_portable_file(report_path, maximum_bytes=_MAX_REPORT_BYTES)


def _valid_cases() -> list[CaseFixture]:
    return [case for case in discover_cases() if case.manifest["expect"] == "valid"]


def _tamper_cases() -> list[CaseFixture]:
    return [case for case in discover_cases() if case.manifest["expect"] == "tamper"]


def _minimal_report() -> UsageReport:
    """A hand-built, self-consistent report for unit-level (non-fixture) tests."""

    provider = Identity(
        schema_version=IDENTITY_SCHEMA_VERSION,
        role="provider",
        name="widgetlib",
        version="1.2.3",
        digest=digest_value({"name": "widgetlib", "version": "1.2.3"}),
    )
    consumer = Identity(
        schema_version=IDENTITY_SCHEMA_VERSION,
        role="consumer",
        name="unit-consumer",
        version="0.1.0",
        digest=digest_value({"name": "unit-consumer"}),
    )
    requirements_text = "widgetlib==1.2.3\n"
    dependency = DependencyEvidence(
        schema_version="leitir-usage-dependency-v1",
        requirements_text=requirements_text,
        requirements_digest=digest_bytes(requirements_text.encode("utf-8")),
        parser_name="leitir-requirements-parser",
        parser_version="v1",
    )
    span = SourceSpan(file="app.py", start_line=1, start_col=0, end_line=1, end_col=16)
    code_reference = _code_reference(span)
    coverage = CoverageSummary(
        schema_version="leitir-usage-coverage-v1",
        records=(CoverageRecord(schema_version="leitir-usage-coverage-record-v1", file="app.py", state=UnresolvedState.RESOLVED),),
        exclusions=(),
        cap=10,
        capped=False,
    )
    license_evidence = LicenseSnippetEvidence(
        schema_version="leitir-usage-license-v1",
        span=span,
        license_guess="MIT",
        confidence="low",
        advisory=True,
    )
    return build_report(
        provider_identity=provider,
        consumer_identity=consumer,
        dependency_evidence=dependency,
        import_mappings=(ImportMapping(schema_version="leitir-usage-import-mapping-v1", distribution="widgetlib", import_roots=("widgetlib",)),),
        references=(code_reference,),
        coverage=coverage,
        license_evidence=(license_evidence,),
    )


def _code_reference(span: SourceSpan):
    from leitir.usage.contract import CodeReference

    return CodeReference(
        schema_version=CODE_REFERENCE_SCHEMA_VERSION,
        distribution="widgetlib",
        span=span,
        code_digest=digest_bytes(b"import widgetlib"),
    )


# ---------------------------------------------------------------------------
# Closed-schema validation.
# ---------------------------------------------------------------------------


def test_report_from_dict_rejects_unknown_top_level_field() -> None:
    payload = _minimal_report().to_dict()
    payload["unexpected_extra_field"] = "surprise"
    with pytest.raises(UsageMalformedError) as excinfo:
        report_from_dict(payload)
    assert excinfo.value.kind == "usage_malformed"
    assert "unknown fields" in excinfo.value.evidence.message


def test_report_from_dict_rejects_missing_top_level_field() -> None:
    payload = _minimal_report().to_dict()
    del payload["coverage"]
    with pytest.raises(UsageMalformedError) as excinfo:
        report_from_dict(payload)
    assert "missing required fields" in excinfo.value.evidence.message


def test_report_from_dict_rejects_unknown_nested_field() -> None:
    payload = _minimal_report().to_dict()
    payload["provider_identity"] = dict(payload["provider_identity"], surprise=True)
    with pytest.raises(UsageMalformedError):
        report_from_dict(payload)


@pytest.mark.parametrize(
    "corruption",
    [
        lambda p: p.__setitem__("cap", "not-an-int"),
        lambda p: p.__setitem__("cap", -1),
        lambda p: p.__setitem__("capped", "not-a-bool"),
    ],
)
def test_report_from_dict_rejects_wrong_field_types(corruption) -> None:
    payload = _minimal_report().to_dict()
    corruption(payload["coverage"])
    with pytest.raises(UsageMalformedError):
        report_from_dict(payload)


def test_report_from_dict_rejects_unknown_unresolved_state() -> None:
    payload = _minimal_report().to_dict()
    payload["coverage"]["records"][0]["state"] = "not-a-real-state"
    with pytest.raises(UsageMalformedError):
        report_from_dict(payload)


def test_report_from_dict_rejects_non_advisory_license_evidence() -> None:
    payload = _minimal_report().to_dict()
    payload["license_evidence"][0]["advisory"] = False
    with pytest.raises(UsageMalformedError):
        report_from_dict(payload)


def test_report_from_dict_rejects_unsupported_schema_version() -> None:
    payload = _minimal_report().to_dict()
    payload["schema_version"] = "leitir-usage-report-v99"
    with pytest.raises(UsageUnsupportedError) as excinfo:
        report_from_dict(payload)
    assert excinfo.value.kind == "usage_unsupported"
    assert excinfo.value.evidence.expected == REPORT_SCHEMA_VERSION


def test_report_from_dict_rejects_unsupported_nested_schema_version() -> None:
    payload = _minimal_report().to_dict()
    payload["dependency_evidence"]["schema_version"] = "leitir-usage-dependency-v99"
    with pytest.raises(UsageUnsupportedError):
        report_from_dict(payload)


def test_report_from_json_bytes_rejects_malformed_json() -> None:
    with pytest.raises(UsageMalformedError):
        report_from_json_bytes(b"{not valid json")


def test_report_from_json_bytes_rejects_non_utf8_bytes() -> None:
    with pytest.raises(UsageMalformedError):
        report_from_json_bytes(b"\xff\xfe\x00\x01")


def test_report_round_trips_through_json_bytes() -> None:
    report = _minimal_report()
    parsed = report_from_json_bytes(report.to_json_bytes())
    assert parsed == report


# ---------------------------------------------------------------------------
# Digest stability and self-consistency ("tamper" before replay).
# ---------------------------------------------------------------------------


def test_report_digest_is_stable_across_independent_builds() -> None:
    first = _minimal_report()
    second = _minimal_report()
    assert first.report_digest == second.report_digest
    assert first.to_json_bytes() == second.to_json_bytes()


def test_report_digest_changes_when_content_changes() -> None:
    first = _minimal_report()
    second = build_report(
        provider_identity=first.provider_identity,
        consumer_identity=first.consumer_identity,
        dependency_evidence=first.dependency_evidence,
        import_mappings=first.import_mappings,
        references=first.references,
        coverage=first.coverage,
        license_evidence=first.license_evidence,
        tool_version="leitir-usage-tool-v2-hypothetical",
    )
    assert first.report_digest != second.report_digest


def test_report_from_dict_rejects_tampered_report_digest_before_touching_disk() -> None:
    """A self-inconsistent report_digest is rejected at validate time -- no fixture, no I/O."""

    report = _minimal_report()
    payload = report.to_dict()
    payload["report_digest"] = "sha256:" + "0" * 64
    with pytest.raises(UsageTamperError) as excinfo:
        report_from_dict(payload)
    assert excinfo.value.kind == "usage_tamper"
    assert excinfo.value.evidence.stage == "validate"


def test_report_from_dict_rejects_tampered_dependency_digest() -> None:
    report = _minimal_report()
    payload = report.to_dict()
    payload["dependency_evidence"]["requirements_digest"] = "sha256:" + "1" * 64
    # The report_digest still matches the (unmodified) `to_dict()` output
    # only if we recompute it; leave report_digest untouched so the failure
    # is attributed specifically to the dependency-evidence self-check.
    with pytest.raises(UsageTamperError):
        report_from_dict(payload)


def test_error_to_json_is_a_machine_readable_dict() -> None:
    report = _minimal_report()
    payload = report.to_dict()
    payload["report_digest"] = "sha256:" + "0" * 64
    try:
        report_from_dict(payload)
    except UsageTamperError as exc:
        as_json = exc.to_json()
        assert as_json["kind"] == "usage_tamper"
        assert as_json["stage"] == "validate"
        assert isinstance(as_json["message"], str) and as_json["message"]
    else:  # pragma: no cover - defensive
        pytest.fail("expected UsageTamperError")


# ---------------------------------------------------------------------------
# Fixture-corpus-driven validate + offline replay.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("case", _valid_cases(), ids=lambda case: case.name)
def test_valid_fixture_cases_validate_and_replay_offline(case: CaseFixture) -> None:
    report = report_from_json_bytes(_load_report_bytes(case))

    # Identities are present, SHA-pinned, and carry the roles the schema requires.
    assert report.provider_identity.role == "provider"
    assert report.consumer_identity.role == "consumer"
    assert report.provider_identity.digest.startswith("sha256:")
    assert report.consumer_identity.digest.startswith("sha256:")

    # Dependency evidence: exact bytes, digest, and parser identity/version.
    requirements_path = case.directory / str(case.manifest["requirements_file"])
    on_disk_requirements = read_portable_file(requirements_path, maximum_bytes=65_536)
    assert report.dependency_evidence.requirements_text.encode("utf-8") == on_disk_requirements
    assert report.dependency_evidence.requirements_digest == digest_bytes(on_disk_requirements)
    assert report.dependency_evidence.parser_name
    assert report.dependency_evidence.parser_version

    # Distribution -> import roots mapping.
    assert report.import_mappings
    for mapping in report.import_mappings:
        assert mapping.import_roots

    # Spans and per-span code digests.
    assert report.references
    for reference in report.references:
        assert reference.span.file
        assert reference.code_digest.startswith("sha256:")

    # Coverage: records, exclusions, cap, and the typed unresolved state.
    expected_state = UnresolvedState(str(case.manifest["expected_state"]))
    assert {record.state for record in report.coverage.records} == {expected_state}
    assert report.coverage.cap >= 1
    assert isinstance(report.coverage.capped, bool)

    # Advisory-only license evidence.
    for evidence in report.license_evidence:
        assert evidence.advisory is True
        assert evidence.confidence in {"low", "medium", "high"}

    # Report digest is present and self-consistent.
    assert report.recompute_digest() == report.report_digest

    # Offline replay: byte-identical, no substitution, and no import/execution
    # of the consumer code (widgetlib is never imported by this process).
    replayed = replay_report(report, corpus_root=case.directory, dependency_path=requirements_path)
    assert replayed == report
    assert replayed.to_json_bytes() == report.to_json_bytes()
    assert "widgetlib" not in sys.modules


@pytest.mark.parametrize("case", _valid_cases(), ids=lambda case: case.name)
def test_replay_is_idempotent_and_deterministic(case: CaseFixture) -> None:
    report = report_from_json_bytes(_load_report_bytes(case))
    requirements_path = case.directory / str(case.manifest["requirements_file"])
    first = replay_report(report, corpus_root=case.directory, dependency_path=requirements_path)
    second = replay_report(report, corpus_root=case.directory, dependency_path=requirements_path)
    assert first.to_json_bytes() == second.to_json_bytes() == report.to_json_bytes()


def test_determinism_case_report_digest_matches_independent_recomputation() -> None:
    cases = {case.name: case for case in discover_cases()}
    case = cases["determinism"]
    report = report_from_json_bytes(_load_report_bytes(case))
    # Recomputing from a deep-copied dict representation must be byte-identical.
    payload_copy = copy.deepcopy(report.to_dict())
    reparsed = report_from_dict(payload_copy)
    assert reparsed.report_digest == report.report_digest
    assert reparsed.to_json_bytes() == report.to_json_bytes()


# ---------------------------------------------------------------------------
# SP-1: tampered evidence/fixture bytes are rejected before replay.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("case", _tamper_cases(), ids=lambda case: case.name)
def test_tamper_fixture_cases_are_rejected_not_silently_replayed(case: CaseFixture) -> None:
    manifest = case.manifest
    assert manifest["expected_error"] == "UsageTamperError"

    # The report itself is self-consistent (validate succeeds) -- the tamper
    # is only observable by replaying against the actual on-disk bytes.
    report = report_from_json_bytes(_load_report_bytes(case))
    assert report.recompute_digest() == report.report_digest

    requirements_path = case.directory / str(manifest["requirements_file"])
    with pytest.raises(UsageTamperError) as excinfo:
        replay_report(report, corpus_root=case.directory, dependency_path=requirements_path)
    assert excinfo.value.kind == "usage_tamper"
    assert excinfo.value.evidence.stage == "replay"
    # The mismatch must be caught before any consumer import/execution.
    assert "widgetlib" not in sys.modules


def test_tampered_report_digest_is_rejected_before_any_replay_attempt(tmp_path) -> None:
    """A validate-stage tamper never reaches replay_report at all."""

    report = _minimal_report()
    payload = report.to_dict()
    payload["report_digest"] = "sha256:" + "f" * 64
    with pytest.raises(UsageTamperError) as excinfo:
        report_from_dict(payload)
    assert excinfo.value.evidence.stage == "validate"
    # tmp_path is untouched: report_from_dict never performed any I/O.
    assert list(tmp_path.iterdir()) == []


def test_tampered_requirements_bytes_are_rejected_during_replay(tmp_path) -> None:
    report = _minimal_report()
    (tmp_path / "app.py").write_text("import widgetlib\n", encoding="utf-8")
    requirements_path = tmp_path / "requirements.txt"
    # Differs from the report's recorded "widgetlib==1.2.3\n".
    requirements_path.write_text("widgetlib==9.9.9\n", encoding="utf-8")
    with pytest.raises(UsageTamperError) as excinfo:
        replay_report(report, corpus_root=tmp_path, dependency_path=requirements_path)
    assert excinfo.value.evidence.stage == "replay"
    assert "requirements" in (excinfo.value.evidence.field or "")


def test_tampered_code_span_bytes_are_rejected_during_replay(tmp_path) -> None:
    report = _minimal_report()
    requirements_path = tmp_path / "requirements.txt"
    requirements_path.write_text("widgetlib==1.2.3\n", encoding="utf-8")
    # The reported span covers columns [0:16) of line 1 ("import widgetlib");
    # tamper a character inside that window so the recomputed digest differs.
    (tmp_path / "app.py").write_text("import widgetlub\n", encoding="utf-8")
    with pytest.raises(UsageTamperError) as excinfo:
        replay_report(report, corpus_root=tmp_path, dependency_path=requirements_path)
    assert excinfo.value.evidence.stage == "replay"
    assert "code_digest" in (excinfo.value.evidence.field or "")
