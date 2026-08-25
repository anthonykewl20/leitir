"""Tests for the consumer admission gate (issue #256).

Assertions are at intent level per ``docs/testing.md``: exact typed error
classes, and byte-for-byte retention of dependency evidence for admitted
consumers. Fixture-backed cases are discovered via
``test_usage_fixtures.discover_cases()`` and driven by each case's
``admission.json`` sidecar (added for #256; ignored by the generic corpus
tests in ``tests/test_usage_fixtures.py``).
"""

from __future__ import annotations

import json

import pytest
from test_usage_fixtures import CaseFixture, discover_cases

from leitir.safeio import read_regular_file
from leitir.usage import UsageMalformedError, UsageTamperError, UsageUnsupportedError
from leitir.usage._canonical import digest_bytes
from leitir.usage.admission import (
    ADMITTED_CONSUMER_SCHEMA_VERSION,
    PINNED_REQUIREMENT_SCHEMA_VERSION,
    REQUIREMENTS_PARSER_NAME,
    REQUIREMENTS_PARSER_VERSION,
    AdmittedConsumer,
    PinnedRequirement,
    admit_consumer,
    parse_exact_pins,
)

_MAX_SIDECAR_BYTES = 16_384
_PINNED_SHA = "a" * 40
_OTHER_SHA = "b" * 40


def _admission_cases() -> list[CaseFixture]:
    cases = []
    for case in discover_cases():
        if (case.directory / "admission.json").is_file():
            cases.append(case)
    return cases


def _load_sidecar(case: CaseFixture) -> dict[str, object]:
    raw = read_regular_file(case.directory / "admission.json", maximum_bytes=_MAX_SIDECAR_BYTES, no_follow=True)
    payload = json.loads(raw.decode("utf-8"))
    assert isinstance(payload, dict)
    return payload


def _admission_scenarios() -> list[CaseFixture]:
    return [case for case in _admission_cases() if "consumer_ref" in _load_sidecar(case)]


# --------------------------------------------------------------------------
# Direct unit tests: happy path, exact-pin parsing.
# --------------------------------------------------------------------------


def test_admits_a_sha_pinned_consumer_with_exact_pins() -> None:
    requirements = b"widgetlib==1.2.3\nother-lib==0.4.0\n"
    digest = digest_bytes(requirements)
    admitted = admit_consumer(
        consumer_name="demo-consumer",
        consumer_version="0.1.0",
        consumer_ref=_PINNED_SHA,
        expected_consumer_ref=_PINNED_SHA,
        requirements_bytes=requirements,
        recorded_requirements_digest=digest,
    )
    assert isinstance(admitted, AdmittedConsumer)
    assert admitted.schema_version == ADMITTED_CONSUMER_SCHEMA_VERSION
    assert admitted.consumer_identity.role == "consumer"
    assert admitted.consumer_identity.name == "demo-consumer"
    # The full dependency evidence is retained byte-for-byte -- not re-derived.
    assert admitted.dependency_evidence.requirements_text == requirements.decode("utf-8")
    assert admitted.dependency_evidence.requirements_digest == digest
    assert admitted.dependency_evidence.parser_name == REQUIREMENTS_PARSER_NAME
    assert admitted.dependency_evidence.parser_version == REQUIREMENTS_PARSER_VERSION
    assert [pin.distribution for pin in admitted.direct_pins] == ["widgetlib", "other-lib"]
    assert all(isinstance(pin, PinnedRequirement) for pin in admitted.direct_pins)
    assert all(pin.schema_version == PINNED_REQUIREMENT_SCHEMA_VERSION for pin in admitted.direct_pins)


def test_ignores_blank_lines_and_comments_when_parsing_exact_pins() -> None:
    text = "# a comment\n\nwidgetlib==1.2.3\n   \n# another\nother-lib==2.0.0\n"
    pins = parse_exact_pins(text)
    assert [(pin.distribution, pin.version) for pin in pins] == [
        ("widgetlib", "1.2.3"),
        ("other-lib", "2.0.0"),
    ]


@pytest.mark.parametrize(
    "line",
    [
        "widgetlib>=1.2.3",
        "widgetlib~=1.2.3",
        "widgetlib!=1.2.3",
        "widgetlib<=1.2.3",
        "widgetlib<1.2.3",
        "widgetlib>1.2.3",
        "widgetlib==1.2.*",
        "widgetlib",
        "widgetlib[extra]==1.2.3",
        "widgetlib==1.2.3; python_version >= '3.11'",
        "git+https://example.com/widgetlib.git",
        "widgetlib @ https://example.com/widgetlib-1.2.3.tar.gz",
        "-e ./local-widgetlib",
    ],
)
def test_range_and_unpinned_and_url_requirement_shapes_are_rejected(line: str) -> None:
    with pytest.raises(UsageUnsupportedError) as excinfo:
        parse_exact_pins(f"{line}\n")
    assert excinfo.value.kind == "usage_unsupported"


def test_empty_requirements_text_is_rejected_as_unsupported() -> None:
    with pytest.raises(UsageUnsupportedError):
        parse_exact_pins("\n\n# only comments\n")


# --------------------------------------------------------------------------
# Direct unit tests: SP-1 sad paths (tamper, ambiguity-adjacent rejection).
# --------------------------------------------------------------------------


def test_tamper_floating_consumer_ref_is_rejected_as_unsupported() -> None:
    requirements = b"widgetlib==1.2.3\n"
    digest = digest_bytes(requirements)
    with pytest.raises(UsageUnsupportedError) as excinfo:
        admit_consumer(
            consumer_name="demo-consumer",
            consumer_version="0.1.0",
            consumer_ref="main",
            expected_consumer_ref="main",
            requirements_bytes=requirements,
            recorded_requirements_digest=digest,
        )
    assert excinfo.value.evidence.field == "consumer_ref"


def test_tamper_consumer_sha_mismatch_is_rejected() -> None:
    requirements = b"widgetlib==1.2.3\n"
    digest = digest_bytes(requirements)
    with pytest.raises(UsageTamperError) as excinfo:
        admit_consumer(
            consumer_name="demo-consumer",
            consumer_version="0.1.0",
            consumer_ref=_PINNED_SHA,
            expected_consumer_ref=_OTHER_SHA,
            requirements_bytes=requirements,
            recorded_requirements_digest=digest,
        )
    assert excinfo.value.kind == "usage_tamper"
    assert excinfo.value.evidence.field == "consumer_ref"
    assert excinfo.value.evidence.expected == _OTHER_SHA
    assert excinfo.value.evidence.actual == _PINNED_SHA


def test_tamper_requirements_digest_mismatch_is_rejected_and_retains_no_claim() -> None:
    requirements = b"widgetlib==1.2.3\n"
    wrong_digest = digest_bytes(b"widgetlib==9.9.9\n")
    with pytest.raises(UsageTamperError) as excinfo:
        admit_consumer(
            consumer_name="demo-consumer",
            consumer_version="0.1.0",
            consumer_ref=_PINNED_SHA,
            expected_consumer_ref=_PINNED_SHA,
            requirements_bytes=requirements,
            recorded_requirements_digest=wrong_digest,
        )
    assert excinfo.value.kind == "usage_tamper"
    assert excinfo.value.evidence.field == "requirements_bytes"


def test_non_utf8_requirements_bytes_are_rejected_as_malformed_not_bare_unicode_error() -> None:
    # requirements_bytes must digest-match recorded_requirements_digest to
    # reach the decode step at all; use its own digest so the tamper check
    # passes and the decode failure is what's actually exercised.
    requirements = b"widgetlib==1.2.3\n# \xff\xfe not valid utf-8\n"
    digest = digest_bytes(requirements)
    with pytest.raises(UsageMalformedError) as excinfo:
        admit_consumer(
            consumer_name="demo-consumer",
            consumer_version="0.1.0",
            consumer_ref=_PINNED_SHA,
            expected_consumer_ref=_PINNED_SHA,
            requirements_bytes=requirements,
            recorded_requirements_digest=digest,
        )
    assert excinfo.value.kind == "usage_malformed"
    assert excinfo.value.evidence.field == "requirements_bytes"


def test_tamper_consumer_ref_mismatch_never_constructs_dependency_evidence() -> None:
    """A rejected consumer must never leak a partially-built dependency claim."""

    requirements = b"widgetlib==1.2.3\n"
    digest = digest_bytes(requirements)
    try:
        admit_consumer(
            consumer_name="demo-consumer",
            consumer_version="0.1.0",
            consumer_ref=_PINNED_SHA,
            expected_consumer_ref=_OTHER_SHA,
            requirements_bytes=requirements,
            recorded_requirements_digest=digest,
        )
    except UsageTamperError as exc:
        payload = exc.to_json()
        assert "requirements_text" not in json.dumps(payload)
        return
    raise AssertionError("expected UsageTamperError")


# --------------------------------------------------------------------------
# Fixture-driven cases (tests/fixtures/usage/*/admission.json).
# --------------------------------------------------------------------------


@pytest.mark.parametrize("case", _admission_scenarios(), ids=lambda case: case.name)
def test_fixture_admission_scenarios_match_expected_outcome(case: CaseFixture) -> None:
    sidecar = _load_sidecar(case)
    requirements_path = case.directory / str(case.manifest["requirements_file"])
    requirements_bytes = read_regular_file(requirements_path, maximum_bytes=65_536, no_follow=True)

    kwargs = dict(
        consumer_name=str(sidecar["consumer_name"]),
        consumer_version=str(sidecar["consumer_version"]),
        consumer_ref=str(sidecar["consumer_ref"]),
        expected_consumer_ref=str(sidecar["expected_consumer_ref"]),
        requirements_bytes=requirements_bytes,
        recorded_requirements_digest=str(sidecar["recorded_requirements_digest"]),
    )

    expected_outcome = sidecar["expected_outcome"]
    if expected_outcome == "admit":
        admitted = admit_consumer(**kwargs)
        assert isinstance(admitted, AdmittedConsumer)
        assert admitted.dependency_evidence.requirements_text == requirements_bytes.decode("utf-8")
    else:
        assert expected_outcome == "reject"
        error_type = {"UsageUnsupportedError": UsageUnsupportedError, "UsageTamperError": UsageTamperError}[
            str(sidecar["expected_error"])
        ]
        with pytest.raises(error_type):
            admit_consumer(**kwargs)


def test_fixture_corpus_has_at_least_one_admission_sidecar() -> None:
    assert _admission_scenarios(), "expected at least one fixture case with an admission.json sidecar"
