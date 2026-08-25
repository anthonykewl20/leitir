"""Tests for the conservative distribution -> import-root catalog (issue #256).

Assertions are at intent level per ``docs/testing.md``. Fixture-backed cases
are discovered via ``test_usage_fixtures.discover_cases()`` and driven by
each case's ``admission.json`` sidecar's ``distribution_records`` list
(added for #256; ignored by the generic corpus tests).
"""

from __future__ import annotations

import json

import pytest
from test_usage_fixtures import CaseFixture, discover_cases

from leitir.usage import ImportMapping, UnresolvedState
from leitir.usage._io import read_portable_file
from leitir.usage.import_catalog import (
    CATALOG_SCHEMA_VERSION,
    DISTRIBUTION_RECORD_SCHEMA_VERSION,
    UNRESOLVED_DISTRIBUTION_SCHEMA_VERSION,
    DistributionRecord,
    ImportCatalog,
    UnresolvedDistribution,
    build_import_catalog,
    normalize_distribution_name,
)

_MAX_SIDECAR_BYTES = 16_384


def _record(distribution: str, roots: tuple[str, ...], source: str) -> DistributionRecord:
    return DistributionRecord(
        schema_version=DISTRIBUTION_RECORD_SCHEMA_VERSION,
        distribution=distribution,
        declared_roots=roots,
        source=source,
    )


# --------------------------------------------------------------------------
# Direct unit tests.
# --------------------------------------------------------------------------


def test_pep503_normalization_groups_dot_dash_underscore_variants() -> None:
    assert normalize_distribution_name("Widget.Lib") == "widget-lib"
    assert normalize_distribution_name("widget_lib") == "widget-lib"
    assert normalize_distribution_name("widget--lib") == "widget-lib"


def test_single_supported_record_resolves_to_an_import_mapping() -> None:
    catalog = build_import_catalog((_record("widgetlib", ("widgetlib",), "top-level-txt"),))
    assert isinstance(catalog, ImportCatalog)
    assert catalog.schema_version == CATALOG_SCHEMA_VERSION
    assert catalog.unresolved == ()
    assert len(catalog.mappings) == 1
    mapping = catalog.mappings[0]
    assert isinstance(mapping, ImportMapping)
    assert mapping.distribution == "widgetlib"
    assert mapping.import_roots == ("widgetlib",)


def test_multi_root_distribution_from_one_coherent_source_is_resolved_not_ambiguous() -> None:
    catalog = build_import_catalog((_record("widgetlib", ("widgetlib", "widgetlib_ext"), "top-level-txt"),))
    assert catalog.unresolved == ()
    assert len(catalog.mappings) == 1
    assert set(catalog.mappings[0].import_roots) == {"widgetlib", "widgetlib_ext"}


def test_missing_evidence_is_typed_unsupported_not_a_guess() -> None:
    catalog = build_import_catalog((_record("widgetlib", (), "top-level-txt"),))
    assert catalog.mappings == ()
    assert len(catalog.unresolved) == 1
    unresolved = catalog.unresolved[0]
    assert isinstance(unresolved, UnresolvedDistribution)
    assert unresolved.schema_version == UNRESOLVED_DISTRIBUTION_SCHEMA_VERSION
    assert unresolved.distribution == "widgetlib"
    assert unresolved.state == UnresolvedState.UNSUPPORTED_SYNTAX
    assert unresolved.evidence  # raw evidence preserved


def test_unsupported_evidence_source_is_typed_unsupported() -> None:
    catalog = build_import_catalog((_record("widgetlib", ("widgetlib",), "namespace-pth-file"),))
    assert catalog.mappings == ()
    (unresolved,) = catalog.unresolved
    assert unresolved.state == UnresolvedState.UNSUPPORTED_SYNTAX


def test_ambiguous_normalized_name_collision_never_picks_one() -> None:
    records = (
        _record("widget-lib", ("widget_lib",), "top-level-txt"),
        _record("widget_lib", ("widgetlib",), "top-level-txt"),
    )
    catalog = build_import_catalog(records)
    assert catalog.mappings == ()
    assert {u.distribution for u in catalog.unresolved} == {"widget-lib", "widget_lib"}
    assert all(u.state == UnresolvedState.AMBIGUOUS_BINDING for u in catalog.unresolved)


def test_ambiguous_disagreeing_sources_for_same_distribution_never_pick_one() -> None:
    records = (
        _record("widgetlib", ("widgetlib",), "top-level-txt"),
        _record("widgetlib", ("widgetlib_other",), "record-derived-single-root"),
    )
    catalog = build_import_catalog(records)
    assert catalog.mappings == ()
    (unresolved,) = catalog.unresolved
    assert unresolved.state == UnresolvedState.AMBIGUOUS_BINDING
    assert len(unresolved.evidence) == 2


def test_two_distributions_claiming_the_same_root_are_both_ambiguous() -> None:
    records = (
        _record("widgetlib-a", ("shared_root",), "top-level-txt"),
        _record("widgetlib-b", ("shared_root",), "top-level-txt"),
    )
    catalog = build_import_catalog(records)
    assert catalog.mappings == ()
    assert {u.distribution for u in catalog.unresolved} == {"widgetlib-a", "widgetlib-b"}
    assert all(u.state == UnresolvedState.AMBIGUOUS_BINDING for u in catalog.unresolved)


def test_agreeing_duplicate_sources_for_same_distribution_still_resolve() -> None:
    records = (
        _record("widgetlib", ("widgetlib",), "top-level-txt"),
        _record("widgetlib", ("widgetlib",), "record-derived-single-root"),
    )
    catalog = build_import_catalog(records)
    assert catalog.unresolved == ()
    assert len(catalog.mappings) == 1
    assert catalog.mappings[0].import_roots == ("widgetlib",)


def test_does_not_infer_an_import_root_from_the_distribution_name_alone() -> None:
    """No evidence at all for a name that *looks* obvious must still be unresolved."""

    catalog = build_import_catalog((_record("some-oddly-named-thing", (), "top-level-txt"),))
    assert catalog.mappings == ()
    (unresolved,) = catalog.unresolved
    assert unresolved.state == UnresolvedState.UNSUPPORTED_SYNTAX


def test_empty_batch_produces_an_empty_catalog() -> None:
    catalog = build_import_catalog(())
    assert catalog.mappings == ()
    assert catalog.unresolved == ()


# --------------------------------------------------------------------------
# Fixture-driven cases (tests/fixtures/usage/*/admission.json's distribution_records).
# --------------------------------------------------------------------------


def _catalog_cases() -> list[CaseFixture]:
    cases = []
    for case in discover_cases():
        sidecar_path = case.directory / "admission.json"
        if not sidecar_path.is_file():
            continue
        raw = read_portable_file(sidecar_path, maximum_bytes=_MAX_SIDECAR_BYTES)
        payload = json.loads(raw.decode("utf-8"))
        if "distribution_records" in payload:
            cases.append(case)
    return cases


def _load_records(case: CaseFixture) -> tuple[dict[str, object], tuple[DistributionRecord, ...]]:
    raw = read_portable_file(case.directory / "admission.json", maximum_bytes=_MAX_SIDECAR_BYTES)
    payload = json.loads(raw.decode("utf-8"))
    records = tuple(
        DistributionRecord(
            schema_version=str(item["schema_version"]),
            distribution=str(item["distribution"]),
            declared_roots=tuple(str(root) for root in item["declared_roots"]),
            source=str(item["source"]),
        )
        for item in payload["distribution_records"]
    )
    return payload, records


@pytest.mark.parametrize("case", _catalog_cases(), ids=lambda case: case.name)
def test_fixture_catalog_scenarios_match_expected_outcome(case: CaseFixture) -> None:
    payload, records = _load_records(case)
    catalog = build_import_catalog(records)

    expected_outcome = payload["expected_outcome"]
    if expected_outcome == "resolved":
        assert catalog.unresolved == ()
        assert len(catalog.mappings) == 1
        expected_roots = set(payload["expected_import_roots"])  # type: ignore[arg-type]
        assert set(catalog.mappings[0].import_roots) == expected_roots
    else:
        assert expected_outcome == "unresolved"
        assert catalog.mappings == ()
        assert len(catalog.unresolved) >= 1
        expected_state = UnresolvedState(str(payload["expected_state"]))
        assert all(u.state == expected_state for u in catalog.unresolved)


def test_fixture_corpus_has_at_least_one_catalog_sidecar() -> None:
    assert _catalog_cases(), "expected at least one fixture case with distribution_records"
