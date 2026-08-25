"""Tests for the deterministic usage evidence assembler (issue #258).

``leitir.usage.assemble.assemble_usage_evidence`` never imports/execs
consumer code; several cases below feed it real resolver output produced
against small fixture trees under ``tests/fixtures/usage/assemble/`` (that
subdirectory has no ``manifest.json`` of its own, so
``tests/test_usage_fixtures.py``'s corpus discovery -- which only looks at
immediate children of ``tests/fixtures/usage/`` -- does not pick it up).
Other cases hand-construct typed evidence directly to exercise dedup,
conflict, and cap behavior precisely and deterministically.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

from leitir.usage import (
    CODE_REFERENCE_SCHEMA_VERSION,
    COVERAGE_SUMMARY_SCHEMA_VERSION,
    DEPENDENCY_EVIDENCE_SCHEMA_VERSION,
    IDENTITY_SCHEMA_VERSION,
    IMPORT_MAPPING_SCHEMA_VERSION,
    CodeReference,
    CoverageSummary,
    DependencyEvidence,
    Identity,
    ImportMapping,
    SourceSpan,
    UnresolvedState,
    UsageUnsupportedError,
)
from leitir.usage._canonical import digest_bytes, digest_value
from leitir.usage.assemble import (
    MAX_LICENSE_SNIPPETS_PER_RESULT,
    REFERENCE_BATCH_SCHEMA_VERSION,
    ReferenceBatch,
    assemble_usage_evidence,
)
from leitir.usage.import_catalog import (
    UNRESOLVED_DISTRIBUTION_SCHEMA_VERSION,
    DistributionRecord,
    UnresolvedDistribution,
)
from leitir.usage.resolver import resolve_consumer

FIXTURES_ROOT = Path(__file__).resolve().parent / "fixtures" / "usage" / "assemble"

_WIDGETLIB_ROOTS = {"widgetlib": "widgetlib"}


def _identity(role: str, name: str, version: str) -> Identity:
    return Identity(
        schema_version=IDENTITY_SCHEMA_VERSION,
        role=role,
        name=name,
        version=version,
        digest=digest_value({"role": role, "name": name, "version": version}),
    )


def _dependency_evidence() -> DependencyEvidence:
    text = "widgetlib==1.2.3\n"
    return DependencyEvidence(
        schema_version=DEPENDENCY_EVIDENCE_SCHEMA_VERSION,
        requirements_text=text,
        requirements_digest=digest_bytes(text.encode("utf-8")),
        parser_name="leitir-usage-exact-pin-parser",
        parser_version="v1",
    )


def _import_mappings() -> tuple[ImportMapping, ...]:
    return (
        ImportMapping(schema_version=IMPORT_MAPPING_SCHEMA_VERSION, distribution="widgetlib", import_roots=("widgetlib",)),
    )


def _batch_from_resolver(case: str, *, origin: str) -> ReferenceBatch:
    result = resolve_consumer(consumer_root=FIXTURES_ROOT / case / "consumer", import_roots=_WIDGETLIB_ROOTS)
    return ReferenceBatch(schema_version=REFERENCE_BATCH_SCHEMA_VERSION, origin=origin, references=result.references, coverage=result.coverage)


def _reference(distribution: str, file: str, line: int, *, digest_seed: str, end_col: int = 9) -> CodeReference:
    return CodeReference(
        schema_version=CODE_REFERENCE_SCHEMA_VERSION,
        distribution=distribution,
        span=SourceSpan(file=file, start_line=line, start_col=0, end_line=line, end_col=end_col),
        code_digest=digest_bytes(digest_seed.encode("utf-8")),
    )


def _empty_coverage() -> CoverageSummary:
    return CoverageSummary(schema_version=COVERAGE_SUMMARY_SCHEMA_VERSION, records=(), exclusions=(), cap=10_000, capped=False)


def _assemble(**overrides: object) -> object:
    kwargs: dict[str, object] = {
        "provider_identity": _identity("provider", "widgetlib", "1.2.3"),
        "consumer_identity": _identity("consumer", "consumer-app", "0.1.0"),
        "dependency_evidence": _dependency_evidence(),
        "import_mappings": _import_mappings(),
        "reference_batches": (),
        "unresolved_distributions": (),
        "consumer_root": None,
        "path_prefix": "",
    }
    kwargs.update(overrides)
    return assemble_usage_evidence(**kwargs)  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# AC-1: byte-stable double run.
# ---------------------------------------------------------------------------


def test_double_run_is_byte_identical() -> None:
    batch = _batch_from_resolver("license_known", origin="resolver-run")
    kwargs = {
        "reference_batches": (batch,),
        "consumer_root": FIXTURES_ROOT / "license_known" / "consumer",
    }
    first = _assemble(**kwargs)
    second = _assemble(**kwargs)
    assert first.to_json_bytes() == second.to_json_bytes()
    assert first.to_json_bytes()  # non-trivial


def test_double_run_is_byte_identical_across_subprocess_hashseeds() -> None:
    script = (
        "import sys; sys.path.insert(0, 'src'); sys.path.insert(0, 'tests')\n"
        "from test_usage_assemble import _assemble, _batch_from_resolver, FIXTURES_ROOT\n"
        "batch = _batch_from_resolver('license_known', origin='resolver-run')\n"
        "report = _assemble(reference_batches=(batch,), consumer_root=FIXTURES_ROOT / 'license_known' / 'consumer')\n"
        "sys.stdout.buffer.write(report.to_json_bytes())\n"
    )
    outputs = []
    for seed in ("0", "1", "42"):
        env = dict(os.environ)
        env["PYTHONHASHSEED"] = seed
        env["PYTHONPATH"] = "src"
        completed = subprocess.run(
            [sys.executable, "-c", script], cwd=Path(__file__).resolve().parent.parent, env=env, capture_output=True, check=True
        )
        outputs.append(completed.stdout)
    assert outputs[0] == outputs[1] == outputs[2]
    assert outputs[0]


# ---------------------------------------------------------------------------
# Duplicate-provenance retention.
# ---------------------------------------------------------------------------


def test_duplicate_provenance_is_retained_not_dropped() -> None:
    batch_a = _batch_from_resolver("duplicate_provenance", origin="run-a")
    batch_b = _batch_from_resolver("duplicate_provenance", origin="run-b")
    assembled = _assemble(reference_batches=(batch_a, batch_b))

    assert len(assembled.results) == 1
    result = assembled.results[0]
    assert result.conflicting is False
    assert len(result.provenance) == 2
    origins = {record.consumer for record in result.provenance}
    assert origins == {"run-a", "run-b"}
    # Both provenance records survive dedup even though they agree on digest.
    digests = {record.code_digest for record in result.provenance}
    assert len(digests) == 1


# ---------------------------------------------------------------------------
# Conflicting-provenance retention.
# ---------------------------------------------------------------------------


def test_conflicting_provenance_is_retained_and_surfaced() -> None:
    ref_a = _reference("widgetlib", "app.py", 3, digest_seed="widgetlib")
    ref_b = _reference("widgetlib", "app.py", 3, digest_seed="widgetlib-tampered")
    batch_a = ReferenceBatch(schema_version=REFERENCE_BATCH_SCHEMA_VERSION, origin="run-a", references=(ref_a,), coverage=_empty_coverage())
    batch_b = ReferenceBatch(schema_version=REFERENCE_BATCH_SCHEMA_VERSION, origin="run-b", references=(ref_b,), coverage=_empty_coverage())

    assembled = _assemble(reference_batches=(batch_a, batch_b))

    assert len(assembled.results) == 1
    result = assembled.results[0]
    assert result.conflicting is True
    assert len(result.provenance) == 2
    digests = {record.code_digest for record in result.provenance}
    assert digests == {ref_a.code_digest, ref_b.code_digest}

    # A conflicting identity must never be silently merged into a single
    # CodeReference in the underlying frozen report -- it is excluded from
    # `references` entirely (no single digest could honestly represent it).
    assert not any(ref.distribution == "widgetlib" and ref.span == ref_a.span for ref in assembled.report.references)

    conflict_records = [record for record in assembled.report.coverage.records if record.state == UnresolvedState.AMBIGUOUS_BINDING]
    assert conflict_records


# ---------------------------------------------------------------------------
# Bound/cap tests -- one per cap constant.
# ---------------------------------------------------------------------------


def test_provenance_cap_exceeded_is_rejected_from_results_but_provenance_retained() -> None:
    ref_a = _reference("widgetlib", "app.py", 3, digest_seed="same-usage")
    ref_b = _reference("widgetlib", "app.py", 3, digest_seed="same-usage")
    batch_a = ReferenceBatch(schema_version=REFERENCE_BATCH_SCHEMA_VERSION, origin="run-a", references=(ref_a,), coverage=_empty_coverage())
    batch_b = ReferenceBatch(schema_version=REFERENCE_BATCH_SCHEMA_VERSION, origin="run-b", references=(ref_b,), coverage=_empty_coverage())

    assembled = _assemble(reference_batches=(batch_a, batch_b), max_provenance_per_result=1)

    assert assembled.results == ()
    assert len(assembled.capped_results) == 1
    capped = assembled.capped_results[0]
    assert capped.reason == "provenance-cap-exceeded"
    assert len(capped.provenance) == 2  # never truncated
    assert assembled.capped is True
    assert len(capped.provenance) <= 2  # cap was genuinely not exceeded in the emitted structure
    cap_records = [record for record in assembled.report.coverage.records if record.state == UnresolvedState.CAP_EXCEEDED]
    assert cap_records


def test_results_cap_exceeded_moves_overflow_to_capped_results_with_full_provenance() -> None:
    ref_a = _reference("widgetlib", "app_a.py", 3, digest_seed="a")
    ref_b = _reference("widgetlib", "app_b.py", 3, digest_seed="b")
    batch = ReferenceBatch(schema_version=REFERENCE_BATCH_SCHEMA_VERSION, origin="run", references=(ref_a, ref_b), coverage=_empty_coverage())

    assembled = _assemble(reference_batches=(batch,), max_results=1)

    assert len(assembled.results) == 1
    assert len(assembled.results) <= 1  # cap genuinely honored
    assert len(assembled.capped_results) == 1
    overflow = assembled.capped_results[0]
    assert overflow.reason == "results-cap-exceeded"
    assert len(overflow.provenance) == 1  # full provenance for that identity, not dropped
    assert assembled.capped is True


def test_license_snippet_cap_exceeded_is_recorded() -> None:
    batch = _batch_from_resolver("license_known", origin="resolver-run")
    assembled = _assemble(
        reference_batches=(batch,), consumer_root=FIXTURES_ROOT / "license_known" / "consumer", max_license_snippets_per_result=0
    )
    assert len(assembled.results) == 1
    result = assembled.results[0]
    assert result.license_snippets == ()
    assert len(result.license_snippets) <= MAX_LICENSE_SNIPPETS_PER_RESULT
    cap_records = [record for record in assembled.report.coverage.records if record.state == UnresolvedState.CAP_EXCEEDED]
    assert any("capped-license" in record.file for record in cap_records)


def test_total_output_size_cap_is_rejected_outright() -> None:
    batch = _batch_from_resolver("license_known", origin="resolver-run")
    with pytest.raises(UsageUnsupportedError) as excinfo:
        _assemble(reference_batches=(batch,), consumer_root=FIXTURES_ROOT / "license_known" / "consumer", max_total_output_bytes=10)
    payload = excinfo.value.to_json()
    assert payload["kind"] == "usage_unsupported"
    assert payload["field"] == "assembled_report"


# ---------------------------------------------------------------------------
# Advisory per-snippet licensing.
# ---------------------------------------------------------------------------


def test_known_license_marker_is_advisory_high_confidence() -> None:
    batch = _batch_from_resolver("license_known", origin="resolver-run")
    assembled = _assemble(reference_batches=(batch,), consumer_root=FIXTURES_ROOT / "license_known" / "consumer")

    assert len(assembled.results) == 1
    snippet = assembled.results[0].license_snippets[0]
    assert snippet.advisory is True
    assert snippet.license_guess == "MIT"
    assert snippet.confidence == "high"


def test_unknown_license_never_claims_certainty() -> None:
    batch = _batch_from_resolver("license_unknown", origin="resolver-run")
    assembled = _assemble(reference_batches=(batch,), consumer_root=FIXTURES_ROOT / "license_unknown" / "consumer")

    assert len(assembled.results) == 1
    snippet = assembled.results[0].license_snippets[0]
    assert snippet.advisory is True
    assert snippet.license_guess == "unknown"
    assert snippet.confidence != "high"


def test_missing_consumer_root_yields_unknown_advisory_license() -> None:
    batch = _batch_from_resolver("license_known", origin="resolver-run")
    assembled = _assemble(reference_batches=(batch,), consumer_root=None)

    snippet = assembled.results[0].license_snippets[0]
    assert snippet.advisory is True
    assert snippet.license_guess == "unknown"


# ---------------------------------------------------------------------------
# Ranking explanation and deterministic tie-breaking.
# ---------------------------------------------------------------------------


def test_ranking_explanation_is_present_and_complete() -> None:
    batch = _batch_from_resolver("duplicate_provenance", origin="run")
    assembled = _assemble(reference_batches=(batch,))

    assert len(assembled.results) == 1
    explanation = assembled.results[0].score_explanation
    names = {component.name for component in explanation.components}
    assert names == {"conflicting_penalty", "license_confidence", "provenance_count", "span_width"}
    assert explanation.total_score == sum(component.contribution for component in explanation.components)
    for component in explanation.components:
        assert component.contribution == component.weight * component.raw_value


def test_ranking_ties_break_on_stable_identity_key_not_insertion_order() -> None:
    ref_first = _reference("widgetlib", "zzz_app.py", 3, digest_seed="tie")
    ref_second = _reference("widgetlib", "aaa_app.py", 3, digest_seed="tie")
    # Insertion order deliberately reversed vs. expected tie-break order.
    batch = ReferenceBatch(
        schema_version=REFERENCE_BATCH_SCHEMA_VERSION, origin="run", references=(ref_first, ref_second), coverage=_empty_coverage()
    )

    assembled = _assemble(reference_batches=(batch,))

    assert len(assembled.results) == 2
    assert assembled.results[0].score_explanation.total_score == assembled.results[1].score_explanation.total_score
    # tie_break_key is (distribution, file, ...) -- "aaa_app.py" sorts before "zzz_app.py".
    assert assembled.results[0].span.file == "aaa_app.py"
    assert assembled.results[1].span.file == "zzz_app.py"
    assert assembled.results[0].score_explanation.tie_break_key < assembled.results[1].score_explanation.tie_break_key


def test_results_are_sorted_by_descending_score() -> None:
    ref_weak = _reference("widgetlib", "weak.py", 1, digest_seed="weak")
    ref_a = _reference("widgetlib", "strong.py", 3, digest_seed="strong-a")
    ref_b = _reference("widgetlib", "strong.py", 3, digest_seed="strong-a")  # duplicate provenance -> higher score
    batch = ReferenceBatch(
        schema_version=REFERENCE_BATCH_SCHEMA_VERSION, origin="run-a", references=(ref_weak, ref_a), coverage=_empty_coverage()
    )
    batch_dup = ReferenceBatch(schema_version=REFERENCE_BATCH_SCHEMA_VERSION, origin="run-b", references=(ref_b,), coverage=_empty_coverage())

    assembled = _assemble(reference_batches=(batch, batch_dup))

    assert [result.span.file for result in assembled.results] == ["strong.py", "weak.py"]
    scores = [result.score_explanation.total_score for result in assembled.results]
    assert scores == sorted(scores, reverse=True)


# ---------------------------------------------------------------------------
# Coverage / unresolved-distribution wiring (#256 wiring note).
# ---------------------------------------------------------------------------


def test_unresolved_distributions_are_carried_forward_into_coverage() -> None:
    unresolved = UnresolvedDistribution(
        schema_version=UNRESOLVED_DISTRIBUTION_SCHEMA_VERSION,
        distribution="mystery-lib",
        state=UnresolvedState.UNSUPPORTED_SYNTAX,
        reason="no local evidence declares any import root for this distribution",
        evidence=(
            DistributionRecord(
                schema_version="leitir-usage-distribution-record-v1", distribution="mystery-lib", declared_roots=(), source="top-level-txt"
            ),
        ),
    )

    assembled = _assemble(unresolved_distributions=(unresolved,))

    assert assembled.unresolved_distributions == (unresolved,)
    assert "unresolved-distribution:mystery-lib:unsupported-syntax" in assembled.report.coverage.exclusions


def test_no_evidence_produces_empty_but_valid_report() -> None:
    assembled = _assemble()
    assert assembled.results == ()
    assert assembled.capped_results == ()
    assert assembled.capped is False
    assert assembled.report.references == ()
