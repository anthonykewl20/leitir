"""Regenerate the admission/import-catalog fixture cases added for issue #256.

Companion to ``generate.py`` (issue #255's corpus generator): that script
owns the resolver-shaped cases (``positive``, ``alias``, ``shadowing``,
``ambiguous``, ``unsupported``, ``tamper``, ``determinism``) and this one
owns the admission/import-catalog cases layered on top for #256. Each case
still gets the generic fixture files every corpus case needs (a closed
``manifest.json``, ``requirements.txt``, a ``consumer/`` tree with at least
one ``.py`` file, and a self-consistent ``report.json``) so
``tests/test_usage_fixtures.py`` keeps discovering and validating it
unchanged. On top of that, each case gets an ``admission.json`` sidecar
(read only by ``tests/test_usage_admission.py`` /
``tests/test_usage_import_catalog.py``, never by the generic corpus tests)
describing the admission/catalog-specific inputs and expected outcome.

Run with ``PYTHONPATH=src python tests/fixtures/usage/generate_admission_catalog.py``
from the repo root whenever a case's content changes.
"""

from __future__ import annotations

import json
from pathlib import Path

from leitir.usage import (
    CoverageRecord,
    CoverageSummary,
    DependencyEvidence,
    Identity,
    ImportMapping,
    SourceSpan,
    UnresolvedState,
    build_report,
)
from leitir.usage._canonical import digest_bytes, digest_value
from leitir.usage.contract import CODE_REFERENCE_SCHEMA_VERSION, CodeReference

ROOT = Path(__file__).resolve().parent

PROVIDER_NAME = "widgetlib"
PROVIDER_VERSION = "1.2.3"
PARSER_NAME = "leitir-requirements-parser"
PARSER_VERSION = "v1"


def _identity(role: str, name: str, version: str, extra: object) -> Identity:
    return Identity(
        schema_version="leitir-usage-identity-v1",
        role=role,
        name=name,
        version=version,
        digest=digest_value({"name": name, "version": version, "extra": extra}),
    )


def _report_for(case: str, requirements_text: str) -> bytes:
    """Build a self-consistent report.json body for the generic corpus tests.

    This report is independent of the admission/catalog-specific scenario
    the case is testing (see the sidecar ``admission.json`` for that); it
    only needs to satisfy the frozen contract so corpus discovery and the
    generic fixture tests keep passing.
    """

    app_text = "import widgetlib\n\nwidgetlib.do_thing()\n"
    span = SourceSpan(file="consumer/app.py", start_line=1, start_col=0, end_line=1, end_col=len("import widgetlib"))
    reference = CodeReference(
        schema_version=CODE_REFERENCE_SCHEMA_VERSION,
        distribution=PROVIDER_NAME,
        span=span,
        code_digest=digest_bytes(b"import widgetlib"),
    )
    coverage = CoverageSummary(
        schema_version="leitir-usage-coverage-v1",
        records=(
            CoverageRecord(
                schema_version="leitir-usage-coverage-record-v1",
                file="consumer/app.py",
                state=UnresolvedState.RESOLVED,
            ),
        ),
        exclusions=(),
        cap=100,
        capped=False,
    )
    dependency_evidence = DependencyEvidence(
        schema_version="leitir-usage-dependency-v1",
        requirements_text=requirements_text,
        requirements_digest=digest_bytes(requirements_text.encode("utf-8")),
        parser_name=PARSER_NAME,
        parser_version=PARSER_VERSION,
    )
    provider = _identity(
        "provider", PROVIDER_NAME, PROVIDER_VERSION, {"requirements_digest": dependency_evidence.requirements_digest}
    )
    consumer = _identity("consumer", f"{case}-consumer", "0.1.0", {"app": digest_bytes(app_text.encode("utf-8"))})
    report = build_report(
        provider_identity=provider,
        consumer_identity=consumer,
        dependency_evidence=dependency_evidence,
        import_mappings=(
            ImportMapping(schema_version="leitir-usage-import-mapping-v1", distribution=PROVIDER_NAME, import_roots=(PROVIDER_NAME,)),
        ),
        references=(reference,),
        coverage=coverage,
        license_evidence=(),
    )
    return report.to_json_bytes() + b"\n"


def _write_generic_case(
    case: str,
    *,
    kind: str,
    description: str,
    requirements_text: str,
    expect: str = "valid",
    extra_manifest_fields: dict[str, object] | None = None,
    tamper_requirements_after_report: str | None = None,
) -> Path:
    case_dir = ROOT / case
    consumer_dir = case_dir / "consumer"
    consumer_dir.mkdir(parents=True, exist_ok=True)
    (consumer_dir / "app.py").write_text(
        "import widgetlib\n\nwidgetlib.do_thing()\n", encoding="utf-8", newline="\n"
    )
    (case_dir / "requirements.txt").write_text(requirements_text, encoding="utf-8", newline="\n")
    (case_dir / "report.json").write_bytes(_report_for(case, requirements_text))
    if tamper_requirements_after_report is not None:
        # Written *after* report.json so the report stays self-consistent
        # (report_digest still validates) while the on-disk requirements.txt
        # bytes diverge from what dependency_evidence recorded -- only
        # offline replay/admission catches this, matching the frozen
        # tamper/ case's pattern for consumer source (see generate.py).
        (case_dir / "requirements.txt").write_text(
            tamper_requirements_after_report, encoding="utf-8", newline="\n"
        )

    manifest: dict[str, object] = {
        "schema_version": "leitir-usage-fixture-manifest-v1",
        "case": case,
        "kind": kind,
        "description": description,
        "requirements_file": "requirements.txt",
        "consumer_dir": "consumer",
        "report_file": "report.json",
        "expect": expect,
        "expected_state": UnresolvedState.RESOLVED.value,
    }
    if extra_manifest_fields:
        manifest.update(extra_manifest_fields)
    (case_dir / "manifest.json").write_text(
        json.dumps(manifest, sort_keys=True, indent=2, ensure_ascii=False) + "\n", encoding="utf-8", newline="\n"
    )
    return case_dir


def _write_admission_sidecar(case_dir: Path, payload: dict[str, object]) -> None:
    (case_dir / "admission.json").write_text(
        json.dumps(payload, sort_keys=True, indent=2, ensure_ascii=False) + "\n", encoding="utf-8", newline="\n"
    )


_PINNED_SHA = "a" * 40
_OTHER_SHA = "b" * 40


def main() -> None:
    # -- admission.py cases -------------------------------------------------

    verified_requirements = "widgetlib==1.2.3\nother-lib==0.4.0\n"
    case_dir = _write_generic_case(
        "verified-consumer",
        kind="positive",
        description="A SHA-pinned consumer with exact direct pins is admitted and retains full dependency evidence.",
        requirements_text=verified_requirements,
    )
    _write_admission_sidecar(
        case_dir,
        {
            "scenario": "verified-consumer",
            "consumer_name": "verified-consumer",
            "consumer_version": "0.1.0",
            "consumer_ref": _PINNED_SHA,
            "expected_consumer_ref": _PINNED_SHA,
            "recorded_requirements_digest": digest_bytes(verified_requirements.encode("utf-8")),
            "expected_outcome": "admit",
        },
    )

    case_dir = _write_generic_case(
        "unpinned-consumer",
        kind="unsupported",
        description="A floating branch ref ('main') is not a SHA pin; admission must reject it.",
        requirements_text="widgetlib==1.2.3\n",
    )
    _write_admission_sidecar(
        case_dir,
        {
            "scenario": "unpinned-consumer",
            "consumer_name": "unpinned-consumer",
            "consumer_version": "0.1.0",
            "consumer_ref": "main",
            "expected_consumer_ref": "main",
            "recorded_requirements_digest": digest_bytes(b"widgetlib==1.2.3\n"),
            "expected_outcome": "reject",
            "expected_error": "UsageUnsupportedError",
        },
    )

    case_dir = _write_generic_case(
        "range-pin",
        kind="unsupported",
        description="A '>=' range pin is not an exact direct pin; admission must reject the whole requirements set.",
        requirements_text="widgetlib>=1.2.3\n",
    )
    _write_admission_sidecar(
        case_dir,
        {
            "scenario": "range-pin",
            "consumer_name": "range-pin-consumer",
            "consumer_version": "0.1.0",
            "consumer_ref": _PINNED_SHA,
            "expected_consumer_ref": _PINNED_SHA,
            "recorded_requirements_digest": digest_bytes(b"widgetlib>=1.2.3\n"),
            "expected_outcome": "reject",
            "expected_error": "UsageUnsupportedError",
        },
    )

    digest_mismatch_requirements = "widgetlib==1.2.3\n"
    digest_mismatch_tampered = "widgetlib==9.9.9\n"
    case_dir = _write_generic_case(
        "digest-mismatch",
        kind="tamper",
        description=(
            "The report (and its recorded requirements digest) is self-consistent, but the "
            "on-disk requirements.txt was altered afterward; both offline replay and admission "
            "must reject on the digest mismatch before retaining any dependency claim."
        ),
        requirements_text=digest_mismatch_requirements,
        expect="tamper",
        extra_manifest_fields={"tamper_stage": "replay", "expected_error": "UsageTamperError"},
        tamper_requirements_after_report=digest_mismatch_tampered,
    )
    _write_admission_sidecar(
        case_dir,
        {
            "scenario": "digest-mismatch",
            "consumer_name": "digest-mismatch-consumer",
            "consumer_version": "0.1.0",
            "consumer_ref": _PINNED_SHA,
            "expected_consumer_ref": _PINNED_SHA,
            # The digest recorded for this consumer's requirements.txt (matches the
            # ORIGINAL text baked into report.json); the on-disk file was tampered
            # afterward, so admission must recompute a different actual digest.
            "recorded_requirements_digest": digest_bytes(digest_mismatch_requirements.encode("utf-8")),
            "expected_outcome": "reject",
            "expected_error": "UsageTamperError",
        },
    )

    # -- import_catalog.py cases --------------------------------------------

    case_dir = _write_generic_case(
        "missing-mapping",
        kind="unsupported",
        description="No local evidence declares any import root for the pinned distribution.",
        requirements_text="widgetlib==1.2.3\n",
    )
    _write_admission_sidecar(
        case_dir,
        {
            "scenario": "missing-mapping",
            "distribution_records": [
                {
                    "schema_version": "leitir-usage-distribution-record-v1",
                    "distribution": "widgetlib",
                    "declared_roots": [],
                    "source": "top-level-txt",
                }
            ],
            "expected_outcome": "unresolved",
            "expected_state": "unsupported-syntax",
        },
    )

    case_dir = _write_generic_case(
        "ambiguous-mapping",
        kind="ambiguous",
        description="Two distinct distributions normalize to the same identity and disagree, so both are ambiguous.",
        requirements_text="widget-lib==1.2.3\n",
    )
    _write_admission_sidecar(
        case_dir,
        {
            "scenario": "ambiguous-mapping",
            "distribution_records": [
                {
                    "schema_version": "leitir-usage-distribution-record-v1",
                    "distribution": "widget-lib",
                    "declared_roots": ["widget_lib"],
                    "source": "top-level-txt",
                },
                {
                    "schema_version": "leitir-usage-distribution-record-v1",
                    "distribution": "widget_lib",
                    "declared_roots": ["widgetlib"],
                    "source": "top-level-txt",
                },
            ],
            "expected_outcome": "unresolved",
            "expected_state": "ambiguous-binding",
        },
    )

    case_dir = _write_generic_case(
        "multi-root-distribution",
        kind="positive",
        description="One coherent evidence source declares two import roots for one distribution; still resolved.",
        requirements_text="widgetlib==1.2.3\n",
    )
    _write_admission_sidecar(
        case_dir,
        {
            "scenario": "multi-root-distribution",
            "distribution_records": [
                {
                    "schema_version": "leitir-usage-distribution-record-v1",
                    "distribution": "widgetlib",
                    "declared_roots": ["widgetlib", "widgetlib_ext"],
                    "source": "top-level-txt",
                }
            ],
            "expected_outcome": "resolved",
            "expected_import_roots": ["widgetlib", "widgetlib_ext"],
        },
    )

    case_dir = _write_generic_case(
        "unsupported-packaging",
        kind="unsupported",
        description="The only local evidence for this distribution comes from an unsupported packaging shape.",
        requirements_text="widgetlib==1.2.3\n",
    )
    _write_admission_sidecar(
        case_dir,
        {
            "scenario": "unsupported-packaging",
            "distribution_records": [
                {
                    "schema_version": "leitir-usage-distribution-record-v1",
                    "distribution": "widgetlib",
                    "declared_roots": ["widgetlib"],
                    "source": "namespace-pth-file",
                }
            ],
            "expected_outcome": "unresolved",
            "expected_state": "unsupported-syntax",
        },
    )

    print("regenerated admission/import-catalog fixture cases under " + str(ROOT))


if __name__ == "__main__":
    main()
