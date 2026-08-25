"""The usage evidence and offline replay contract (issue #255).

This package freezes the closed, versioned data contract that later usage
pipeline issues build on:

- #256 admission and the import catalog
- #257 the static resolver
- #258 the evidence assembler
- #259 the CLI, replay, and end-to-end wiring

Import the frozen dataclasses, schema-version literals, bounds, the typed
error hierarchy, and the parse/build/replay entry points from here rather
than reaching into ``leitir.usage.contract`` or ``leitir.usage.errors``
directly, so the public surface stays reviewable in one place.
"""

from __future__ import annotations

from .contract import (
    CODE_REFERENCE_SCHEMA_VERSION,
    CONTRACT_VERSION,
    COVERAGE_RECORD_SCHEMA_VERSION,
    COVERAGE_SUMMARY_SCHEMA_VERSION,
    DEPENDENCY_EVIDENCE_SCHEMA_VERSION,
    FIXTURE_MANIFEST_SCHEMA_VERSION,
    IDENTITY_SCHEMA_VERSION,
    IMPORT_MAPPING_SCHEMA_VERSION,
    LICENSE_EVIDENCE_SCHEMA_VERSION,
    MAX_COVERAGE_CAP,
    MAX_EXCLUSIONS,
    MAX_IMPORT_MAPPINGS,
    MAX_IMPORT_ROOTS_PER_MAPPING,
    MAX_LICENSE_EVIDENCE,
    MAX_REFERENCES,
    MAX_REQUIREMENTS_BYTES,
    MAX_SNIPPET_BYTES,
    REPORT_SCHEMA_VERSION,
    TOOL_VERSION,
    CodeReference,
    CoverageRecord,
    CoverageSummary,
    DependencyEvidence,
    Identity,
    ImportMapping,
    LicenseSnippetEvidence,
    SourceSpan,
    UnresolvedState,
    UsageReport,
    build_report,
    replay_report,
    report_from_dict,
    report_from_json_bytes,
)
from .errors import (
    UsageError,
    UsageErrorEvidence,
    UsageMalformedError,
    UsageTamperError,
    UsageUnsupportedError,
)

__all__ = [
    "CODE_REFERENCE_SCHEMA_VERSION",
    "CONTRACT_VERSION",
    "COVERAGE_RECORD_SCHEMA_VERSION",
    "COVERAGE_SUMMARY_SCHEMA_VERSION",
    "DEPENDENCY_EVIDENCE_SCHEMA_VERSION",
    "FIXTURE_MANIFEST_SCHEMA_VERSION",
    "IDENTITY_SCHEMA_VERSION",
    "IMPORT_MAPPING_SCHEMA_VERSION",
    "LICENSE_EVIDENCE_SCHEMA_VERSION",
    "MAX_COVERAGE_CAP",
    "MAX_EXCLUSIONS",
    "MAX_IMPORT_MAPPINGS",
    "MAX_IMPORT_ROOTS_PER_MAPPING",
    "MAX_LICENSE_EVIDENCE",
    "MAX_REFERENCES",
    "MAX_REQUIREMENTS_BYTES",
    "MAX_SNIPPET_BYTES",
    "REPORT_SCHEMA_VERSION",
    "TOOL_VERSION",
    "CodeReference",
    "CoverageRecord",
    "CoverageSummary",
    "DependencyEvidence",
    "Identity",
    "ImportMapping",
    "LicenseSnippetEvidence",
    "SourceSpan",
    "UnresolvedState",
    "UsageError",
    "UsageErrorEvidence",
    "UsageMalformedError",
    "UsageReport",
    "UsageTamperError",
    "UsageUnsupportedError",
    "build_report",
    "replay_report",
    "report_from_dict",
    "report_from_json_bytes",
]
