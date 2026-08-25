"""Regenerate the usage evidence/replay fixture corpus (issue #255).

Run with ``PYTHONPATH=src python tests/fixtures/usage/generate.py`` from the
repo root whenever a case's source content changes. This script is a
maintenance tool (see ``tests/fixtures/occupied_validate/generate.py`` for
the precedent) -- it is not imported by the test suite or the shipped
package, so it uses plain file I/O rather than ``leitir.safeio``.

Each case directory is self-describing via ``manifest.json`` and contains:

- ``requirements.txt`` -- the exact pinned dependency bytes.
- ``consumer/`` -- a tiny stdlib-only Python source tree standing in for
  the consuming project.
- ``report.json`` -- a :class:`leitir.usage.UsageReport`, closed and
  digest-stamped, describing how the consumer uses the pinned provider.
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
    LicenseSnippetEvidence,
    SourceSpan,
    UnresolvedState,
    build_report,
)
from leitir.usage._canonical import digest_bytes, digest_value
from leitir.usage.contract import CODE_REFERENCE_SCHEMA_VERSION, CodeReference

ROOT = Path(__file__).resolve().parent

PROVIDER_NAME = "widgetlib"
PROVIDER_VERSION = "1.2.3"
REQUIREMENTS_TEXT = "widgetlib==1.2.3\n"
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


def _dependency_evidence() -> DependencyEvidence:
    return DependencyEvidence(
        schema_version="leitir-usage-dependency-v1",
        requirements_text=REQUIREMENTS_TEXT,
        requirements_digest=digest_bytes(REQUIREMENTS_TEXT.encode("utf-8")),
        parser_name=PARSER_NAME,
        parser_version=PARSER_VERSION,
    )


def _line_span(text: str, needle: str, relative_path: str) -> SourceSpan:
    lines = text.splitlines()
    for index, line in enumerate(lines):
        if needle in line:
            return SourceSpan(file=relative_path, start_line=index + 1, start_col=0, end_line=index + 1, end_col=len(line))
    raise AssertionError(f"needle {needle!r} not found in {relative_path}")


def _reference(text: str, needle: str, relative_path: str, distribution: str) -> CodeReference:
    span = _line_span(text, needle, relative_path)
    snippet = text.splitlines()[span.start_line - 1]
    return CodeReference(
        schema_version=CODE_REFERENCE_SCHEMA_VERSION,
        distribution=distribution,
        span=span,
        code_digest=digest_bytes(snippet.encode("utf-8")),
    )


def _license_evidence(text: str, needle: str, relative_path: str) -> LicenseSnippetEvidence:
    span = _line_span(text, needle, relative_path)
    return LicenseSnippetEvidence(
        schema_version="leitir-usage-license-v1",
        span=span,
        license_guess="MIT",
        confidence="low",
        advisory=True,
    )


def _write_case(
    case: str,
    *,
    description: str,
    consumer_files: dict[str, str],
    reference_needle: tuple[str, str],
    coverage_state: UnresolvedState,
    expect: str = "valid",
    tamper_after_report: dict[str, str] | None = None,
    extra_manifest_fields: dict[str, object] | None = None,
) -> None:
    case_dir = ROOT / case
    consumer_dir = case_dir / "consumer"
    consumer_dir.mkdir(parents=True, exist_ok=True)
    for relative, content in consumer_files.items():
        path = consumer_dir / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8", newline="\n")

    (case_dir / "requirements.txt").write_text(REQUIREMENTS_TEXT, encoding="utf-8", newline="\n")

    needle_file, needle_text = reference_needle
    needle_relative = f"consumer/{needle_file}"
    full_text = consumer_files[needle_file]

    provider = _identity("provider", PROVIDER_NAME, PROVIDER_VERSION, {"requirements_digest": digest_bytes(REQUIREMENTS_TEXT.encode("utf-8"))})
    file_digests = {
        f"consumer/{relative}": digest_bytes(content.encode("utf-8")) for relative, content in sorted(consumer_files.items())
    }
    consumer = _identity("consumer", f"{case}-consumer", "0.1.0", {"files": file_digests})

    reference = _reference(full_text, needle_text, needle_relative, PROVIDER_NAME)
    coverage = CoverageSummary(
        schema_version="leitir-usage-coverage-v1",
        records=(
            CoverageRecord(schema_version="leitir-usage-coverage-record-v1", file=needle_relative, state=coverage_state),
        ),
        exclusions=(),
        cap=100,
        capped=False,
    )
    report = build_report(
        provider_identity=provider,
        consumer_identity=consumer,
        dependency_evidence=_dependency_evidence(),
        import_mappings=(ImportMapping(schema_version="leitir-usage-import-mapping-v1", distribution=PROVIDER_NAME, import_roots=(PROVIDER_NAME,)),),
        references=(reference,),
        coverage=coverage,
        license_evidence=(_license_evidence(full_text, needle_text, needle_relative),),
    )

    (case_dir / "report.json").write_bytes(report.to_json_bytes() + b"\n")

    if tamper_after_report is not None:
        for relative, content in tamper_after_report.items():
            path = consumer_dir / relative
            path.write_text(content, encoding="utf-8", newline="\n")

    manifest: dict[str, object] = {
        "schema_version": "leitir-usage-fixture-manifest-v1",
        "case": case,
        "kind": case,
        "description": description,
        "requirements_file": "requirements.txt",
        "consumer_dir": "consumer",
        "report_file": "report.json",
        "expect": expect,
        "expected_state": coverage_state.value,
    }
    if extra_manifest_fields:
        manifest.update(extra_manifest_fields)
    (case_dir / "manifest.json").write_text(
        json.dumps(manifest, sort_keys=True, indent=2, ensure_ascii=False) + "\n", encoding="utf-8", newline="\n"
    )


def main() -> None:
    _write_case(
        "positive",
        description="A direct, unaliased import of the pinned distribution resolves cleanly with full coverage.",
        consumer_files={"app.py": "import widgetlib\n\nwidgetlib.do_thing()\n"},
        reference_needle=("app.py", "import widgetlib"),
        coverage_state=UnresolvedState.RESOLVED,
    )

    _write_case(
        "alias",
        description="An aliased import (`import widgetlib as wl`) still resolves to the same distribution.",
        consumer_files={"app.py": "import widgetlib as wl\n\nwl.do_thing()\n"},
        reference_needle=("app.py", "import widgetlib as wl"),
        coverage_state=UnresolvedState.RESOLVED,
    )

    _write_case(
        "shadowing",
        description=(
            "A local function definition rebinds the name the import introduced, "
            "so the binding is recorded as a re-export rather than a plain resolution."
        ),
        consumer_files={
            "app.py": (
                "import widgetlib\n\n\ndef widgetlib():  # noqa: F811 - deliberate shadow fixture\n"
                "    return None\n\n\nwidgetlib()\n"
            )
        },
        reference_needle=("app.py", "import widgetlib"),
        coverage_state=UnresolvedState.RE_EXPORT,
    )

    _write_case(
        "ambiguous",
        description="Two distinct import statements bind the same local name, so the binding is ambiguous.",
        consumer_files={
            "app.py": (
                "import widgetlib\nimport widgetlib as widgetlib  # noqa: F811 - deliberate ambiguity fixture\n"
                "\nwidgetlib.do_thing()\n"
            )
        },
        reference_needle=("app.py", "import widgetlib"),
        coverage_state=UnresolvedState.AMBIGUOUS_BINDING,
    )

    _write_case(
        "unsupported",
        description="A dynamic `__import__` call cannot be statically resolved to an import root.",
        consumer_files={"app.py": 'widgetlib = __import__("widgetlib")\n\nwidgetlib.do_thing()\n'},
        reference_needle=("app.py", "__import__"),
        coverage_state=UnresolvedState.DYNAMIC_IMPORT,
    )

    _write_case(
        "determinism",
        description="Re-validating and re-replaying this case must reproduce byte-identical output every run.",
        consumer_files={"app.py": "import widgetlib\n\nwidgetlib.do_thing()\n"},
        reference_needle=("app.py", "import widgetlib"),
        coverage_state=UnresolvedState.RESOLVED,
    )

    _write_case(
        "tamper",
        description=(
            "The report is self-consistent (its own report_digest validates) but the on-disk "
            "consumer source was altered after the report was produced, so offline replay must "
            "detect the code_digest mismatch and reject before doing anything else."
        ),
        consumer_files={"app.py": "import widgetlib\n\nwidgetlib.do_thing()\n"},
        reference_needle=("app.py", "import widgetlib"),
        coverage_state=UnresolvedState.RESOLVED,
        expect="tamper",
        # Tampers the exact referenced span (line 1, "import widgetlib") so
        # offline replay's per-span code_digest recomputation must catch it;
        # the report itself stays self-consistent (report_digest still
        # validates), so this is only observable by replaying real bytes.
        tamper_after_report={
            "app.py": (
                "import widgetlub  # noqa: F401 - deliberate tamper fixture\n\n"
                "widgetlib.do_thing()  # noqa: F821 - deliberate tamper fixture\n"
            )
        },
        extra_manifest_fields={"tamper_stage": "replay", "expected_error": "UsageTamperError"},
    )

    print(f"regenerated {len(list(ROOT.iterdir()))} fixture entries under {ROOT}")


if __name__ == "__main__":
    main()
