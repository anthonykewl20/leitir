"""CLI-facing support for the leitir ``usage`` subcommand (issue #259).

Wires the frozen usage contract (#255), admission/import catalog (#256),
static resolver (#257), and evidence assembler (#258) into two offline
operations the CLI exposes:

- ``verify`` -- parse and structurally validate a usage evidence report
  (``leitir.usage.report_from_json_bytes``), rejecting a malformed,
  unsupported, or self-inconsistent (tampered) report before returning
  anything.
- ``replay`` -- fully offline, deterministic replay of an already-verified
  report against the real corpus/requirements bytes on disk
  (``leitir.usage.replay_report``), run ``times`` times (default 2) and
  compared byte-for-byte.

Nothing here performs network I/O or imports/executes consumer code: every
file read goes through ``leitir.safeio.read_regular_file`` with an explicit
byte bound, and replay only ever reads source text to recompute digests,
never executes it.
"""

from __future__ import annotations

from pathlib import Path

from leitir.safeio import read_regular_file

from . import Identity, UsageErrorEvidence, UsageReport, UsageTamperError, replay_report, report_from_json_bytes

# A generous but bounded cap on the report document itself -- reports are
# closed, capped structures (MAX_REFERENCES etc. in contract.py), so a
# report this large already implies a cap was hit; this is purely a
# CLI-boundary read guard, not a contract bound, so it is declared here
# rather than in the frozen contract module.
MAX_REPORT_BYTES = 4 * 1024 * 1024

CLI_VERIFY_SCHEMA_VERSION = "leitir-usage-cli-verify-v1"
CLI_REPLAY_SCHEMA_VERSION = "leitir-usage-cli-replay-v1"


def _identity_payload(identity: Identity) -> dict[str, object]:
    return {"name": identity.name, "version": identity.version, "digest": identity.digest}


def load_report(report_path: Path) -> UsageReport:
    """Read and structurally validate a usage report from ``report_path``.

    Raises :class:`leitir.usage.UsageMalformedError`,
    :class:`leitir.usage.UsageUnsupportedError`, or
    :class:`leitir.usage.UsageTamperError` (self-inconsistent
    ``report_digest``) -- never partially returns a report that failed
    validation.
    """

    raw = read_regular_file(report_path, maximum_bytes=MAX_REPORT_BYTES, no_follow=True)
    return report_from_json_bytes(raw)


def verify_payload(report: UsageReport) -> dict[str, object]:
    """Build the canonical CLI payload for a successfully verified report."""

    return {
        "schema_version": CLI_VERIFY_SCHEMA_VERSION,
        "action": "verify",
        "report_digest": report.report_digest,
        "tool_version": report.tool_version,
        "contract_version": report.contract_version,
        "provider": _identity_payload(report.provider_identity),
        "consumer": _identity_payload(report.consumer_identity),
        "reference_count": len(report.references),
        "import_mapping_count": len(report.import_mappings),
        "license_evidence_count": len(report.license_evidence),
        "coverage_cap": report.coverage.cap,
        "coverage_capped": report.coverage.capped,
        "coverage_record_count": len(report.coverage.records),
    }


def replay_payload(report: UsageReport, *, corpus_root: Path, dependency_path: Path, times: int = 2) -> dict[str, object]:
    """Replay ``report`` offline ``times`` times and confirm byte-identical output.

    Raises :class:`leitir.usage.UsageMalformedError` or
    :class:`leitir.usage.UsageTamperError` (fail-closed) if any replay pass
    rejects the on-disk bytes. If every individual pass succeeds but their
    canonical bytes somehow disagree -- which should be unreachable given
    :func:`leitir.usage.replay_report`'s own determinism -- this raises
    :class:`leitir.usage.UsageTamperError` rather than reporting a false
    "byte_identical" claim.
    """

    if times < 1:
        raise ValueError("times must be >= 1")
    passes = [replay_report(report, corpus_root=corpus_root, dependency_path=dependency_path).to_json_bytes() for _ in range(times)]
    byte_identical = all(passed == passes[0] for passed in passes)
    if not byte_identical:
        raise UsageTamperError(
            UsageErrorEvidence(
                message="replay passes produced non-identical canonical bytes",
                stage="replay",
                field="report",
            )
        )
    return {
        "schema_version": CLI_REPLAY_SCHEMA_VERSION,
        "action": "replay",
        "report_digest": report.report_digest,
        "replay_count": times,
        "byte_identical": byte_identical,
    }
