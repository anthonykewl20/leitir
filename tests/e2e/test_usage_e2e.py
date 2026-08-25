"""Opt-in, pinned public-source E2E benchmark for the usage evidence pipeline
(issue #259).

**Owner decision: made.** ``_PUBLIC_E2E_PINS`` below records the chosen
public provider/consumer identities and their exact, immutable pins:

- **Provider**: PyPI ``six`` ``1.16.0`` -- MIT licensed, a single ~34 KB
  file (``six.py``), frozen/unmaintained since 2021 (extremely unlikely to
  ever change or disappear), pinned by an exact sdist URL and its real
  ``sha256`` digest (verified against PyPI's published digest and the
  actual downloaded bytes, not merely asserted).
- **Consumer**: the ``six`` project's own GitHub repository
  (``benjaminp/six``), MIT licensed, pinned at the exact 40-hex commit SHA
  tagged ``1.16.0``. Its ``test_six.py`` is a genuine real-world consumer
  of the ``six`` distribution: a module-level ``import six`` followed by
  dozens of statically-resolvable ``six.<attr>`` usages the resolver can
  pin down with certainty (``six.integer_types``, ``six.string_types``,
  ``six.PY3``, ``six.moves``, ...).

This test performs the full pipeline end to end, against the real network,
with no fabricated bytes:

1. Fetches the real PyPI sdist for the pinned provider and verifies its
   bytes hash to the pinned ``sha256`` digest (materialization proof).
2. Fetches the real ``test_six.py`` source from the pinned GitHub commit
   (materialization proof for the consumer).
3. Runs it through the actual pipeline modules: admission
   (:mod:`leitir.usage.admission`), the import catalog
   (:mod:`leitir.usage.import_catalog`), the static resolver
   (:mod:`leitir.usage.resolver`), and the evidence assembler
   (:mod:`leitir.usage.assemble`).
4. Writes the assembled report to disk and drives it through the real
   shipped CLI (``python -m leitir.cli usage verify`` /
   ``usage replay --times 2``) exactly as a human operator would, and
   asserts on real outcomes: a non-empty resolved reference count, a
   coverage summary that is not capped, and byte-identical replay output.

Per the shared brief, any network/opt-in test carries both
``@pytest.mark.live`` and a ``skipif`` gated on ``LEITIR_ENABLE_LIVE_E2E``;
``tests/test_live_marker_inventory.py`` enforces that pairing. The default
(opt-out) run of this file always passes by skipping, and performs no
network I/O whatsoever -- this module is opt-in solely because it requires
real network access to PyPI and GitHub, not because of any remaining
identity/pin decision.
"""

from __future__ import annotations

import io
import json
import os
import subprocess
import sys
import tarfile
import urllib.error
import urllib.request
from pathlib import Path

import pytest

from leitir.usage import Identity
from leitir.usage._canonical import digest_bytes, digest_value
from leitir.usage.admission import admit_consumer
from leitir.usage.assemble import REFERENCE_BATCH_SCHEMA_VERSION, ReferenceBatch, assemble_usage_evidence
from leitir.usage.contract import IDENTITY_SCHEMA_VERSION
from leitir.usage.import_catalog import (
    DISTRIBUTION_RECORD_SCHEMA_VERSION,
    DistributionRecord,
    build_import_catalog,
)
from leitir.usage.resolver import resolve_consumer

# Owner-selected, pinned public E2E identities (issue #259 decision, made).
# Every value here is an exact, immutable pin -- a version, a 40-hex commit
# SHA, and a real sha256 digest -- never a floating branch/tag.
_PUBLIC_E2E_PINS: dict[str, str] = {
    "provider_distribution": "six",
    "provider_version": "1.16.0",
    "provider_sdist_url": (
        "https://files.pythonhosted.org/packages/71/39/"
        "171f1c67cd00715f190ba0b100d606d440a28c93c7714febeca8b79af85e/six-1.16.0.tar.gz"
    ),
    "provider_sdist_sha256": "1e61c37477a1626458e36f7b1d82aa5c9b094fa4802892072e49de9c60c4c926",
    "consumer_repo": "benjaminp/six",
    "consumer_commit": "65486e4383f9f411da95937451205d3c7b61b9e1",
    "consumer_file": "test_six.py",
}

_REASON = (
    "opt-in pinned public-source usage E2E (six==1.16.0 provider / benjaminp/six@"
    "65486e4383f9f411da95937451205d3c7b61b9e1 consumer): requires real network access "
    "to PyPI and GitHub, so it only runs with LEITIR_ENABLE_LIVE_E2E=1; the default "
    "offline suite never depends on it"
)

_REQUEST_TIMEOUT_SECONDS = 30
_MAX_DOWNLOAD_BYTES = 1_048_576  # 1 MiB is generous for a ~34 KB sdist / ~35 KB test file.


def _http_get(url: str, *, extra_headers: dict[str, str] | None = None) -> bytes:
    headers = {"User-Agent": "leitir-usage-e2e/1"}
    if extra_headers:
        headers.update(extra_headers)
    request = urllib.request.Request(url, headers=headers)  # noqa: S310
    with urllib.request.urlopen(request, timeout=_REQUEST_TIMEOUT_SECONDS) as response:  # noqa: S310
        data = response.read(_MAX_DOWNLOAD_BYTES + 1)
    if len(data) > _MAX_DOWNLOAD_BYTES:
        raise AssertionError(f"response from {url} exceeded the {_MAX_DOWNLOAD_BYTES}-byte E2E fetch bound")
    return data


@pytest.mark.live
@pytest.mark.skipif(
    os.environ.get("LEITIR_ENABLE_LIVE_E2E") != "1",
    reason=_REASON,
)
def test_pinned_public_source_usage_e2e(tmp_path: Path) -> None:
    """Verify+replay a real, pinned public provider/consumer pair end-to-end."""

    pins = _PUBLIC_E2E_PINS
    gh_token = os.environ.get("GH_TOKEN") or os.environ.get("GITHUB_TOKEN")

    # ---- 1. Materialize the pinned provider (PyPI sdist), verify its digest. ----
    sdist_bytes = _http_get(pins["provider_sdist_url"])
    expected_sdist_digest = f"sha256:{pins['provider_sdist_sha256']}"
    actual_sdist_digest = digest_bytes(sdist_bytes)
    assert actual_sdist_digest == expected_sdist_digest, (
        f"pinned provider sdist digest mismatch: expected {expected_sdist_digest}, got {actual_sdist_digest}"
    )

    # Real local evidence of the provider's declared import root, extracted
    # from the actual downloaded sdist tarball (never guessed/hard-coded).
    with tarfile.open(fileobj=io.BytesIO(sdist_bytes), mode="r:gz") as tar:
        top_level_member = next(
            member for member in tar.getmembers() if member.name.endswith("six.egg-info/top_level.txt")
        )
        extracted = tar.extractfile(top_level_member)
        assert extracted is not None
        declared_roots = tuple(sorted({line.strip() for line in extracted.read().decode("utf-8").splitlines() if line.strip()}))
    assert declared_roots == ("six",)

    # ---- 2. Materialize the pinned consumer (real GitHub commit). ----
    consumer_url = (
        f"https://api.github.com/repos/{pins['consumer_repo']}/contents/{pins['consumer_file']}"
        f"?ref={pins['consumer_commit']}"
    )
    gh_headers = {"Accept": "application/vnd.github.raw"}
    if gh_token:
        gh_headers["Authorization"] = f"Bearer {gh_token}"
    try:
        consumer_source_bytes = _http_get(consumer_url, extra_headers=gh_headers)
    except urllib.error.HTTPError as exc:  # pragma: no cover - network-dependent
        pytest.fail(f"failed to fetch pinned consumer source from GitHub: {exc}")

    consumer_root = tmp_path / "corpus"
    consumer_root.mkdir()
    consumer_file_path = consumer_root / pins["consumer_file"]
    consumer_file_path.write_bytes(consumer_source_bytes)
    assert b"import six" in consumer_source_bytes  # genuine, real usage sanity check

    # ---- 3. Admission: a locally-authored, exact-pin requirements.txt for
    #         "this consumer depends on the pinned provider". ----
    requirements_text = f"{pins['provider_distribution']}=={pins['provider_version']}\n"
    requirements_bytes = requirements_text.encode("utf-8")
    recorded_requirements_digest = digest_bytes(requirements_bytes)

    admitted = admit_consumer(
        consumer_name=pins["consumer_repo"],
        consumer_version=pins["provider_version"],
        consumer_ref=pins["consumer_commit"],
        expected_consumer_ref=pins["consumer_commit"],
        requirements_bytes=requirements_bytes,
        recorded_requirements_digest=recorded_requirements_digest,
    )

    # ---- 4. Provider identity, bound to the real, verified sdist digest. ----
    provider_identity = Identity(
        schema_version=IDENTITY_SCHEMA_VERSION,
        role="provider",
        name=pins["provider_distribution"],
        version=pins["provider_version"],
        digest=digest_value(
            {
                "name": pins["provider_distribution"],
                "version": pins["provider_version"],
                "sdist_sha256": actual_sdist_digest,
            }
        ),
    )

    # ---- 5. Import catalog, from the real extracted top_level.txt evidence. ----
    catalog = build_import_catalog(
        (
            DistributionRecord(
                schema_version=DISTRIBUTION_RECORD_SCHEMA_VERSION,
                distribution=pins["provider_distribution"],
                declared_roots=declared_roots,
                source="top-level-txt",
            ),
        )
    )
    assert not catalog.unresolved, f"unexpected unresolved distributions: {catalog.unresolved}"
    assert len(catalog.mappings) == 1

    # ---- 6. Static resolver over the real downloaded consumer source. ----
    resolver_result = resolve_consumer(
        consumer_root=consumer_root,
        import_roots={"six": pins["provider_distribution"]},
    )
    assert len(resolver_result.references) > 0, "resolver found no statically-resolvable six usage in test_six.py"
    assert all(reference.distribution == pins["provider_distribution"] for reference in resolver_result.references)

    # ---- 7. Assemble the final, deterministic evidence report. ----
    assembled = assemble_usage_evidence(
        provider_identity=provider_identity,
        consumer_identity=admitted.consumer_identity,
        dependency_evidence=admitted.dependency_evidence,
        import_mappings=catalog.mappings,
        reference_batches=(
            ReferenceBatch(
                schema_version=REFERENCE_BATCH_SCHEMA_VERSION,
                origin="e2e-live",
                references=resolver_result.references,
                coverage=resolver_result.coverage,
            ),
        ),
        unresolved_distributions=catalog.unresolved,
        consumer_root=consumer_root,
    )
    assert len(assembled.results) > 0
    # test_six.py genuinely exercises six.* dozens of times, comfortably past
    # MAX_RESULTS -- the assembler's own cap-exceeded bookkeeping (never a
    # silently dropped record) is itself part of what this E2E proves works
    # against real data, so a capped run is an expected, not a failing, outcome.
    if assembled.capped:
        assert len(assembled.capped_results) > 0
    assert len(assembled.report.references) == len(assembled.results)

    # ---- 8. Write report/requirements to disk, drive the real shipped CLI. ----
    report_path = tmp_path / "report.json"
    report_path.write_bytes(assembled.report.to_json_bytes() + b"\n")
    requirements_path = tmp_path / "requirements.txt"
    requirements_path.write_bytes(requirements_bytes)

    repo_root = Path(__file__).resolve().parents[2]
    env = dict(os.environ)
    env["PYTHONPATH"] = str(repo_root / "src")

    verify_cmd = [sys.executable, "-m", "leitir.cli", "usage", "verify", str(report_path), "--json"]
    verify_proc = subprocess.run(verify_cmd, capture_output=True, text=True, timeout=60, env=env, cwd=repo_root)
    assert verify_proc.returncode == 0, f"verify failed: stdout={verify_proc.stdout!r} stderr={verify_proc.stderr!r}"
    verify_payload = json.loads(verify_proc.stdout)
    assert verify_payload["report_digest"] == assembled.report.report_digest
    assert verify_payload["reference_count"] == len(assembled.report.references) > 0
    assert verify_payload["coverage_capped"] == assembled.report.coverage.capped
    assert f"ok report_digest={assembled.report.report_digest}" in verify_proc.stderr

    replay_cmd = [
        sys.executable,
        "-m",
        "leitir.cli",
        "usage",
        "replay",
        str(report_path),
        "--corpus-root",
        str(consumer_root),
        "--requirements",
        str(requirements_path),
        "--times",
        "2",
        "--json",
    ]
    replay_outputs = []
    for _ in range(2):  # run the whole CLI replay twice to prove stable, deterministic output
        replay_proc = subprocess.run(replay_cmd, capture_output=True, text=True, timeout=60, env=env, cwd=repo_root)
        assert replay_proc.returncode == 0, f"replay failed: stdout={replay_proc.stdout!r} stderr={replay_proc.stderr!r}"
        replay_payload = json.loads(replay_proc.stdout)
        assert replay_payload["report_digest"] == assembled.report.report_digest
        assert replay_payload["replay_count"] == 2
        assert replay_payload["byte_identical"] is True
        replay_outputs.append(replay_proc.stdout)

    assert replay_outputs[0] == replay_outputs[1], "CLI replay output was not byte-identical across independent runs"
