"""Recipient profiles are content-bound, deterministic, and fail closed."""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

import leitir.lockfiles as lockfiles
from leitir.bts_errors import BTSError, BTSRejectReason
from leitir.lockfiles import DependencyManifestPolicy
from leitir.project_profile import (
    RecipientInputManifest,
    RecipientManifestEntry,
    profile_project,
)


def _manifest(*entries: RecipientManifestEntry) -> RecipientInputManifest:
    return RecipientInputManifest.create("recipient:test", tuple(entries))


def _entry(path: str, text: str) -> RecipientManifestEntry:
    return RecipientManifestEntry.from_bytes(path, "dependency", text.encode())


def test_valid_manifest_has_exact_dependencies_runtime_provenance_and_digest() -> None:
    manifest = _manifest(
        _entry(
            "pyproject.toml",
            '[project]\nrequires-python = ">=3.11"\ndependencies = ["Requests==2.32.0"]\n',
        ),
        _entry("requirements.txt", "idna==3.7\n"),
    )
    policy = DependencyManifestPolicy(("pyproject.toml", "requirements.txt"))

    profile = profile_project(manifest, policy)

    assert [(item.ecosystem, item.name, item.version) for item in profile.dependencies] == [
        ("pypi", "idna", "3.7"),
        ("pypi", "requests", "2.32.0"),
    ]
    assert [(item.language, item.runtime, item.constraint) for item in profile.runtime_constraints] == [
        ("python", "python", ">=3.11")
    ]
    assert [item.path for item in profile.provenance] == ["pyproject.toml", "requirements.txt"]
    assert profile.profile_digest == "sha256:c2e74abc878a41a6277e50d82ffdd1dda66d2114d203498e354524c39c9e58e7"
    assert profile.to_bytes().endswith(b"\n")


def test_malformed_cargo_record_rejects_instead_of_complete_graph() -> None:
    manifest = _manifest(
        _entry(
            "Cargo.lock",
            'version = 3\npackage = [1, {name = "serde", version = "1.0.203", source = "registry"}]\n',
        )
    )

    with pytest.raises(BTSError) as caught:
        profile_project(manifest, DependencyManifestPolicy(("Cargo.lock",)))

    assert caught.value.reason is BTSRejectReason.REJECT_COVERAGE_MISCOUNT
    assert caught.value.evidence.detail_code == "dependency_record_malformed_v1"


def test_missing_required_manifest_record_rejects() -> None:
    with pytest.raises(BTSError) as caught:
        profile_project(_manifest(), DependencyManifestPolicy(("requirements.txt",)))

    assert caught.value.reason is BTSRejectReason.REJECT_PROVENANCE_MISMATCH
    assert caught.value.evidence.detail_code == "recipient_manifest_source_absent_v1"


def test_manifest_dependency_source_omitted_from_policy_rejects() -> None:
    manifest = _manifest(
        _entry("requirements.txt", "safe==1.0\n"),
        _entry(
            "services/api/Cargo.lock",
            'version = 3\n[[package]]\nname = "hidden"\nversion = "9.9.9"\nsource = "registry"\n',
        ),
    )

    with pytest.raises(BTSError) as caught:
        profile_project(manifest, DependencyManifestPolicy(("requirements.txt",)))

    assert caught.value.reason is BTSRejectReason.REJECT_COVERAGE_MISCOUNT
    assert caught.value.evidence.detail_code == "dependency_record_omitted_v1"


def test_profile_is_manifest_bound_and_does_not_probe_host(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    (tmp_path / "Cargo.lock").write_text(
        'version = 3\n[[package]]\nname = "poison"\nversion = "9.9.9"\nsource = "registry"\n'
    )
    manifest = RecipientInputManifest.create(
        str(tmp_path), (_entry("requirements.txt", "safe==1.0\n"),)
    )

    def fail_read(*_args: object, **_kwargs: object) -> str:
        raise AssertionError("host filesystem was probed")

    monkeypatch.setattr(Path, "read_text", fail_read)
    profile = profile_project(manifest, DependencyManifestPolicy(("requirements.txt",)))
    assert [item.name for item in profile.dependencies] == ["safe"]


def test_manifest_wrapper_reuses_existing_python_parser(monkeypatch: pytest.MonkeyPatch) -> None:
    called = 0
    parser = lockfiles._python_edges

    def recording_parser(
        text: str,
        diagnostics: list[tuple[str, lockfiles.ManifestDiagnosticKind]] | None = None,
    ) -> list[lockfiles.DependencyEdge]:
        nonlocal called
        called += 1
        return parser(text, diagnostics)

    monkeypatch.setattr(lockfiles, "_python_edges", recording_parser)
    profile_project(
        _manifest(_entry("requirements.txt", "demo==1.2.3\n")),
        DependencyManifestPolicy(("requirements.txt",)),
    )
    assert called == 1


@pytest.mark.parametrize("seed", ["0", "1", "42"])
def test_profile_digest_is_hashseed_independent(seed: str) -> None:
    script = """
from leitir.lockfiles import DependencyManifestPolicy
from leitir.project_profile import RecipientInputManifest, RecipientManifestEntry, profile_project
entry = RecipientManifestEntry.from_bytes('requirements.txt', 'dependency', b'beta==2.0\\nalpha==1.0\\n')
manifest = RecipientInputManifest.create('recipient:seed', (entry,))
print(profile_project(manifest, DependencyManifestPolicy(('requirements.txt',))).profile_digest)
"""
    environment = dict(os.environ, PYTHONHASHSEED=seed)
    completed = subprocess.run(
        [sys.executable, "-c", script],
        check=True,
        capture_output=True,
        text=True,
        env=environment,
    )
    assert completed.stdout.strip() == "sha256:c34910319d619c3e9f0b6e539c07da78dd0f427becb4e15f73f2280792ae19dd"
