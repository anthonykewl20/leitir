"""The usage evidence fixture corpus is well-formed and covers every required case.

Downstream issues (#256-#258) will ADD cases to this corpus, so this module
iterates over whatever is discovered under ``tests/fixtures/usage/*`` rather
than hardcoding a case list, and only asserts the required minimum set is
present (see ``docs/adr/0025-usage-evidence-and-replay-contract.md``).
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from leitir.safeio import read_regular_file
from leitir.usage import FIXTURE_MANIFEST_SCHEMA_VERSION

FIXTURES_ROOT = Path(__file__).resolve().parent / "fixtures" / "usage"

# The corpus this issue (#255) must deliver at minimum. #256-#258 append to
# this set; they must never remove one of these kinds.
REQUIRED_CASE_KINDS = frozenset(
    {"positive", "alias", "shadowing", "ambiguous", "unsupported", "tamper", "determinism"}
)

_REQUIRED_MANIFEST_FIELDS = frozenset(
    {
        "schema_version",
        "case",
        "kind",
        "description",
        "requirements_file",
        "consumer_dir",
        "report_file",
        "expect",
        "expected_state",
    }
)
# Downstream issues (#256-#258) may add case-specific manifest fields (this
# corpus already does, for its tamper case); only unknown fields outside this
# allowed set would indicate an undocumented, undiscoverable extension.
_OPTIONAL_MANIFEST_FIELDS = frozenset({"tamper_stage", "expected_error"})
_ALLOWED_MANIFEST_FIELDS = _REQUIRED_MANIFEST_FIELDS | _OPTIONAL_MANIFEST_FIELDS
_VALID_EXPECT_VALUES = frozenset({"valid", "tamper"})
_MAX_MANIFEST_BYTES = 16_384


@dataclass(frozen=True, slots=True)
class CaseFixture:
    """One discovered usage fixture case: its directory and parsed manifest."""

    name: str
    directory: Path
    manifest: dict[str, object]


def discover_cases() -> list[CaseFixture]:
    """Return every fixture case directory under ``tests/fixtures/usage``, sorted by name.

    A case directory is any immediate child of the fixtures root that
    contains a ``manifest.json``; ``generate.py`` (the maintenance script
    that produces the corpus) is not a case and is skipped.
    """

    cases: list[CaseFixture] = []
    for entry in sorted(FIXTURES_ROOT.iterdir()):
        manifest_path = entry / "manifest.json"
        if not entry.is_dir() or not manifest_path.is_file():
            continue
        raw = read_regular_file(manifest_path, maximum_bytes=_MAX_MANIFEST_BYTES, no_follow=True)
        manifest = json.loads(raw.decode("utf-8"))
        cases.append(CaseFixture(name=entry.name, directory=entry, manifest=manifest))
    return cases


def test_corpus_root_exists_and_has_at_least_one_case() -> None:
    assert FIXTURES_ROOT.is_dir()
    assert discover_cases()


def test_corpus_contains_every_required_case_kind() -> None:
    kinds = {case.manifest.get("kind") for case in discover_cases()}
    missing = REQUIRED_CASE_KINDS - kinds
    assert not missing, f"fixture corpus is missing required case kinds: {sorted(missing)}"


def test_every_case_manifest_is_closed_and_self_describing() -> None:
    cases = discover_cases()
    assert cases
    for case in cases:
        manifest = case.manifest
        assert isinstance(manifest, dict), case.name
        keys = frozenset(manifest.keys())
        unknown = keys - _ALLOWED_MANIFEST_FIELDS
        missing = _REQUIRED_MANIFEST_FIELDS - keys
        assert not unknown, (case.name, sorted(unknown))
        assert not missing, (case.name, sorted(missing))
        assert manifest["schema_version"] == FIXTURE_MANIFEST_SCHEMA_VERSION
        assert manifest["case"] == case.name
        assert manifest["kind"] in REQUIRED_CASE_KINDS
        assert isinstance(manifest["description"], str) and manifest["description"]
        assert manifest["expect"] in _VALID_EXPECT_VALUES


def test_every_case_directory_has_its_declared_files() -> None:
    for case in discover_cases():
        manifest = case.manifest
        requirements_path = case.directory / str(manifest["requirements_file"])
        report_path = case.directory / str(manifest["report_file"])
        consumer_dir = case.directory / str(manifest["consumer_dir"])
        assert requirements_path.is_file(), case.name
        assert report_path.is_file(), case.name
        assert consumer_dir.is_dir(), case.name
        assert any(consumer_dir.rglob("*.py")), case.name


def test_tamper_case_manifest_declares_its_stage_and_error() -> None:
    tamper_cases = [case for case in discover_cases() if case.manifest.get("kind") == "tamper"]
    assert tamper_cases, "at least one tamper case is required"
    for case in tamper_cases:
        manifest = case.manifest
        assert manifest["expect"] == "tamper"
        assert manifest.get("tamper_stage") in {"validate", "replay"}
        assert manifest.get("expected_error") == "UsageTamperError"


def test_determinism_case_is_present_and_marked_valid() -> None:
    determinism_cases = [case for case in discover_cases() if case.manifest.get("kind") == "determinism"]
    assert determinism_cases
    for case in determinism_cases:
        assert case.manifest["expect"] == "valid"
