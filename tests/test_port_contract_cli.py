"""User-level intent tests for ``leitir bts-port-contract`` (ADR-0033, issue #270).

Drives the public CLI end to end: donor behaviour (a COMPLETE Python BTS
computed from the same fixture shelf ``tests/test_bts_cli.py`` uses) ->
translated Go contract -> port attribution evidence. Also covers the two
sad paths issue #270 requires: a contract that cannot be faithfully
translated must reject rather than degrade, and missing/incompatible
attribution evidence must fail closed exactly as it does for same-language
reuse today. This module never executes agent-written code and never claims
a containment proof: ``bts-port-contract`` translates and attributes only,
and says so in its own JSON output (``containment_proof``).
"""

from __future__ import annotations

import base64
import hashlib
import io
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

from leitir import cli
from leitir.bts_cli import SeedSelector, run_bts_compute
from leitir.materialize import manifest_digest_fields, target_path
from leitir.port_contract import (
    OutcomeKind,
    PortableCase,
    PortableValue,
    PortableValueKind,
    _canonical,
)
from leitir.treehash import compute_materialized_tree_hash

_SHA = "a" * 40
_FIXTURE = Path(__file__).parent / "fixtures" / "bts_cli" / "donor"


def _shelf(root: Path) -> str:
    target = target_path(root, "owner", "donor", _SHA)
    shutil.copytree(_FIXTURE, target)
    digest, scope = compute_materialized_tree_hash(target)
    manifest = {
        "commit_sha": _SHA,
        "fetch_method": "codeload-tarball",
        "fetched_at": "2026-08-15T00:00:00Z",
        "host": "github.com",
        "owner": "owner",
        "repo": "donor",
        "repo_url": "https://github.com/owner/donor",
        "source": "git-commit",
        "parity": "exact",
        "spec": "github:owner/donor",
        "tag": None,
        "verified": True,
        "verified_at": "2026-08-15T00:00:00Z",
    }
    manifest.update(manifest_digest_fields(digest, scope=scope))
    (target / "leitir-manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    return manifest["materialized_tree_hash"]


def _bts_digest(root: Path) -> str:
    artifacts = run_bts_compute(
        root, "owner", "donor", _SHA, seed=SeedSelector("package.policy", "package.policy.normalize_contract")
    )
    assert artifacts.result.bts is not None
    return artifacts.result.bts.bts_digest


def _contract_json(root: Path, mth: str, *, bts_digest: str, case: PortableCase, return_kind: str | None) -> bytes:
    payload = {
        "bts_digest": bts_digest,
        "cases": [case._payload()],
        "donor": {"commit_sha": _SHA, "materialized_tree_hash": mth, "slug": "owner/donor", "source": "git-commit"},
        "function_qualified_name": "package.policy.normalize_contract",
        "parameter_kinds": ["string"],
        "return_kind": return_kind,
        "schema_version": "leitir-portable-contract-v1",
        "target_function_name": "NormalizeContract",
    }
    digest = "sha256:" + hashlib.sha256(_canonical(payload)).hexdigest()
    payload["suite_digest"] = digest
    return json.dumps(payload).encode("utf-8")


def _return_case(name: str = "identity_string") -> PortableCase:
    return PortableCase(
        name,
        (PortableValue(PortableValueKind.STRING, string_value="hello"),),
        OutcomeKind.RETURN,
        expected=PortableValue(PortableValueKind.STRING, string_value="hello"),
    )


def _raises_case() -> PortableCase:
    return PortableCase(
        "raises_value_error",
        (PortableValue(PortableValueKind.STRING, string_value="bad"),),
        OutcomeKind.RAISES,
        donor_exception_type="ValueError",
    )


_DONOR_SOURCE_BYTES = b"# SPDX-License-Identifier: MIT\ndef normalize_contract(value):\n    return value\n"


def _donor_sources_json() -> bytes:
    payload = {
        "schema_version": "leitir-port-donor-sources-v1",
        "sources": [
            {
                "source_record_id": "src1",
                "packet_path": "package/policy.py",
                "source_path": "package/policy.py",
                "source_bytes_base64": base64.b64encode(_DONOR_SOURCE_BYTES).decode("ascii"),
                "package_scope": ".",
                "verified_files": [],
                "contributing_source_record_ids": [],
                "modified_from_sha256": None,
            }
        ],
    }
    return json.dumps(payload).encode("utf-8")


def _recipient_policy_json(*, allowed: tuple[str, ...] = ("MIT",)) -> bytes:
    payload = {
        "policy_id": "test-recipient",
        "policy_version": "v1",
        "use_category": "internal",
        "allowed_spdx_expressions": list(allowed),
        "prohibited_spdx_expressions": [],
    }
    return json.dumps(payload).encode("utf-8")


def _run(argv: list[str]) -> tuple[int, dict[str, object], str]:
    out, err = io.StringIO(), io.StringIO()
    code = cli.main(argv, stdout=out, stderr=err)
    payload: dict[str, object] = {}
    text = out.getvalue().strip()
    if text:
        payload = json.loads(text)
    return code, payload, err.getvalue()


def _base_argv(root: Path, contract: Path, donor_sources: Path, recipient_policy: Path, out_dir: Path) -> list[str]:
    return [
        "bts-port-contract", f"owner/donor@{_SHA}",
        "--root", str(root),
        "--seed-module", "package.policy",
        "--seed-name", "package.policy.normalize_contract",
        "--contract-spec", str(contract),
        "--target-language", "go",
        "--donor-sources", str(donor_sources),
        "--recipient-policy", str(recipient_policy),
        "--out", str(out_dir),
        "--json",
    ]


def test_translates_donor_behaviour_into_go_contract_and_attribution(tmp_path: Path) -> None:
    root = tmp_path / "root"
    mth = _shelf(root)
    bts_digest = _bts_digest(root)

    contract = tmp_path / "contract.json"
    contract.write_bytes(_contract_json(root, mth, bts_digest=bts_digest, case=_return_case(), return_kind="string"))
    donor_sources = tmp_path / "donor_sources.json"
    donor_sources.write_bytes(_donor_sources_json())
    recipient_policy = tmp_path / "recipient_policy.json"
    recipient_policy.write_bytes(_recipient_policy_json())
    out_dir = tmp_path / "out"

    code, payload, err = _run(_base_argv(root, contract, donor_sources, recipient_policy, out_dir))
    assert code == 0, err

    # The user observes: a deterministic Go contract test file, obligations
    # and attribution evidence, and an explicit statement that no
    # containment proof was executed (this change never fakes one).
    assert payload["target_language"] == "go"
    assert payload["attribution_mode"] == "behavioral_descent"
    assert payload["bts_digest"] == bts_digest
    assert payload["containment_proof"] == "not_executed_v1"

    go_source = (out_dir / "normalizecontract_contract_test.go").read_text(encoding="utf-8")
    assert "package donorport" in go_source
    assert "func TestPortableContract_IdentityString" in go_source
    assert "NormalizeContract(" in go_source
    # The Python donor exception model never leaks into the generated file.
    assert "except" not in go_source and "raise" not in go_source

    obligations = json.loads((out_dir / "obligations.json").read_text(encoding="utf-8"))
    assert obligations["obligations_digest"] == payload["obligations_digest"]
    attribution_md = (out_dir / "ATTRIBUTION.md").read_text(encoding="utf-8")
    assert "MIT" in attribution_md

    result_on_disk = json.loads((out_dir / "port-result.json").read_text(encoding="utf-8"))
    assert result_on_disk == payload


def test_raises_contract_rejects_instead_of_approximating(tmp_path: Path) -> None:
    """The issue's own illustrative case: a Python exception has no faithful Go equivalent."""

    root = tmp_path / "root"
    mth = _shelf(root)
    bts_digest = _bts_digest(root)

    contract = tmp_path / "contract.json"
    contract.write_bytes(_contract_json(root, mth, bts_digest=bts_digest, case=_raises_case(), return_kind=None))
    donor_sources = tmp_path / "donor_sources.json"
    donor_sources.write_bytes(_donor_sources_json())
    recipient_policy = tmp_path / "recipient_policy.json"
    recipient_policy.write_bytes(_recipient_policy_json())
    out_dir = tmp_path / "out"

    code, payload, err = _run(_base_argv(root, contract, donor_sources, recipient_policy, out_dir))

    assert code == 1
    assert "port_contract_raises_not_portable_go_v1" in err
    assert "reject_unsupported_construct" in err
    # A rejected port never leaves a partial or approximated artifact behind.
    assert not out_dir.exists()


def test_incompatible_recipient_license_policy_fails_closed(tmp_path: Path) -> None:
    """Missing/incompatible attribution evidence must fail closed, as it does for same-language reuse."""

    root = tmp_path / "root"
    mth = _shelf(root)
    bts_digest = _bts_digest(root)

    contract = tmp_path / "contract.json"
    contract.write_bytes(_contract_json(root, mth, bts_digest=bts_digest, case=_return_case(), return_kind="string"))
    donor_sources = tmp_path / "donor_sources.json"
    donor_sources.write_bytes(_donor_sources_json())
    recipient_policy = tmp_path / "recipient_policy.json"
    # The recipient explicitly does not allow MIT: this must reject, not
    # silently drop the license gate that a same-language reuse packet
    # would enforce.
    recipient_policy.write_bytes(_recipient_policy_json(allowed=("Apache-2.0",)))
    out_dir = tmp_path / "out"

    code, payload, err = _run(_base_argv(root, contract, donor_sources, recipient_policy, out_dir))

    assert code == 1
    assert "reject_license_incompatible" in err
    assert not out_dir.exists()


def test_bts_digest_mismatch_rejects(tmp_path: Path) -> None:
    root = tmp_path / "root"
    mth = _shelf(root)
    _bts_digest(root)  # computed for parity with other tests; unused here

    contract = tmp_path / "contract.json"
    forged_digest = "sha256:" + "0" * 64
    contract.write_bytes(_contract_json(root, mth, bts_digest=forged_digest, case=_return_case(), return_kind="string"))
    donor_sources = tmp_path / "donor_sources.json"
    donor_sources.write_bytes(_donor_sources_json())
    recipient_policy = tmp_path / "recipient_policy.json"
    recipient_policy.write_bytes(_recipient_policy_json())
    out_dir = tmp_path / "out"

    code, payload, err = _run(_base_argv(root, contract, donor_sources, recipient_policy, out_dir))

    assert code == 1
    assert "reject_provenance_mismatch" in err
    assert not out_dir.exists()


def test_translated_contract_is_hash_seed_independent(tmp_path: Path) -> None:
    root = tmp_path / "root"
    mth = _shelf(root)
    bts_digest = _bts_digest(root)

    contract = tmp_path / "contract.json"
    contract.write_bytes(_contract_json(root, mth, bts_digest=bts_digest, case=_return_case(), return_kind="string"))
    donor_sources = tmp_path / "donor_sources.json"
    donor_sources.write_bytes(_donor_sources_json())
    recipient_policy = tmp_path / "recipient_policy.json"
    recipient_policy.write_bytes(_recipient_policy_json())

    payloads = []
    go_bytes_by_seed = []
    for hash_seed in ("0", "1", "1337", "4294967295"):
        out_dir = tmp_path / f"out-{hash_seed}"
        env = dict(os.environ)
        env["PYTHONHASHSEED"] = hash_seed
        env["PYTHONPATH"] = str(Path(__file__).resolve().parents[1] / "src")
        argv = _base_argv(root, contract, donor_sources, recipient_policy, out_dir)
        completed = subprocess.run(
            [sys.executable, "-m", "leitir.cli", *argv],
            capture_output=True, text=True, env=env, timeout=60,
        )
        assert completed.returncode == 0, completed.stderr
        payloads.append(json.loads(completed.stdout))
        go_bytes_by_seed.append((out_dir / "normalizecontract_contract_test.go").read_bytes())

    assert len(set(json.dumps(item, sort_keys=True) for item in payloads)) == 1
    assert len(set(go_bytes_by_seed)) == 1
