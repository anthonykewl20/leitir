"""User-level intent tests for ``leitir bts-port-contract`` (ADR-0033, issue #270).

Drives the public CLI end to end: donor behaviour (a COMPLETE Python BTS
computed from a fixture shelf) -> translated Go contract -> port
attribution evidence. Also covers the sad paths issue #270 requires: a
contract that cannot be faithfully translated must reject rather than
degrade, missing/incompatible attribution evidence must fail closed exactly
as it does for same-language reuse today, and -- following two rounds of
adversarial review on the original PR (reviewer-hy3) -- neither the donor's
license evidence nor its identity may be taken on the caller's word.

The second review round found the first fix insufficient: verifying only
the BTS member *span* inside a caller-supplied blob did not stop a forged
license header placed *outside* that span in the same blob, since
``evaluate_license_policy``'s header scan reads the whole blob. The fix in
this revision removes the caller-supplied donor-bytes channel entirely --
``bts-port-contract`` no longer accepts a ``--donor-sources`` flag at all.
Every byte ``evaluate_license_policy`` evaluates is read directly from the
same tree-hash-verified donor materialization the BTS was computed from
(``leitir.port_contract.load_donor_sources_from_snapshot``); there is no
remaining caller-controlled blob for a forged header to hide in.
``test_tampered_materialized_source_with_span_preserved_rejects_at_tree_hash``
below reproduces the reviewer's exact attack shape (identical member span,
mutated surrounding bytes, injected SPDX header, line count preserved so
span addressing still resolves) and confirms it now fails closed at the
pre-existing tree-verification gate, before any BTS or license logic runs.

This module never executes agent-written code and never claims a
containment proof: ``bts-port-contract`` translates and attributes only,
and says so in its own JSON output (``containment_proof``).
"""

from __future__ import annotations

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
_FIXTURES = Path(__file__).parent / "fixtures" / "bts_cli"
_UNLICENSED_FIXTURE = "donor"
_MIT_FIXTURE = "donor-mit"


def _shelf(root: Path, *, fixture: str = _UNLICENSED_FIXTURE) -> tuple[str, bytes]:
    """Materialize a verified donor shelf and return (materialized_tree_hash, real on-disk policy.py bytes)."""

    target = target_path(root, "owner", "donor", _SHA)
    shutil.copytree(_FIXTURES / fixture, target)
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
    real_bytes = (target / "package" / "policy.py").read_bytes()
    return manifest["materialized_tree_hash"], real_bytes


def _bts_digest(root: Path) -> str:
    artifacts = run_bts_compute(
        root, "owner", "donor", _SHA, seed=SeedSelector("package.policy", "package.policy.normalize_contract")
    )
    assert artifacts.result.bts is not None
    return artifacts.result.bts.bts_digest


def _contract_json(
    root: Path,
    mth: str,
    *,
    bts_digest: str,
    case: PortableCase,
    return_kind: str | None,
    donor_slug: str = "owner/donor",
    donor_commit_sha: str = _SHA,
) -> bytes:
    payload = {
        "bts_digest": bts_digest,
        "cases": [case._payload()],
        "donor": {"commit_sha": donor_commit_sha, "materialized_tree_hash": mth, "slug": donor_slug, "source": "git-commit"},
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


def _base_argv(root: Path, contract: Path, recipient_policy: Path, out_dir: Path) -> list[str]:
    return [
        "bts-port-contract", f"owner/donor@{_SHA}",
        "--root", str(root),
        "--seed-module", "package.policy",
        "--seed-name", "package.policy.normalize_contract",
        "--contract-spec", str(contract),
        "--target-language", "go",
        "--recipient-policy", str(recipient_policy),
        "--out", str(out_dir),
        "--json",
    ]


def test_translates_donor_behaviour_into_go_contract_and_attribution(tmp_path: Path) -> None:
    root = tmp_path / "root"
    mth, _real_bytes = _shelf(root, fixture=_MIT_FIXTURE)
    bts_digest = _bts_digest(root)

    contract = tmp_path / "contract.json"
    contract.write_bytes(_contract_json(root, mth, bts_digest=bts_digest, case=_return_case(), return_kind="string"))
    recipient_policy = tmp_path / "recipient_policy.json"
    recipient_policy.write_bytes(_recipient_policy_json())
    out_dir = tmp_path / "out"

    code, payload, err = _run(_base_argv(root, contract, recipient_policy, out_dir))
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


def test_unlicensed_donor_fails_closed_with_no_donor_sources_flag_to_forge(tmp_path: Path) -> None:
    """The positive path is not vacuous: with the real (unlicensed) fixture, resolution
    genuinely fails, and there is no ``--donor-sources`` flag left through which a caller
    could supply a substitute license claim."""

    root = tmp_path / "root"
    mth, _real_bytes = _shelf(root)  # no SPDX marker on disk
    bts_digest = _bts_digest(root)

    contract = tmp_path / "contract.json"
    contract.write_bytes(_contract_json(root, mth, bts_digest=bts_digest, case=_return_case(), return_kind="string"))
    recipient_policy = tmp_path / "recipient_policy.json"
    recipient_policy.write_bytes(_recipient_policy_json())
    out_dir = tmp_path / "out"

    code, payload, err = _run(_base_argv(root, contract, recipient_policy, out_dir))

    assert code == 1
    assert "reject_license_unknown" in err
    assert not out_dir.exists()


def test_raises_contract_rejects_instead_of_approximating(tmp_path: Path) -> None:
    """The issue's own illustrative case: a Python exception has no faithful Go equivalent."""

    root = tmp_path / "root"
    mth, _real_bytes = _shelf(root)
    bts_digest = _bts_digest(root)

    contract = tmp_path / "contract.json"
    contract.write_bytes(_contract_json(root, mth, bts_digest=bts_digest, case=_raises_case(), return_kind=None))
    recipient_policy = tmp_path / "recipient_policy.json"
    recipient_policy.write_bytes(_recipient_policy_json())
    out_dir = tmp_path / "out"

    code, payload, err = _run(_base_argv(root, contract, recipient_policy, out_dir))

    assert code == 1
    assert "port_contract_raises_not_portable_go_v1" in err
    assert "reject_unsupported_construct" in err
    # A rejected port never leaves a partial or approximated artifact behind.
    assert not out_dir.exists()


def test_incompatible_recipient_license_policy_fails_closed(tmp_path: Path) -> None:
    """Missing/incompatible attribution evidence must fail closed, as it does for same-language reuse."""

    root = tmp_path / "root"
    mth, _real_bytes = _shelf(root, fixture=_MIT_FIXTURE)
    bts_digest = _bts_digest(root)

    contract = tmp_path / "contract.json"
    contract.write_bytes(_contract_json(root, mth, bts_digest=bts_digest, case=_return_case(), return_kind="string"))
    recipient_policy = tmp_path / "recipient_policy.json"
    # The recipient explicitly does not allow MIT: this must reject, not
    # silently drop the license gate that a same-language reuse packet
    # would enforce.
    recipient_policy.write_bytes(_recipient_policy_json(allowed=("Apache-2.0",)))
    out_dir = tmp_path / "out"

    code, payload, err = _run(_base_argv(root, contract, recipient_policy, out_dir))

    assert code == 1
    assert "reject_license_incompatible" in err
    assert not out_dir.exists()


def test_bts_digest_mismatch_rejects(tmp_path: Path) -> None:
    root = tmp_path / "root"
    mth, _real_bytes = _shelf(root)
    _bts_digest(root)  # computed for parity with other tests; unused here

    contract = tmp_path / "contract.json"
    forged_digest = "sha256:" + "0" * 64
    contract.write_bytes(_contract_json(root, mth, bts_digest=forged_digest, case=_return_case(), return_kind="string"))
    recipient_policy = tmp_path / "recipient_policy.json"
    recipient_policy.write_bytes(_recipient_policy_json())
    out_dir = tmp_path / "out"

    code, payload, err = _run(_base_argv(root, contract, recipient_policy, out_dir))

    assert code == 1
    assert "reject_provenance_mismatch" in err
    assert not out_dir.exists()


def test_donor_identity_unbound_from_the_computed_commit_rejects(tmp_path: Path) -> None:
    """reviewer-hy3 first-round P1 probe 2: the portable contract's declared donor identity must
    be bound to the BTS actually computed, never merely a caller-declared label."""

    root = tmp_path / "root"
    mth, _real_bytes = _shelf(root, fixture=_MIT_FIXTURE)
    bts_digest = _bts_digest(root)

    contract = tmp_path / "contract.json"
    # The BTS was genuinely computed from owner/donor@_SHA, but the suite
    # claims a different donor slug entirely.
    contract.write_bytes(
        _contract_json(
            root, mth, bts_digest=bts_digest, case=_return_case(), return_kind="string",
            donor_slug="attacker/stolen-repo",
        )
    )
    recipient_policy = tmp_path / "recipient_policy.json"
    recipient_policy.write_bytes(_recipient_policy_json())
    out_dir = tmp_path / "out"

    code, payload, err = _run(_base_argv(root, contract, recipient_policy, out_dir))

    assert code == 1
    assert "port_contract_donor_identity_mismatch_v1" in err
    assert "reject_provenance_mismatch" in err
    assert not out_dir.exists()


def test_tampered_materialized_source_with_span_preserved_rejects_at_tree_hash(tmp_path: Path) -> None:
    """reviewer-hy3 second-round P1 exact repro: keep the BTS member's byte span byte-identical
    (so a span-only check would pass) while rewriting every surrounding byte -- including
    injecting a fabricated ``SPDX-License-Identifier: MIT`` header -- and preserving the exact
    per-line byte length of the mutated lines (so ``_span``'s line/col addressing still resolves
    to the same offsets). Because donor bytes are now read only from the materialized shelf, and
    that shelf's *entire* tree (not merely the member span) is hash-verified before any BTS
    computation runs, this must reject at the pre-existing tree-verification gate -- there is no
    later point where a forged blob could still reach license evaluation."""

    root = tmp_path / "root"
    mth, real_bytes = _shelf(root)
    bts_digest = _bts_digest(root)
    assert b"SPDX-License-Identifier" not in real_bytes

    original_lines = real_bytes.splitlines(keepends=True)
    assert len(original_lines) == 6  # 4 header comment lines, then def + return
    forged_header_lines = [
        b"# SPDX-License-Identifier: MIT",
        b"# (c) Totally Fabricated Corp -- injected outside the verified span",
        b"# padding line to preserve line count",
        b"# padding line to preserve line count 2",
    ]
    mutated_lines = []
    for original, forged_text in zip(original_lines[:4], forged_header_lines, strict=True):
        # Preserve the exact per-line byte length (including the trailing
        # newline) so every later line's cumulative byte offset -- and
        # therefore the member span's start/end coordinates -- is
        # unaffected by this rewrite.
        body = forged_text.ljust(len(original) - 1, b" ")
        assert len(body) == len(original) - 1
        mutated_lines.append(body + b"\n")
    tampered = b"".join(mutated_lines) + b"".join(original_lines[4:])
    assert len(tampered) == len(real_bytes)
    assert tampered[-23:] == real_bytes[-23:]  # the function body itself is untouched

    policy_path = target_path(root, "owner", "donor", _SHA) / "package" / "policy.py"
    policy_path.write_bytes(tampered)
    # The manifest's materialized_tree_hash is deliberately left stale --
    # this models bytes changing after verification, not a caller declaring
    # anything: there is no --donor-sources flag left to declare through.

    contract = tmp_path / "contract.json"
    contract.write_bytes(_contract_json(root, mth, bts_digest=bts_digest, case=_return_case(), return_kind="string"))
    recipient_policy = tmp_path / "recipient_policy.json"
    recipient_policy.write_bytes(_recipient_policy_json())
    out_dir = tmp_path / "out"

    code, payload, err = _run(_base_argv(root, contract, recipient_policy, out_dir))

    assert code == 1
    assert "reject_provenance_mismatch" in err
    # Caught by ADR-0006's pre-existing load-time tree verification
    # (materialize.read_valid_manifest), even earlier than run_bts_compute's
    # own redundant re-check -- there is no point in the pipeline where a
    # mutated-but-span-preserved file reaches BTS computation or license
    # evaluation.
    assert "bts_cli_shelf_unverified_v1" in err or "not verified" in err
    # No clean, MIT-laundered attribution was ever produced.
    assert not out_dir.exists()


def test_translated_contract_is_hash_seed_independent(tmp_path: Path) -> None:
    root = tmp_path / "root"
    mth, _real_bytes = _shelf(root, fixture=_MIT_FIXTURE)
    bts_digest = _bts_digest(root)

    contract = tmp_path / "contract.json"
    contract.write_bytes(_contract_json(root, mth, bts_digest=bts_digest, case=_return_case(), return_kind="string"))
    recipient_policy = tmp_path / "recipient_policy.json"
    recipient_policy.write_bytes(_recipient_policy_json())

    payloads = []
    go_bytes_by_seed = []
    for hash_seed in ("0", "1", "1337", "4294967295"):
        out_dir = tmp_path / f"out-{hash_seed}"
        env = dict(os.environ)
        env["PYTHONHASHSEED"] = hash_seed
        env["PYTHONPATH"] = str(Path(__file__).resolve().parents[1] / "src")
        argv = _base_argv(root, contract, recipient_policy, out_dir)
        completed = subprocess.run(
            [sys.executable, "-m", "leitir.cli", *argv],
            capture_output=True, text=True, env=env, timeout=60,
        )
        assert completed.returncode == 0, completed.stderr
        payloads.append(json.loads(completed.stdout))
        go_bytes_by_seed.append((out_dir / "normalizecontract_contract_test.go").read_bytes())

    assert len(set(json.dumps(item, sort_keys=True) for item in payloads)) == 1
    assert len(set(go_bytes_by_seed)) == 1
