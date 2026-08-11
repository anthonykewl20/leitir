from __future__ import annotations

import hashlib
import os
import subprocess
import sys
from pathlib import Path
from typing import cast

import pytest

from leitir.bts import (
    BTS,
    BTSDisposition,
    BTSResult,
    BTSStatus,
    MemberEvidence,
    RequiredFileEvidence,
    RequiredSymbolEvidence,
)
from leitir.bts import (
    _digest as _bts_digest,
)
from leitir.bts_errors import BTSError, BTSRejectReason
from leitir.graph.model import NodeId, NodeKind, NodeOrigin, SourceRef
from leitir.relocate import (
    BindingScope,
    ContractTest,
    FileRole,
    ModuleMap,
    RecipientBinding,
    RecipientBindingManifest,
    SourceFile,
    relocate_tests,
)

_HEX = "0" * 64
_COMMIT = "1" * 40
_BLOB = "2" * 40


def _digest(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _bts(source: bytes, *, start_col: int = 0) -> BTS:
    node = NodeId(NodeOrigin.DONOR, NodeKind.FUNCTION, "donor.mod", "f", "donor/mod.py:1")
    source_ref = SourceRef(
        "owner/repo",
        _COMMIT,
        "donor/mod.py",
        _BLOB,
        1,
        start_col,
        len(source.splitlines()),
        len(source.splitlines()[-1]),
    )
    member_bytes = source[start_col:-1] if source.endswith(b"\n") else source[start_col:]
    member = MemberEvidence(node, source_ref, _digest(member_bytes), BTSDisposition.INCLUDE)
    draft = BTS(
        "leitir-bts-v1",
        node,
        (member,),
        (),
        (RequiredFileEvidence(source_ref.path, source_ref.blob_sha, member.source_bytes_sha256),),
        (RequiredSymbolEvidence(node, source_ref),),
        "sha256:" + _HEX,
        "sha256:" + "1" * 64,
    )
    return BTS(
        draft.schema_version,
        draft.seed,
        draft.members,
        draft.dispositions,
        draft.required_files,
        draft.required_symbols,
        draft.bts_digest,
        _bts_digest(draft, omit=frozenset({"bts_digest", "member_equivalence_digest"})),
    )


def _relocate(source: bytes = b"def f():\n    return 3\n"):
    return relocate_tests(
        _bts(source),
        module_map=ModuleMap.from_pairs(("donor.mod", "transplant.core")),
        source_files=(SourceFile("donor/mod.py", source),),
        tests=(
            ContractTest(
                "test_contract.py",
                b"import json\nimport requests\nfrom donor.mod import f as subject\n\ndef test_f():\n    assert subject() == 3\n",
                "donor.tests.test_contract",
            ),
        ),
        declared_external_modules=("requests",),
    )


def test_complete_bts_relocates_members_and_rewrites_only_donor_imports() -> None:
    relocation = _relocate()
    files = {item.path: item for item in relocation.files}

    source = files["staging-v1/src/transplant/core.py"]
    assert source.content == b"def f():\n    return 3\n"
    assert source.mode == 0o444
    assert files["staging-v1/src/transplant/__init__.py"].content == b""
    rewritten = files["staging-v1/tests/rewritten/test_contract.py"].content
    assert b"from transplant.core import f as subject" in rewritten
    assert b"import json" in rewritten
    assert b"import requests" in rewritten
    assert b"donor.mod" not in rewritten
    assert files["staging-v1/tests/original/test_contract.py"].content.startswith(b"import json")
    assert {item.role for item in relocation.files} >= {
        FileRole.SOURCE,
        FileRole.TEST_ORIGINAL,
        FileRole.TEST_REWRITTEN,
        FileRole.MANIFEST,
    }


def test_unaliased_import_and_references_are_rewritten() -> None:
    source = b"def f():\n    return 3\n"
    relocation = relocate_tests(
        _bts(source),
        module_map=ModuleMap.from_pairs(("donor.mod", "transplant.core")),
        source_files=(SourceFile("donor/mod.py", source),),
        tests=(ContractTest("test_x.py", b"import donor.mod\nassert donor.mod.f() == 3\n", "donor.tests.test_x"),),
    )
    rewritten = next(item.content for item in relocation.files if item.path.endswith("tests/rewritten/test_x.py"))
    assert rewritten == b"import transplant.core\nassert transplant.core.f() == 3\n"


def test_relative_donor_import_is_normalized_and_rewritten() -> None:
    source = b"def f():\n    return 3\n"
    relocation = relocate_tests(
        _bts(source),
        module_map=ModuleMap.from_pairs(("donor.mod", "transplant.core")),
        source_files=(SourceFile("donor/mod.py", source),),
        tests=(ContractTest("test_x.py", b"from ..mod import f\n", "donor.tests.test_x"),),
    )
    rewritten = next(item.content for item in relocation.files if item.path.endswith("tests/rewritten/test_x.py"))
    assert rewritten == b"from transplant.core import f\n"


def test_undeclared_external_import_rejects() -> None:
    source = b"def f():\n    return 3\n"
    with pytest.raises(BTSError) as raised:
        relocate_tests(
            _bts(source),
            module_map=ModuleMap.from_pairs(("donor.mod", "transplant.core")),
            source_files=(SourceFile("donor/mod.py", source),),
            tests=(ContractTest("test_x.py", b"import requests\n", "donor.tests.test_x"),),
        )
    assert raised.value.evidence.detail_code == "relocate_undeclared_external_import_v1"


@pytest.mark.parametrize("target", ["json", "pytest.plugin", "importlib._bootstrap", "leitir.bootstrap"])
def test_module_map_rejects_reserved_and_bootstrap_targets(target: str) -> None:
    with pytest.raises(BTSError) as raised:
        ModuleMap.from_pairs(("donor.mod", target))
    assert raised.value.reason is BTSRejectReason.REJECT_UNRESOLVED_EDGE
    assert raised.value.evidence.detail_code == "relocate_reserved_module_collision_v1"


def test_recipient_module_and_binding_collisions_reject() -> None:
    source = b"def f():\n    return 3\n"
    common = {
        "module_map": ModuleMap.from_pairs(("donor.mod", "transplant.core")),
        "source_files": (SourceFile("donor/mod.py", source),),
        "tests": (),
    }
    with pytest.raises(BTSError, match="definition collides") as binding:
        relocate_tests(
            _bts(source),
            **common,
            recipient_bindings=RecipientBindingManifest((RecipientBinding("transplant.core", "f"),)),
        )
    assert binding.value.evidence.detail_code == "relocate_binding_collision_v1"

    with pytest.raises(BTSError, match="module path collides") as module:
        relocate_tests(
            _bts(source),
            **common,
            recipient_bindings=RecipientBindingManifest(
                (RecipientBinding("transplant", "occupied", BindingScope.MODULE),)
            ),
        )
    assert module.value.evidence.detail_code == "relocate_module_collision_v1"


def test_span_that_needs_an_enclosing_suite_rejects_without_expansion() -> None:
    source = b"    def f():\n        return 3\n"
    with pytest.raises(BTSError) as raised:
        relocate_tests(
            _bts(source, start_col=0),
            module_map=ModuleMap.from_pairs(("donor.mod", "transplant.core")),
            source_files=(SourceFile("donor/mod.py", source),),
            tests=(),
        )
    assert raised.value.reason is BTSRejectReason.REJECT_UNDER_COLLECTION
    assert raised.value.evidence.detail_code == "relocate_required_span_expansion_v1"


def test_omitted_decorator_rejects_instead_of_silent_expansion() -> None:
    source = b"@staticmethod\ndef f():\n    return 3\n"
    bts = _bts(source)
    original = bts.members[0]
    ref = SourceRef(
        original.source.slug,
        original.source.commit_sha,
        original.source.path,
        original.source.blob_sha,
        2,
        0,
        3,
        12,
    )
    member_bytes = b"def f():\n    return 3"
    member = MemberEvidence(original.node, ref, _digest(member_bytes), BTSDisposition.INCLUDE)
    narrowed = BTS(
        bts.schema_version,
        bts.seed,
        (member,),
        bts.dispositions,
        bts.required_files,
        (RequiredSymbolEvidence(original.node, ref),),
        bts.bts_digest,
        bts.member_equivalence_digest,
    )
    narrowed = BTS(
        narrowed.schema_version,
        narrowed.seed,
        narrowed.members,
        narrowed.dispositions,
        narrowed.required_files,
        narrowed.required_symbols,
        narrowed.bts_digest,
        _bts_digest(narrowed, omit=frozenset({"bts_digest", "member_equivalence_digest"})),
    )
    with pytest.raises(BTSError) as raised:
        relocate_tests(
            narrowed,
            module_map=ModuleMap.from_pairs(("donor.mod", "transplant.core")),
            source_files=(SourceFile("donor/mod.py", source),),
            tests=(),
        )
    assert raised.value.reason is BTSRejectReason.REJECT_UNDER_COLLECTION
    assert raised.value.evidence.detail_code == "relocate_required_span_expansion_v1"


def test_bare_bts_with_forged_member_equivalence_digest_rejects() -> None:
    source = b"def f():\n    return 3\n"
    forged = _bts(source)
    forged = BTS(
        forged.schema_version,
        forged.seed,
        forged.members,
        forged.dispositions,
        forged.required_files,
        forged.required_symbols,
        forged.bts_digest,
        "sha256:" + "f" * 64,
    )
    with pytest.raises(BTSError) as raised:
        relocate_tests(
            forged,
            module_map=ModuleMap.from_pairs(("donor.mod", "transplant.core")),
            source_files=(SourceFile("donor/mod.py", source),),
            tests=(),
        )
    assert raised.value.evidence.detail_code == "relocate_bts_identity_v1"


@pytest.mark.parametrize("status", [BTSStatus.PARTIAL, BTSStatus.REJECT])
def test_non_complete_result_refuses_relocation(status: BTSStatus) -> None:
    # The incomplete algebra guarantees bts=None; report is deliberately never
    # inspected because status is the first fail-closed gate.
    result = BTSResult(status, cast("object", None), None)  # type: ignore[arg-type]
    with pytest.raises(BTSError) as raised:
        relocate_tests(
            result,
            module_map=ModuleMap.from_pairs(("donor.mod", "transplant.core")),
            source_files=(),
            tests=(),
        )
    assert raised.value.reason is BTSRejectReason.REJECT_HARD_GATE_FAILED
    assert raised.value.evidence.detail_code == "relocate_non_complete_bts_v1"


@pytest.mark.parametrize(
    "test_bytes,detail",
    [
        (b"import importlib\nsubject = importlib.import_module('donor.mod')\n", "relocate_dynamic_import_v1"),
        (b"subject = __import__('donor.mod')\n", "relocate_dynamic_import_v1"),
        (b"from donor.mod import *\n", "relocate_star_import_v1"),
        (b"try:\n    from donor.mod import f\nexcept ImportError:\n    pass\n", "relocate_conditional_import_v1"),
    ],
)
def test_ambiguous_or_dynamic_rewrites_reject(test_bytes: bytes, detail: str) -> None:
    source = b"def f():\n    return 3\n"
    with pytest.raises(BTSError) as raised:
        relocate_tests(
            _bts(source),
            module_map=ModuleMap.from_pairs(("donor.mod", "transplant.core")),
            source_files=(SourceFile("donor/mod.py", source),),
            tests=(ContractTest("test_x.py", test_bytes, "donor.tests.test_x"),),
        )
    assert raised.value.evidence.detail_code == detail


def test_mount_authorizations_are_distinct_and_read_only() -> None:
    relocation = _relocate()
    assert relocation.baseline_mounts != relocation.rerun_mounts
    assert any(item.donor_present for item in relocation.baseline_mounts)
    assert not any(item.donor_present for item in relocation.rerun_mounts)
    assert all(item.read_only for item in relocation.baseline_mounts + relocation.rerun_mounts)


def test_publish_requires_empty_recipient_and_preserves_read_only_bytes(tmp_path: Path) -> None:
    relocation = _relocate()
    target = tmp_path / "recipient"
    relocation.publish(target)
    output = target / "staging-v1/src/transplant/core.py"
    assert output.read_bytes() == b"def f():\n    return 3\n"
    assert output.stat().st_mode & 0o222 == 0

    occupied = tmp_path / "occupied"
    occupied.mkdir()
    (occupied / "keep").write_text("x", encoding="utf-8")
    with pytest.raises(BTSError, match="not empty"):
        relocation.publish(occupied)


def test_relocation_is_hash_seed_independent() -> None:
    program = r'''
import hashlib
from dataclasses import replace
from leitir.bts import BTS, BTSDisposition, MemberEvidence, RequiredFileEvidence, RequiredSymbolEvidence, _digest as bts_digest
from leitir.graph.model import NodeId, NodeKind, NodeOrigin, SourceRef
from leitir.relocate import ContractTest, ModuleMap, SourceFile, relocate_tests
s = b"def f():\n    return 3\n"
n = NodeId(NodeOrigin.DONOR, NodeKind.FUNCTION, "donor.mod", "f", "donor/mod.py:1")
r = SourceRef("o/r", "1"*40, "donor/mod.py", "2"*40, 1, 0, 2, 12)
d = "sha256:" + hashlib.sha256(s[:-1]).hexdigest()
m = MemberEvidence(n, r, d, BTSDisposition.INCLUDE)
b = BTS("leitir-bts-v1", n, (m,), (), (RequiredFileEvidence(r.path,r.blob_sha,d),), (RequiredSymbolEvidence(n,r),), "sha256:"+"0"*64, "sha256:"+"1"*64)
b = replace(b, member_equivalence_digest=bts_digest(b, omit=frozenset({"bts_digest", "member_equivalence_digest"})))
x = relocate_tests(b, module_map=ModuleMap.from_pairs(("donor.mod","transplant.core")), source_files=(SourceFile(r.path,s),), tests=(ContractTest("test_x.py",b"from donor.mod import f\n","donor.tests.test_x"),))
print(x.relocation_digest)
print(hashlib.sha256(x.to_bytes()).hexdigest())
'''
    outputs: list[bytes] = []
    for seed in ("0", "1", "42"):
        environment = os.environ.copy()
        environment["PYTHONHASHSEED"] = seed
        environment["PYTHONPATH"] = "src"
        outputs.append(subprocess.check_output([sys.executable, "-c", program], env=environment))
    assert outputs[0] == outputs[1] == outputs[2]
