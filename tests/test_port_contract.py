"""Unit tests for the deterministic, offline half of ADR-0033's cross-language port.

These are internal tests around pure logic (portability classification and
deterministic Go rendering) that is not practical to exercise fully through
the public CLI alone; ``tests/test_port_contract_cli.py`` carries the
user-level intent tests through ``leitir bts-port-contract`` per
``docs/testing.md``.
"""

from __future__ import annotations

import hashlib

import pytest

from leitir.bts_errors import BTSError, BTSRejectReason
from leitir.port_contract import (
    DonorIdentity,
    OutcomeKind,
    PortableCase,
    PortableContractSuite,
    PortableValue,
    PortableValueKind,
    TargetLanguage,
    _canonical,
    _go_case_identifier,
    _validate_go_identifier_namespace,
    classify_case,
)

_SHA = "a" * 40
_TREE_HASH = "h1:" + "A" * 43 + "="
_DONOR = DonorIdentity("owner/donor", _SHA, _TREE_HASH, "git-commit")
_BTS_DIGEST = "sha256:" + "b" * 64


def _suite(
    cases: tuple[PortableCase, ...],
    *,
    return_kind: PortableValueKind | None = PortableValueKind.STRING,
    target_function_name: str = "Fn",
) -> PortableContractSuite:
    ordered_cases = tuple(sorted(cases, key=lambda item: item.name))
    payload = {
        "bts_digest": _BTS_DIGEST,
        "cases": [item._payload() for item in ordered_cases],
        "donor": {
            "commit_sha": _DONOR.commit_sha,
            "materialized_tree_hash": _DONOR.materialized_tree_hash,
            "slug": _DONOR.slug,
            "source": _DONOR.source,
        },
        "function_qualified_name": "pkg.mod.fn",
        "parameter_kinds": ["string"],
        "return_kind": None if return_kind is None else return_kind.value,
        "schema_version": "leitir-portable-contract-v1",
        "target_function_name": target_function_name,
    }
    digest = "sha256:" + hashlib.sha256(_canonical(payload)).hexdigest()
    return PortableContractSuite(
        payload["schema_version"], _DONOR, payload["bts_digest"], payload["function_qualified_name"],
        target_function_name, (PortableValueKind.STRING,), return_kind, ordered_cases, digest,
    )


def test_portable_value_rejects_int_outside_go_int64_range() -> None:
    with pytest.raises(BTSError) as caught:
        PortableValue(PortableValueKind.INT, int_value=2**63)
    assert caught.value.reason is BTSRejectReason.REJECT_UNSUPPORTED_CONSTRUCT
    assert caught.value.evidence.detail_code == "port_contract_int_overflow_go_v1"


def test_portable_value_rejects_nonfinite_float() -> None:
    with pytest.raises(BTSError) as caught:
        PortableValue(PortableValueKind.FLOAT, float_value=float("nan"))
    assert caught.value.evidence.detail_code == "port_contract_nonfinite_float_v1"


def test_portable_value_rejects_heterogeneous_list() -> None:
    with pytest.raises(BTSError) as caught:
        PortableValue(
            PortableValueKind.LIST,
            list_value=(PortableValue(PortableValueKind.INT, int_value=1), PortableValue(PortableValueKind.STRING, string_value="x")),
            list_element_kind=PortableValueKind.INT,
        )
    assert caught.value.evidence.detail_code == "port_contract_heterogeneous_list_v1"


def test_portable_value_rejects_nested_list() -> None:
    inner = PortableValue(PortableValueKind.LIST, list_value=(), list_element_kind=PortableValueKind.INT)
    with pytest.raises(BTSError) as caught:
        PortableValue(PortableValueKind.LIST, list_value=(inner,), list_element_kind=PortableValueKind.LIST)
    assert caught.value.evidence.detail_code == "port_contract_nested_list_v1"


def test_classify_case_rejects_raises_never_approximates() -> None:
    """The issue's own illustrative example: a Python exception has no faithful Go equivalent."""

    case = PortableCase(
        "boom",
        (PortableValue(PortableValueKind.STRING, string_value="x"),),
        OutcomeKind.RAISES,
        donor_exception_type="ValueError",
    )
    with pytest.raises(BTSError) as caught:
        classify_case(case, TargetLanguage.GO)
    assert caught.value.reason is BTSRejectReason.REJECT_UNSUPPORTED_CONSTRUCT
    assert caught.value.evidence.detail_code == "port_contract_raises_not_portable_go_v1"
    # The rejection is typed and specific, not a generic failure: it names
    # the donor exception type so the rejection is actionable.
    assert "ValueError" in caught.value.evidence.message


def test_portable_contract_suite_rejects_tampered_digest() -> None:
    case = PortableCase(
        "a",
        (PortableValue(PortableValueKind.STRING, string_value="x"),),
        OutcomeKind.RETURN,
        expected=PortableValue(PortableValueKind.STRING, string_value="x"),
    )
    with pytest.raises(ValueError, match="suite_digest"):
        PortableContractSuite(
            "leitir-portable-contract-v1", _DONOR, _BTS_DIGEST, "pkg.mod.fn", "Fn",
            (PortableValueKind.STRING,), PortableValueKind.STRING, (case,), "sha256:" + "0" * 64,
        )


def test_portable_contract_suite_rejects_duplicate_case_names() -> None:
    case_a = PortableCase(
        "dup", (PortableValue(PortableValueKind.STRING, string_value="x"),), OutcomeKind.RETURN,
        expected=PortableValue(PortableValueKind.STRING, string_value="x"),
    )
    case_b = PortableCase(
        "dup", (PortableValue(PortableValueKind.STRING, string_value="y"),), OutcomeKind.RETURN,
        expected=PortableValue(PortableValueKind.STRING, string_value="y"),
    )
    with pytest.raises(ValueError, match="duplicate case name"):
        _suite((case_a, case_b))


def test_go_string_literal_escapes_control_and_special_characters() -> None:
    from leitir.port_contract import _go_string_literal

    assert _go_string_literal('a"b\\c\nd\te') == '"a\\"b\\\\c\\nd\\te"'
    assert _go_string_literal("\x01") == '"\\u0001"'


def test_go_case_identifiers_are_non_injective_by_construction() -> None:
    """Documents the raw collision `_validate_go_identifier_namespace` exists to catch."""

    assert _go_case_identifier("a_b") == _go_case_identifier("a__b") == "AB"


def test_colliding_case_identifiers_reject_instead_of_emitting_a_duplicate_go_func() -> None:
    """reviewer-hy3 P2: two distinct, schema-valid case names that render to the same Go
    identifier must reject, not silently emit a `.go` file with a duplicate declaration."""

    case_a = PortableCase(
        "a_b", (PortableValue(PortableValueKind.STRING, string_value="x"),), OutcomeKind.RETURN,
        expected=PortableValue(PortableValueKind.STRING, string_value="x"),
    )
    case_b = PortableCase(
        "a__b", (PortableValue(PortableValueKind.STRING, string_value="y"),), OutcomeKind.RETURN,
        expected=PortableValue(PortableValueKind.STRING, string_value="y"),
    )
    suite = _suite((case_a, case_b))
    with pytest.raises(BTSError) as caught:
        _validate_go_identifier_namespace(suite)
    assert caught.value.reason is BTSRejectReason.REJECT_UNSUPPORTED_CONSTRUCT
    assert caught.value.evidence.detail_code == "port_contract_case_identifier_collision_v1"


def test_target_function_name_colliding_with_a_generated_test_name_rejects() -> None:
    """reviewer-hy3 P3: `target_function_name` literally equaling a generated
    `TestPortableContract_<Ident>` declaration must reject."""

    case = PortableCase(
        "foo", (PortableValue(PortableValueKind.STRING, string_value="x"),), OutcomeKind.RETURN,
        expected=PortableValue(PortableValueKind.STRING, string_value="x"),
    )
    suite = _suite((case,), target_function_name="TestPortableContract_Foo")
    with pytest.raises(BTSError) as caught:
        _validate_go_identifier_namespace(suite)
    assert caught.value.reason is BTSRejectReason.REJECT_UNSUPPORTED_CONSTRUCT
    assert caught.value.evidence.detail_code == "port_contract_target_function_collision_v1"


def test_non_colliding_suite_passes_identifier_namespace_validation() -> None:
    case_a = PortableCase(
        "identity_one", (PortableValue(PortableValueKind.STRING, string_value="x"),), OutcomeKind.RETURN,
        expected=PortableValue(PortableValueKind.STRING, string_value="x"),
    )
    case_b = PortableCase(
        "identity_two", (PortableValue(PortableValueKind.STRING, string_value="y"),), OutcomeKind.RETURN,
        expected=PortableValue(PortableValueKind.STRING, string_value="y"),
    )
    suite = _suite((case_a, case_b))
    _validate_go_identifier_namespace(suite)  # must not raise
