"""Evidence-assisted cross-language port: portable contract translation.

ADR-0033 defines the contract this module implements. The hard boundary from
that ADR is normative here: Leitir never performs source-to-source
translation. It extracts donor behaviour (an ADR-0008 ``COMPLETE`` BTS),
expresses a caller-declared **portable subset** of that behaviour's contract
in a non-Python target language, and rejects -- never approximates -- any
case that has no faithful equivalent in the target language's semantics. The
agent writes the implementation; a future containment extension proves it.
This module supplies the deterministic, offline, testable half: portability
classification, translation, and port attribution. It never executes agent
code and never claims a containment proof it did not run.

Only Go is supported as a target language in v1 (see ADR-0033 Decision 4 for
why). A behaviour whose outcome is expressed as a raised Python exception is
never portable to Go's error model and always rejects with
``BTSRejectReason.REJECT_UNSUPPORTED_CONSTRUCT`` -- this is the concrete
instance of the issue's own illustrative example.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import math
import re
from dataclasses import dataclass
from enum import Enum
from itertools import pairwise

from leitir.bts import BTS, BTSResult, BTSStatus, _digest
from leitir.bts_errors import BTSError, BTSEvidence, BTSRejectReason
from leitir.license_policy import (
    DEFAULT_LICENSE_POLICY,
    BundledSource,
    LicensePolicy,
    Obligations,
    RecipientLicensePolicy,
    VerifiedBytes,
    evaluate_license_policy,
    render_attribution,
)

PORTABLE_CONTRACT_SCHEMA_VERSION = "leitir-portable-contract-v1"
TRANSLATED_CONTRACT_SCHEMA_VERSION = "leitir-translated-contract-v1"
PORT_ATTRIBUTION_SCHEMA_VERSION = "leitir-port-attribution-v1"

# ADR-0033 decision: no shared donor lines transfer to a port, so the
# reuse-packet attribution mode from ADR-0011 does not apply verbatim. This
# constant names the mode that does apply: attribution runs from the donor's
# behaviour (the BTS members that were read to author the portable contract)
# rather than from any bundled or shared byte range.
ATTRIBUTION_MODE_BEHAVIORAL_DESCENT = "behavioral_descent"

_CASE_NAME = re.compile(r"[a-z][a-z0-9_]{0,63}\Z")
_SLUG = re.compile(r"[a-z0-9][a-z0-9._/-]{0,127}\Z")
_HEX40 = re.compile(r"[0-9a-f]{40}\Z")
_TREE_HASH = re.compile(r"h1:[A-Za-z0-9+/]{43}=\Z")
_GO_IDENTIFIER = re.compile(r"[A-Z][A-Za-z0-9_]{0,63}\Z")
_INT64_MIN = -(2**63)
_INT64_MAX = 2**63 - 1


def _sha(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _canonical(value: object) -> bytes:
    return (
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False) + "\n"
    ).encode("utf-8", errors="strict")


def _reject(reason: BTSRejectReason, message: str, detail_code: str) -> BTSError:
    return BTSError(reason, BTSEvidence(message=message, detail_code=detail_code), detail_code=detail_code)


class TargetLanguage(str, Enum):  # noqa: UP042 - canonical contract pins str, Enum
    GO = "go"


@dataclass(frozen=True, slots=True, order=True)
class DonorIdentity:
    """Minimal donor identity, duplicated from ``transplant.DonorIdentity``.

    Deliberately not imported from ``leitir.transplant``: that module pulls
    in the containment pipeline (``bts_pipeline`` / ``rerun`` / ``subprocess``)
    at module scope (see ``tests/test_import_purity.py``), which this module's
    own purity depends on staying off of -- ``port_contract`` is exactly the
    deterministic, offline, containment-free half of ADR-0033 and must not
    transitively require a subprocess launcher to import.
    """

    slug: str
    commit_sha: str
    materialized_tree_hash: str
    source: str = "git-commit"

    def __post_init__(self) -> None:
        if _SLUG.fullmatch(self.slug) is None or any(part in {"", ".", ".."} for part in self.slug.split("/")):
            raise ValueError("donor.slug must be a constrained ASCII slug")
        if not isinstance(self.commit_sha, str) or _HEX40.fullmatch(self.commit_sha) is None:
            raise ValueError("donor.commit_sha must be an immutable 40-character SHA")
        if not isinstance(self.materialized_tree_hash, str) or _TREE_HASH.fullmatch(self.materialized_tree_hash) is None:
            raise ValueError("donor.materialized_tree_hash must be a canonical h1 tree hash")
        if self.source != "git-commit":
            raise ValueError("donor.source must be git-commit")




class PortableValueKind(str, Enum):  # noqa: UP042 - canonical contract pins str, Enum
    BOOL = "bool"
    INT = "int"
    FLOAT = "float"
    STRING = "string"
    LIST = "list"


class OutcomeKind(str, Enum):  # noqa: UP042 - canonical contract pins str, Enum
    RETURN = "return"
    RAISES = "raises"


_SCALAR_KINDS = frozenset(
    {PortableValueKind.BOOL, PortableValueKind.INT, PortableValueKind.FLOAT, PortableValueKind.STRING}
)


@dataclass(frozen=True, slots=True)
class PortableValue:
    """A closed, JSON-representable value with a faithful Go equivalent.

    ``LIST`` elements must share exactly one non-list ``PortableValueKind``
    (declared by ``list_element_kind`` even for an empty list); a nested list
    is not part of the v1 portable subset and rejects at construction.
    """

    kind: PortableValueKind
    bool_value: bool | None = None
    int_value: int | None = None
    float_value: float | None = None
    string_value: str | None = None
    list_value: tuple[PortableValue, ...] | None = None
    list_element_kind: PortableValueKind | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.kind, PortableValueKind):
            raise TypeError("kind must be a PortableValueKind")
        slots = {
            PortableValueKind.BOOL: "bool_value",
            PortableValueKind.INT: "int_value",
            PortableValueKind.FLOAT: "float_value",
            PortableValueKind.STRING: "string_value",
            PortableValueKind.LIST: "list_value",
        }
        active = slots[self.kind]
        for kind, name in slots.items():
            value = getattr(self, name)
            if kind is self.kind:
                if value is None:
                    raise ValueError(f"{active} is required for kind={self.kind.value}")
            elif value is not None:
                raise ValueError(f"only {active} may be set for kind={self.kind.value}")
        if self.kind is PortableValueKind.BOOL and not isinstance(self.bool_value, bool):
            raise TypeError("bool_value must be bool")
        if self.kind is PortableValueKind.INT:
            if isinstance(self.int_value, bool) or not isinstance(self.int_value, int):
                raise TypeError("int_value must be int")
            if not (_INT64_MIN <= self.int_value <= _INT64_MAX):
                raise _reject(
                    BTSRejectReason.REJECT_UNSUPPORTED_CONSTRUCT,
                    "int value does not fit a Go int64",
                    "port_contract_int_overflow_go_v1",
                )
        if self.kind is PortableValueKind.FLOAT:
            if isinstance(self.float_value, bool) or not isinstance(self.float_value, float):
                raise TypeError("float_value must be float")
            if not math.isfinite(self.float_value):
                raise _reject(
                    BTSRejectReason.REJECT_UNSUPPORTED_CONSTRUCT,
                    "non-finite float has no deterministic Go literal",
                    "port_contract_nonfinite_float_v1",
                )
        if self.kind is PortableValueKind.STRING:
            if not isinstance(self.string_value, str):
                raise TypeError("string_value must be str")
            try:
                self.string_value.encode("utf-8", errors="strict")
            except UnicodeEncodeError as exc:
                raise ValueError("string_value must be strict UTF-8") from exc
        if self.kind is PortableValueKind.LIST:
            if self.list_element_kind is None:
                raise ValueError("list_element_kind is required for kind=list")
            if not isinstance(self.list_element_kind, PortableValueKind):
                raise TypeError("list_element_kind must be a PortableValueKind")
            if self.list_element_kind not in _SCALAR_KINDS:
                raise _reject(
                    BTSRejectReason.REJECT_UNSUPPORTED_CONSTRUCT,
                    "a nested list has no faithful Go translation in the v1 portable subset",
                    "port_contract_nested_list_v1",
                )
            if not isinstance(self.list_value, tuple) or not all(
                isinstance(item, PortableValue) for item in self.list_value
            ):
                raise TypeError("list_value must be a tuple of PortableValue")
            if any(item.kind is not self.list_element_kind for item in self.list_value):
                raise _reject(
                    BTSRejectReason.REJECT_UNSUPPORTED_CONSTRUCT,
                    "a heterogeneous list has no single Go slice element type",
                    "port_contract_heterogeneous_list_v1",
                )

    def _payload(self) -> dict[str, object]:
        return {
            "bool_value": self.bool_value,
            "float_value": self.float_value,
            "int_value": self.int_value,
            "kind": self.kind.value,
            "list_element_kind": None if self.list_element_kind is None else self.list_element_kind.value,
            "list_value": None if self.list_value is None else [item._payload() for item in self.list_value],
            "string_value": self.string_value,
        }


@dataclass(frozen=True, slots=True)
class PortableCase:
    """One declarative, evidence-bound behavioural assertion.

    ``outcome=RAISES`` is always rejected by :func:`classify_case` -- it is
    retained as a closed tag (rather than simply omitted from the schema) so
    that a caller-declared exceptional case produces a specific, actionable
    rejection instead of a schema-validation error that looks unrelated to
    the real, ADR-0033-documented reason.
    """

    name: str
    args: tuple[PortableValue, ...]
    outcome: OutcomeKind
    expected: PortableValue | None = None
    donor_exception_type: str | None = None

    def __post_init__(self) -> None:
        if _CASE_NAME.fullmatch(self.name) is None:
            raise ValueError("case name must match [a-z][a-z0-9_]{0,63}")
        if not isinstance(self.args, tuple) or not all(isinstance(item, PortableValue) for item in self.args):
            raise TypeError("args must be a tuple of PortableValue")
        if not isinstance(self.outcome, OutcomeKind):
            raise TypeError("outcome must be an OutcomeKind")
        if self.outcome is OutcomeKind.RETURN:
            if self.expected is None or self.donor_exception_type is not None:
                raise ValueError("a return case requires expected and forbids donor_exception_type")
        else:
            if self.expected is not None or not self.donor_exception_type:
                raise ValueError("a raises case forbids expected and requires donor_exception_type")

    def _payload(self) -> dict[str, object]:
        return {
            "args": [item._payload() for item in self.args],
            "donor_exception_type": self.donor_exception_type,
            "expected": None if self.expected is None else self.expected._payload(),
            "name": self.name,
            "outcome": self.outcome.value,
        }


@dataclass(frozen=True, slots=True)
class PortableContractSuite:
    """A caller-declared, content-addressed portable contract for one donor function."""

    schema_version: str
    donor: DonorIdentity
    bts_digest: str
    function_qualified_name: str
    target_function_name: str
    parameter_kinds: tuple[PortableValueKind, ...]
    return_kind: PortableValueKind | None
    cases: tuple[PortableCase, ...]
    suite_digest: str

    def __post_init__(self) -> None:
        if self.schema_version != PORTABLE_CONTRACT_SCHEMA_VERSION:
            raise ValueError("unsupported portable contract schema")
        if not isinstance(self.donor, DonorIdentity):
            raise TypeError("donor must be a DonorIdentity")
        if not re.fullmatch(r"sha256:[0-9a-f]{64}", self.bts_digest):
            raise ValueError("bts_digest must be a lowercase sha256 digest")
        if not self.function_qualified_name:
            raise ValueError("function_qualified_name must be non-empty")
        if _GO_IDENTIFIER.fullmatch(self.target_function_name) is None:
            raise ValueError("target_function_name must be an exported Go identifier")
        if not isinstance(self.parameter_kinds, tuple) or not all(
            isinstance(item, PortableValueKind) for item in self.parameter_kinds
        ):
            raise TypeError("parameter_kinds must be a tuple of PortableValueKind")
        if self.return_kind is not None and not isinstance(self.return_kind, PortableValueKind):
            raise TypeError("return_kind must be a PortableValueKind or None")
        if not isinstance(self.cases, tuple) or not self.cases or not all(
            isinstance(item, PortableCase) for item in self.cases
        ):
            raise ValueError("cases must be a non-empty tuple of PortableCase")
        ordered = tuple(sorted(self.cases, key=lambda item: item.name))
        for left, right in pairwise(ordered):
            if left.name == right.name:
                raise ValueError("duplicate case name")
        for case in ordered:
            if len(case.args) != len(self.parameter_kinds) or any(
                arg.kind is not kind for arg, kind in zip(case.args, self.parameter_kinds, strict=True)
            ):
                raise ValueError(f"case {case.name!r} arguments do not match parameter_kinds")
            if case.outcome is OutcomeKind.RETURN:
                if self.return_kind is None or case.expected is None or case.expected.kind is not self.return_kind:
                    raise ValueError(f"case {case.name!r} expected value does not match return_kind")
        object.__setattr__(self, "cases", ordered)
        expected_digest = _sha(_canonical(self._payload(include_digest=False)))
        if self.suite_digest != expected_digest:
            raise ValueError("suite_digest does not match canonical contents")

    def _payload(self, *, include_digest: bool = True) -> dict[str, object]:
        payload: dict[str, object] = {
            "bts_digest": self.bts_digest,
            "cases": [item._payload() for item in self.cases],
            "donor": {
                "commit_sha": self.donor.commit_sha,
                "materialized_tree_hash": self.donor.materialized_tree_hash,
                "slug": self.donor.slug,
                "source": self.donor.source,
            },
            "function_qualified_name": self.function_qualified_name,
            "parameter_kinds": [item.value for item in self.parameter_kinds],
            "return_kind": None if self.return_kind is None else self.return_kind.value,
            "schema_version": self.schema_version,
            "target_function_name": self.target_function_name,
        }
        if include_digest:
            payload["suite_digest"] = self.suite_digest
        return payload

    def to_bytes(self) -> bytes:
        return _canonical(self._payload())


def _value_from_json(value: object) -> PortableValue:
    if not isinstance(value, dict):
        raise ValueError("portable value must be an object")
    required = {"kind", "bool_value", "int_value", "float_value", "string_value", "list_value", "list_element_kind"}
    if set(value) != required:
        raise ValueError("portable value has invalid fields")
    kind = PortableValueKind(value["kind"]) if isinstance(value["kind"], str) else None
    if kind is None:
        raise ValueError("portable value kind must be a string")
    list_value = value["list_value"]
    list_kind = value["list_element_kind"]
    return PortableValue(
        kind,
        bool_value=value["bool_value"],
        int_value=value["int_value"],
        float_value=value["float_value"],
        string_value=value["string_value"],
        list_value=None if list_value is None else tuple(_value_from_json(item) for item in list_value),
        list_element_kind=None if list_kind is None else PortableValueKind(list_kind),
    )


def _case_from_json(value: object) -> PortableCase:
    if not isinstance(value, dict) or set(value) != {"name", "args", "outcome", "expected", "donor_exception_type"}:
        raise ValueError("portable case has invalid fields")
    args = value["args"]
    if not isinstance(args, list):
        raise ValueError("case args must be a list")
    expected = value["expected"]
    donor_exception_type = value["donor_exception_type"]
    if donor_exception_type is not None and not isinstance(donor_exception_type, str):
        raise ValueError("donor_exception_type must be a string")
    name = value["name"]
    if not isinstance(name, str):
        raise ValueError("case name must be a string")
    return PortableCase(
        name,
        tuple(_value_from_json(item) for item in args),
        OutcomeKind(value["outcome"]),
        None if expected is None else _value_from_json(expected),
        donor_exception_type,
    )


def load_portable_contract_suite(data: str | bytes) -> PortableContractSuite:
    """Parse and fully validate a portable contract suite from canonical JSON."""

    def reject_duplicates(pairs: list[tuple[str, object]]) -> dict[str, object]:
        seen: dict[str, object] = {}
        for key, value in pairs:
            if key in seen:
                raise ValueError(f"duplicate JSON key: {key}")
            seen[key] = value
        return seen

    try:
        decoded = json.loads(data, object_pairs_hook=reject_duplicates)
    except (json.JSONDecodeError, TypeError) as exc:
        raise ValueError("invalid portable contract JSON") from exc
    required = {
        "schema_version", "donor", "bts_digest", "function_qualified_name", "target_function_name",
        "parameter_kinds", "return_kind", "cases", "suite_digest",
    }
    if not isinstance(decoded, dict) or set(decoded) != required:
        raise ValueError("portable contract suite has invalid fields")
    donor_value = decoded["donor"]
    if not isinstance(donor_value, dict) or set(donor_value) != {"slug", "commit_sha", "materialized_tree_hash", "source"}:
        raise ValueError("donor identity has invalid fields")
    donor = DonorIdentity(
        donor_value["slug"], donor_value["commit_sha"], donor_value["materialized_tree_hash"], donor_value["source"]
    )
    parameter_kinds = decoded["parameter_kinds"]
    if not isinstance(parameter_kinds, list):
        raise ValueError("parameter_kinds must be a list")
    return_kind = decoded["return_kind"]
    cases = decoded["cases"]
    if not isinstance(cases, list):
        raise ValueError("cases must be a list")
    return PortableContractSuite(
        decoded["schema_version"],
        donor,
        decoded["bts_digest"],
        decoded["function_qualified_name"],
        decoded["target_function_name"],
        tuple(PortableValueKind(item) for item in parameter_kinds),
        None if return_kind is None else PortableValueKind(return_kind),
        tuple(_case_from_json(item) for item in cases),
        decoded["suite_digest"],
    )


@dataclass(frozen=True, slots=True)
class TranslatedContract:
    """A deterministically rendered, target-language contract test file."""

    schema_version: str
    target_language: TargetLanguage
    donor: DonorIdentity
    bts_digest: str
    suite_digest: str
    filename: str
    source_bytes: bytes
    source_sha256: str
    contract_digest: str


def _validated_bts(result: BTSResult) -> BTS:
    """Independently re-derive and check BTS identity; never trust caller digests.

    Mirrors ``transplant._validated_bts`` (ADR-0011 packet boundary) so the
    same COMPLETE-only, digest-re-derived admission gate applies before any
    donor behaviour is used to author a port. Not imported from
    ``transplant`` to keep this module's admission gate independently
    auditable, matching this codebase's existing convention of small
    per-module boundary re-derivation (see also ``bts_cli.py``,
    ``pipeline_cli.py``).
    """

    if not isinstance(result, BTSResult):
        raise TypeError("bts result must be a BTSResult")
    if result.status is not BTSStatus.COMPLETE or result.report.status is not BTSStatus.COMPLETE or result.bts is None:
        raise _reject(
            BTSRejectReason.REJECT_HARD_GATE_FAILED,
            "only a COMPLETE BTS may be ported",
            "port_contract_non_complete_bts_v1",
        )
    artifact = result.bts
    result.report.from_json(result.report.to_bytes())
    equivalence = _digest(artifact, omit=frozenset({"bts_digest", "member_equivalence_digest"}))
    primary = _digest((result.report, artifact), omit=frozenset({"analysis_digest", "bts_digest", "member_equivalence_digest"}))
    if artifact.member_equivalence_digest != equivalence or artifact.bts_digest != primary:
        raise _reject(
            BTSRejectReason.REJECT_PROVENANCE_MISMATCH,
            "BTS identity does not match its canonical records",
            "port_contract_bts_digest_v1",
        )
    return artifact


def _go_type(kind: PortableValueKind, element_kind: PortableValueKind | None = None) -> str:
    if kind is PortableValueKind.BOOL:
        return "bool"
    if kind is PortableValueKind.INT:
        return "int64"
    if kind is PortableValueKind.FLOAT:
        return "float64"
    if kind is PortableValueKind.STRING:
        return "string"
    assert kind is PortableValueKind.LIST and element_kind is not None
    return f"[]{_go_type(element_kind)}"


def _go_string_literal(value: str) -> str:
    out = ['"']
    for ch in value:
        if ch == "\\":
            out.append("\\\\")
        elif ch == '"':
            out.append('\\"')
        elif ch == "\n":
            out.append("\\n")
        elif ch == "\t":
            out.append("\\t")
        elif ch == "\r":
            out.append("\\r")
        elif ord(ch) < 0x20:
            out.append(f"\\u{ord(ch):04x}")
        else:
            out.append(ch)
    out.append('"')
    return "".join(out)


def _go_literal(value: PortableValue) -> str:
    if value.kind is PortableValueKind.BOOL:
        return "true" if value.bool_value else "false"
    if value.kind is PortableValueKind.INT:
        assert value.int_value is not None
        return repr(value.int_value)
    if value.kind is PortableValueKind.FLOAT:
        assert value.float_value is not None
        return repr(value.float_value)
    if value.kind is PortableValueKind.STRING:
        assert value.string_value is not None
        return _go_string_literal(value.string_value)
    assert value.kind is PortableValueKind.LIST and value.list_value is not None and value.list_element_kind is not None
    element_type = _go_type(value.list_element_kind)
    rendered = ", ".join(_go_literal(item) for item in value.list_value)
    return f"[]{element_type}{{{rendered}}}"


def _go_case_identifier(name: str) -> str:
    return "".join(part.capitalize() for part in name.split("_"))


def classify_case(case: PortableCase, target: TargetLanguage) -> None:
    """Raise a typed, actionable rejection for a case with no faithful equivalent.

    A raised-exception outcome is the concrete instance of the issue's own
    illustrative example: Go's error-return model has no faithful equivalent
    to a Python exception *type* (identity, hierarchy, and attached
    ``args``); approximating it as ``err != nil`` silently discards which
    exception was raised, which is exactly the "weaker assertion" this ADR
    forbids. It always rejects rather than degrading to a presence check.
    """

    if target is not TargetLanguage.GO:
        raise _reject(
            BTSRejectReason.REJECT_UNSUPPORTED_EXTRA,
            f"unsupported port target language: {target.value}",
            "port_contract_target_language_unsupported_v1",
        )
    if case.outcome is OutcomeKind.RAISES:
        raise _reject(
            BTSRejectReason.REJECT_UNSUPPORTED_CONSTRUCT,
            f"case {case.name!r} asserts donor exception type {case.donor_exception_type!r}, "
            "which has no faithful equivalent in Go's error-return model",
            "port_contract_raises_not_portable_go_v1",
        )


def translate_contract(bts_result: BTSResult, suite: PortableContractSuite, target: TargetLanguage) -> TranslatedContract:
    """Translate a portable contract suite into a deterministic target-language test file.

    Rejects the entire suite -- never a silently narrowed subset -- on the
    first case with no faithful target-language equivalent, in caller-stable
    case-name order. The BTS is independently re-validated as COMPLETE and
    cross-checked against ``suite.bts_digest`` before any translation.
    """

    artifact = _validated_bts(bts_result)
    if suite.bts_digest != artifact.bts_digest:
        raise _reject(
            BTSRejectReason.REJECT_PROVENANCE_MISMATCH,
            "portable contract suite does not bind the supplied BTS",
            "port_contract_bts_digest_mismatch_v1",
        )
    for case in suite.cases:
        classify_case(case, target)

    lines = [
        "// Code generated by leitir bts-port-contract from a translated behavioral",
        "// contract (ADR-0033). DO NOT EDIT BY HAND.",
        "//",
        "// The implementation under test is agent-written and is not part of this",
        "// file or any Leitir-published artifact; see attribution.json for the",
        "// donor provenance this contract was translated from.",
        "//",
        f"// donor: {suite.donor.slug}@{suite.donor.commit_sha}",
        f"// donor function: {suite.function_qualified_name}",
        f"// bts_digest: {artifact.bts_digest}",
        f"// suite_digest: {suite.suite_digest}",
        "",
        "package donorport",
        "",
        "import (",
        '\t"reflect"',
        '\t"testing"',
        ")",
        "",
    ]
    for case in suite.cases:
        args = ", ".join(_go_literal(arg) for arg in case.args)
        assert case.expected is not None
        lines.extend(
            [
                f"func TestPortableContract_{_go_case_identifier(case.name)}(t *testing.T) {{",
                f"\tgot := {suite.target_function_name}({args})",
                f"\twant := {_go_literal(case.expected)}",
                "\tif !reflect.DeepEqual(got, want) {",
                f'\t\tt.Fatalf("case %q: got %#v want %#v", {_go_string_literal(case.name)}, got, want)',
                "\t}",
                "}",
                "",
            ]
        )
    source_bytes = ("\n".join(lines).rstrip("\n") + "\n").encode("utf-8")
    source_sha256 = _sha(source_bytes)
    filename = f"{suite.target_function_name.lower()}_contract_test.go"
    payload = {
        "bts_digest": artifact.bts_digest,
        "donor": {
            "commit_sha": suite.donor.commit_sha,
            "materialized_tree_hash": suite.donor.materialized_tree_hash,
            "slug": suite.donor.slug,
            "source": suite.donor.source,
        },
        "filename": filename,
        "schema_version": TRANSLATED_CONTRACT_SCHEMA_VERSION,
        "source_sha256": source_sha256,
        "suite_digest": suite.suite_digest,
        "target_language": target.value,
    }
    contract_digest = _sha(_canonical(payload))
    return TranslatedContract(
        TRANSLATED_CONTRACT_SCHEMA_VERSION,
        target,
        suite.donor,
        artifact.bts_digest,
        suite.suite_digest,
        filename,
        source_bytes,
        source_sha256,
        contract_digest,
    )


@dataclass(frozen=True, slots=True)
class PortAttributionEvidence:
    """Attribution for a port: behavioural descent, not shared-line reuse.

    ADR-0033 Decision 2: because a port shares zero bytes with the donor,
    ADR-0011's line-based reuse-packet attribution mode does not apply --
    there are no donor lines to bundle or account for. What *does* apply
    unchanged is donor license admissibility: :func:`evaluate_license_policy`
    runs, unmodified, over the donor's own BTS member source bytes (the
    behaviour actually read to author the portable contract), and this
    function fails closed exactly as packet-building does today if that
    donor code's license is missing, unresolved, or recipient-incompatible.
    """

    schema_version: str
    donor: DonorIdentity
    bts_digest: str
    suite_digest: str
    target_language: TargetLanguage
    translated_contract_digest: str
    attribution_mode: str
    obligations: Obligations
    attribution_md_sha256: str
    evidence_digest: str


def build_port_attribution(
    bts_result: BTSResult,
    suite: PortableContractSuite,
    translated: TranslatedContract,
    donor_sources: tuple[BundledSource, ...],
    recipient_policy: RecipientLicensePolicy,
    license_policy: LicensePolicy = DEFAULT_LICENSE_POLICY,
) -> PortAttributionEvidence:
    """Build port attribution evidence, or raise the same fail-closed license rejection a reuse packet would."""

    artifact = _validated_bts(bts_result)
    if suite.bts_digest != artifact.bts_digest or translated.bts_digest != artifact.bts_digest:
        raise _reject(
            BTSRejectReason.REJECT_PROVENANCE_MISMATCH,
            "attribution inputs do not bind the same BTS",
            "port_contract_attribution_bts_digest_v1",
        )
    if translated.suite_digest != suite.suite_digest:
        raise _reject(
            BTSRejectReason.REJECT_PROVENANCE_MISMATCH,
            "translated contract does not bind the supplied portable contract suite",
            "port_contract_attribution_suite_digest_v1",
        )
    decision = evaluate_license_policy(donor_sources, recipient_policy, license_policy)
    if not decision.accepted:
        assert decision.reason is not None
        raise BTSError(
            decision.reason,
            BTSEvidence(message=decision.detail, detail_code=decision.detail_code),
            detail_code=decision.detail_code,
        )
    assert decision.obligations is not None
    attribution_md_sha256 = _sha(render_attribution(decision.obligations))
    payload = {
        "attribution_md_sha256": attribution_md_sha256,
        "attribution_mode": ATTRIBUTION_MODE_BEHAVIORAL_DESCENT,
        "bts_digest": artifact.bts_digest,
        "donor": {
            "commit_sha": suite.donor.commit_sha,
            "materialized_tree_hash": suite.donor.materialized_tree_hash,
            "slug": suite.donor.slug,
            "source": suite.donor.source,
        },
        "obligations_digest": decision.obligations.obligations_digest,
        "schema_version": PORT_ATTRIBUTION_SCHEMA_VERSION,
        "suite_digest": suite.suite_digest,
        "target_language": translated.target_language.value,
        "translated_contract_digest": translated.contract_digest,
    }
    evidence_digest = _sha(_canonical(payload))
    return PortAttributionEvidence(
        PORT_ATTRIBUTION_SCHEMA_VERSION,
        suite.donor,
        artifact.bts_digest,
        suite.suite_digest,
        translated.target_language,
        translated.contract_digest,
        ATTRIBUTION_MODE_BEHAVIORAL_DESCENT,
        decision.obligations,
        attribution_md_sha256,
        evidence_digest,
    )


DONOR_SOURCES_SCHEMA_VERSION = "leitir-port-donor-sources-v1"


def _bytes_field(value: object, name: str) -> bytes:
    if not isinstance(value, str):
        raise ValueError(f"{name} must be a base64 string")
    try:
        return base64.b64decode(value, validate=True)
    except (ValueError, binascii.Error) as exc:
        raise ValueError(f"{name} is not valid base64") from exc


def _verified_bytes_from_json(value: object) -> VerifiedBytesInput:
    if not isinstance(value, dict) or set(value) != {"path", "content_base64", "package_scope"}:
        raise ValueError("verified file entry has invalid fields")
    return VerifiedBytesInput(value["path"], _bytes_field(value["content_base64"], "content_base64"), value["package_scope"])


@dataclass(frozen=True, slots=True)
class VerifiedBytesInput:
    path: str
    content: bytes
    package_scope: str


def load_donor_sources(data: str | bytes) -> tuple[BundledSource, ...]:
    """Load an offline-supplied donor bundled-source manifest for license evaluation.

    This manifest never carries donor bytes into a port artifact; it exists
    only so :func:`build_port_attribution` can run the same
    ``evaluate_license_policy`` the reuse-packet path uses, over the donor's
    actual source bytes, without this module depending on corpus loading.
    """

    def reject_duplicates(pairs: list[tuple[str, object]]) -> dict[str, object]:
        seen: dict[str, object] = {}
        for key, value in pairs:
            if key in seen:
                raise ValueError(f"duplicate JSON key: {key}")
            seen[key] = value
        return seen

    try:
        decoded = json.loads(data, object_pairs_hook=reject_duplicates)
    except (json.JSONDecodeError, TypeError) as exc:
        raise ValueError("invalid donor sources JSON") from exc
    if not isinstance(decoded, dict) or set(decoded) != {"schema_version", "sources"}:
        raise ValueError("donor sources manifest has invalid fields")
    if decoded["schema_version"] != DONOR_SOURCES_SCHEMA_VERSION:
        raise ValueError("unsupported donor sources schema")
    sources = decoded["sources"]
    if not isinstance(sources, list) or not sources:
        raise ValueError("donor sources manifest must declare at least one source")
    built: list[BundledSource] = []
    for item in sources:
        if not isinstance(item, dict) or set(item) != {
            "source_record_id", "packet_path", "source_path", "source_bytes_base64",
            "package_scope", "verified_files", "contributing_source_record_ids", "modified_from_sha256",
        }:
            raise ValueError("donor source entry has invalid fields")
        verified_files = item["verified_files"]
        if not isinstance(verified_files, list):
            raise ValueError("verified_files must be a list")
        contributing = item["contributing_source_record_ids"]
        if not isinstance(contributing, list):
            raise ValueError("contributing_source_record_ids must be a list")
        parsed = tuple(_verified_bytes_from_json(entry) for entry in verified_files)
        built.append(
            BundledSource.create(
                source_record_id=item["source_record_id"],
                packet_path=item["packet_path"],
                source_path=item["source_path"],
                source_bytes=_bytes_field(item["source_bytes_base64"], "source_bytes_base64"),
                verified_files=tuple(VerifiedBytes.create(entry.path, entry.content, entry.package_scope) for entry in parsed),
                package_scope=item["package_scope"],
                contributing_source_record_ids=tuple(contributing),
                modified_from_sha256=item["modified_from_sha256"],
            )
        )
    return tuple(built)


def load_recipient_license_policy(data: str | bytes) -> RecipientLicensePolicy:
    """Load a recipient license policy from its plain (undigested) declaration JSON."""

    def reject_duplicates(pairs: list[tuple[str, object]]) -> dict[str, object]:
        seen: dict[str, object] = {}
        for key, value in pairs:
            if key in seen:
                raise ValueError(f"duplicate JSON key: {key}")
            seen[key] = value
        return seen

    try:
        decoded = json.loads(data, object_pairs_hook=reject_duplicates)
    except (json.JSONDecodeError, TypeError) as exc:
        raise ValueError("invalid recipient license policy JSON") from exc
    required = {"policy_id", "policy_version", "use_category", "allowed_spdx_expressions", "prohibited_spdx_expressions"}
    if not isinstance(decoded, dict) or set(decoded) != required:
        raise ValueError("recipient license policy has invalid fields")
    allowed = decoded["allowed_spdx_expressions"]
    prohibited = decoded["prohibited_spdx_expressions"]
    if not isinstance(allowed, list) or not isinstance(prohibited, list):
        raise ValueError("allowed/prohibited SPDX expressions must be lists")
    return RecipientLicensePolicy.create(
        policy_id=decoded["policy_id"],
        policy_version=decoded["policy_version"],
        use_category=decoded["use_category"],
        allowed_spdx_expressions=tuple(allowed),
        prohibited_spdx_expressions=tuple(prohibited),
    )


__all__ = [
    "ATTRIBUTION_MODE_BEHAVIORAL_DESCENT",
    "DONOR_SOURCES_SCHEMA_VERSION",
    "PORTABLE_CONTRACT_SCHEMA_VERSION",
    "PORT_ATTRIBUTION_SCHEMA_VERSION",
    "TRANSLATED_CONTRACT_SCHEMA_VERSION",
    "DonorIdentity",
    "OutcomeKind",
    "PortAttributionEvidence",
    "PortableCase",
    "PortableContractSuite",
    "PortableValue",
    "PortableValueKind",
    "TargetLanguage",
    "TranslatedContract",
    "build_port_attribution",
    "classify_case",
    "load_donor_sources",
    "load_portable_contract_suite",
    "load_recipient_license_policy",
    "translate_contract",
]
