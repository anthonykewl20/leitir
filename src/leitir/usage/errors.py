"""Typed, fail-closed error hierarchy for the usage evidence/replay contract.

Every rejection raised anywhere in ``leitir.usage`` is one of the three
concrete subclasses below, chosen by *why* the input was rejected:

- ``UsageMalformedError`` -- the payload is structurally broken: an unknown
  or missing field, a wrong JSON type, an invalid digest/enum literal, or an
  out-of-order span. Raised before any digest comparison is attempted.
- ``UsageUnsupportedError`` -- the payload is well-formed but declares a
  schema/parser version, or exceeds a bound, this build of the contract does
  not support.
- ``UsageTamperError`` -- the payload is well-formed and declares a
  supported version, but a recorded digest or byte sequence does not match
  either (a) the report's own self-consistency digest, or (b) the bytes
  actually read from the fixture corpus during replay.

All three carry ``.to_json()`` for machine-readable reporting, following the
pattern in ``leitir.bts_errors.BTSError`` adapted to this package's evidence
shape (a dict, not a pre-serialized string, per the usage-pipeline brief).
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class UsageErrorEvidence:
    """Human-readable, machine-parseable detail for a rejected usage operation."""

    message: str
    stage: str
    field: str | None = None
    expected: str | None = None
    actual: str | None = None


class UsageError(Exception):
    """Base class for every rejected usage evidence/replay operation."""

    kind: str = "usage_error"

    def __init__(self, evidence: UsageErrorEvidence) -> None:
        if not isinstance(evidence, UsageErrorEvidence):
            raise TypeError("evidence must be a UsageErrorEvidence")
        super().__init__(evidence.message)
        self.evidence = evidence

    def to_json(self) -> dict[str, object]:
        """Return the machine-readable evidence dict for this error."""

        return {
            "kind": self.kind,
            "message": self.evidence.message,
            "stage": self.evidence.stage,
            "field": self.evidence.field,
            "expected": self.evidence.expected,
            "actual": self.evidence.actual,
        }


class UsageMalformedError(UsageError):
    """The payload is structurally invalid (unknown/missing field, bad type)."""

    kind = "usage_malformed"


class UsageUnsupportedError(UsageError):
    """The payload is well-formed but declares an unsupported version or bound."""

    kind = "usage_unsupported"


class UsageTamperError(UsageError):
    """A recorded digest or byte sequence does not match what it must match."""

    kind = "usage_tamper"
