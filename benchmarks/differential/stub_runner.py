"""Deterministic stub runner.

Used by ``tests/test_differential_eval.py`` so the whole harness is
exercisable offline: no network, no model credential, no paid call. It
returns fixed candidate source keyed only by ``(case_id, arm, attempt)``,
so it is byte-identical across ``PYTHONHASHSEED`` values and across runs.

The stub deliberately encodes a plausible *shape* of outcome across arms
(A never converges, B converges after one repair, C is right first try) so
that the harness's delta computation and repair-loop bookkeeping have
something non-trivial to exercise offline. These are canned strings, not a
claim about what a real model would do -- see ``README.md``.

Real reimplementations, not donor source
-----------------------------------------
The "correct" snippets below are independent, from-scratch reimplementations
of small public algorithms (Luhn checksum, full-jitter backoff, RFC 3986
percent-encoding, average Earth radius constants, RGB-to-hex formatting).
They are not copied from any exit-corpus donor's source, which this harness
never reads (only the donor's pinned identity and authored contract tests
are read -- see ``tasks.py``).
"""

from __future__ import annotations

from dataclasses import dataclass

from .metrics import Measured
from .runner import Arm, GenerationRequest, GenerationResult, RepairSignal

_CORRECT: dict[str, str] = {
    "luhn-checksum": (
        "def checksum(card_number):\n"
        "    digits = [int(d) for d in str(card_number)]\n"
        "    odd_digits = digits[-1::-2]\n"
        "    even_digits = digits[-2::-2]\n"
        "    total = sum(odd_digits)\n"
        "    for d in even_digits:\n"
        "        total += sum(int(x) for x in str(d * 2))\n"
        "    return total % 10\n"
    ),
    "backoff-full-jitter": (
        "import random\n\n\n"
        "def full_jitter(value):\n"
        "    return random.uniform(0, value)\n"
    ),
    "haversine-avg-earth-radius": (
        "from enum import Enum\n\n\n"
        "class Unit(str, Enum):\n"
        "    KILOMETERS = 'km'\n"
        "    METERS = 'm'\n\n\n"
        "_AVG_EARTH_RADIUS_KM = 6371.0088\n\n\n"
        "def get_avg_earth_radius(unit):\n"
        "    if unit == Unit.METERS:\n"
        "        return _AVG_EARTH_RADIUS_KM * 1000\n"
        "    return _AVG_EARTH_RADIUS_KM\n"
    ),
    "url-normalize-fragment": (
        "import re\n"
        "from urllib.parse import quote\n\n\n"
        "_PERCENT_RE = re.compile(r'%[0-9A-Fa-f]{2}')\n"
        "_SAFE = \"!$&'()*+,;=:@/?-._~\"\n\n\n"
        "def normalize_fragment(fragment):\n"
        "    parts = []\n"
        "    last = 0\n"
        "    for m in _PERCENT_RE.finditer(fragment):\n"
        "        parts.append(quote(fragment[last:m.start()], safe=_SAFE))\n"
        "        parts.append(m.group(0))\n"
        "        last = m.end()\n"
        "    parts.append(quote(fragment[last:], safe=_SAFE))\n"
        "    return ''.join(parts)\n"
    ),
    "webcolors-rgb-to-hex": (
        "def rgb_to_hex(triplet):\n"
        "    return '#%02x%02x%02x' % tuple(triplet)\n"
    ),
}

_BUGGY_FIRST_ATTEMPT: dict[str, str] = {
    "luhn-checksum": (
        "def checksum(card_number):\n"
        "    digits = [int(d) for d in str(card_number)]\n"
        "    odd_digits = digits[-1::-2]\n"
        "    even_digits = digits[-2::-2]\n"
        "    total = sum(odd_digits)\n"
        "    for d in even_digits:\n"
        "        total += sum(int(x) for x in str(d * 2))\n"
        "    return total % 10 + 1\n"  # off by one
    ),
    "backoff-full-jitter": (
        "def full_jitter(value):\n"
        "    return value + 1\n"  # ignores the zero case
    ),
    "haversine-avg-earth-radius": (
        "from enum import Enum\n\n\n"
        "class Unit(str, Enum):\n"
        "    KILOMETERS = 'km'\n"
        "    METERS = 'm'\n\n\n"
        "def get_avg_earth_radius(unit):\n"
        "    return 6371.0\n"  # wrong constant, wrong unit handling
    ),
    "url-normalize-fragment": (
        "from urllib.parse import quote\n\n\n"
        "def normalize_fragment(fragment):\n"
        "    return quote(fragment, safe='')\n"  # re-encodes existing %XX
    ),
    "webcolors-rgb-to-hex": (
        "def rgb_to_hex(triplet):\n"
        "    r, g, b = triplet\n"
        "    return '#%02x%02x%02x' % (b, g, r)\n"  # channel-swapped
    ),
}

_BROKEN = "def __unused():\n    raise NotImplementedError('no retrieval context was available')\n"


def _tokens_for(prompt: str) -> Measured[int]:
    # A deterministic, offline stand-in for a real usage.total_tokens value.
    return Measured(len(prompt.split()))


@dataclass(frozen=True)
class DeterministicStubRunner:
    """Offline runner. Arm A never converges; B converges after one repair; C is right first try."""

    def generate(self, request: GenerationRequest) -> GenerationResult:
        if request.arm is Arm.NO_RETRIEVAL:
            code = _BROKEN
        elif request.arm is Arm.RAW_SEARCH:
            code = _BUGGY_FIRST_ATTEMPT.get(request.task_id, _BROKEN)
        else:
            code = _CORRECT.get(request.task_id, _BROKEN)
        return GenerationResult(
            code=code, tokens_used=_tokens_for(request.prompt), steps_used=Measured(1)
        )

    def repair(
        self, request: GenerationRequest, prior_code: str, signal: RepairSignal
    ) -> GenerationResult:
        if request.arm is Arm.RAW_SEARCH:
            code = _CORRECT.get(request.task_id, _BROKEN)
        else:
            # Arm A has no retrieval context to draw a fix from; arm C never
            # needs a repair (its first attempt already passes), but if the
            # harness calls repair anyway, keep it deterministic.
            code = prior_code
        return GenerationResult(
            code=code, tokens_used=_tokens_for(request.prompt), steps_used=Measured(1)
        )


__all__ = ["DeterministicStubRunner"]
