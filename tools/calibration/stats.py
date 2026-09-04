"""Small, exact-enough statistics used to state calibration claims honestly.

Every estimator here is chosen so the harness can put a *bound* on what it
has not seen, instead of reporting a point estimate as if it were the truth.
"""

from __future__ import annotations

import math
from collections.abc import Sequence


def wilson_interval(successes: int, trials: int, z: float = 1.96) -> tuple[float, float]:
    """Wilson score interval for a binomial proportion (95% at z=1.96).

    Used for the mutation kill rate: with ``k`` killed out of ``n`` sampled
    mutants the *lower* bound is the defensible claim about test adequacy.
    """
    if trials <= 0:
        return (0.0, 1.0)
    if successes < 0 or successes > trials:
        raise ValueError("successes must be within [0, trials]")
    p = successes / trials
    denom = 1.0 + z * z / trials
    centre = (p + z * z / (2.0 * trials)) / denom
    half = (z * math.sqrt(p * (1.0 - p) / trials + z * z / (4.0 * trials * trials))) / denom
    return (max(0.0, centre - half), min(1.0, centre + half))


def rule_of_three(trials: int) -> float:
    """95% upper bound on the per-trial failure probability after zero failures.

    After ``n`` fuzz inputs with no failure, the true failure rate is below
    ``3/n`` with 95% confidence.  This is the honest replacement for "no bugs
    found".
    """
    if trials <= 0:
        return 1.0
    return min(1.0, 3.0 / trials)


def good_turing_unseen_mass(class_counts: Sequence[int], trials: int) -> float:
    """Good-Turing estimate of the probability the *next* input hits an unseen failure class.

    ``class_counts`` are the observed frequencies of each distinct failure
    signature.  The estimate is ``singletons / trials``: the share of failure
    classes seen exactly once predicts how much failure mass is still hidden.
    A value near zero means further random fuzzing of this target is unlikely
    to reveal new classes at the current input distribution.
    """
    if trials <= 0:
        return 1.0
    singletons = sum(1 for count in class_counts if count == 1)
    return min(1.0, singletons / trials)


def median(values: Sequence[float]) -> float:
    if not values:
        raise ValueError("median of empty sequence")
    ordered = sorted(values)
    n = len(ordered)
    mid = n // 2
    if n % 2:
        return float(ordered[mid])
    return (ordered[mid - 1] + ordered[mid]) / 2.0


def mad(values: Sequence[float]) -> float:
    """Median absolute deviation: a robust spread estimate for timing samples."""
    if not values:
        raise ValueError("mad of empty sequence")
    centre = median(values)
    return median([abs(value - centre) for value in values])


def robust_regression(
    baseline: Sequence[float], candidate: Sequence[float], *, ratio_threshold: float = 1.25
) -> tuple[bool, float]:
    """Decide whether ``candidate`` timings regressed against ``baseline``.

    A regression requires both a median ratio above ``ratio_threshold`` and
    the candidate median lying outside the baseline's median + 3*MAD band,
    so a noisy single run cannot flag a regression on its own.
    Returns ``(regressed, ratio)``.
    """
    base_med = median(baseline)
    cand_med = median(candidate)
    if base_med <= 0:
        return (False, float("inf") if cand_med > 0 else 1.0)
    ratio = cand_med / base_med
    band = base_med + 3.0 * mad(baseline)
    return (ratio > ratio_threshold and cand_med > band, ratio)
