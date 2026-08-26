"""Differential evaluation harness (issue #266 E2/E3).

Runs the exit-corpus tasks through three arms -- no retrieval (A), raw
web/GitHub search (B), and leitir (C) -- with everything else held constant,
and reports the delta (C minus B). See ``README.md`` in this directory for
the architecture and the evaluator seam it enforces.

This package is intentionally stdlib-only. It reads (never writes)
``benchmarks/exit-corpus/`` and shells out to the ``leitir`` CLI (``check``)
and to ``pytest`` as external tools instead of importing their internals.
"""

from __future__ import annotations
