"""Opt-in, pinned public-source E2E benchmark for the usage evidence pipeline
(issue #259).

**Owner decision: UNKNOWN.** The issue records that owner-selected public
E2E identities and pinned source revisions are needed before this can run
against the real network; that selection has not been made. Per the sad
path (SP-1), an unselected public identity must never weaken or gate local
completion -- the local-fixture proofs in ``tests/test_usage_cli.py`` and
``tests/test_usage_replay.py`` are independent of this file and do not
require it to run.

This module is therefore structurally wired (opt-in marker, env gate, and
the shape a real run would take) but reports UNKNOWN by skipping until an
owner supplies ``_PUBLIC_E2E_PINS`` (provider distribution name + version,
its PyPI/sdist digest, the consumer repository + pinned commit, and the
requirements.txt pin) -- see the module-level TODO below. Any real network
fetch is deliberately *not* implemented against invented identities: doing
so would fabricate the exact provenance this pipeline exists to verify.

Per the shared brief, any network/opt-in test carries both
``@pytest.mark.live`` and a ``skipif`` gated on ``LEITIR_ENABLE_LIVE_E2E``;
``tests/test_live_marker_inventory.py`` enforces that pairing. The default
(opt-out) run of this file always passes by skipping -- it never fails and
never touches the network.
"""

from __future__ import annotations

import os

import pytest

# TODO(owner): populate once public E2E identities/pins are approved, e.g.
#   {
#       "provider_distribution": "<pypi-name>",
#       "provider_version": "<pinned-version>",
#       "provider_sdist_sha256": "sha256:<64-hex>",
#       "consumer_repo": "<owner/repo>",
#       "consumer_commit": "<40-hex-sha>",
#   }
# Until then this stays None and the test below reports UNKNOWN via skip,
# regardless of LEITIR_ENABLE_LIVE_E2E.
_PUBLIC_E2E_PINS: dict[str, str] | None = None

_REASON = (
    "opt-in pinned public-source usage E2E: owner-selected identities/pins are "
    "UNKNOWN (see issue #259); set LEITIR_ENABLE_LIVE_E2E=1 once _PUBLIC_E2E_PINS "
    "is populated by the owner"
)


@pytest.mark.live
@pytest.mark.skipif(
    os.environ.get("LEITIR_ENABLE_LIVE_E2E") != "1" or _PUBLIC_E2E_PINS is None,
    reason=_REASON,
)
def test_pinned_public_source_usage_e2e() -> None:
    """Verify+replay a real, pinned public provider/consumer pair end-to-end.

    Guarded a second time inside the body: if the module-level skip is ever
    bypassed (e.g. a future edit clears ``_PUBLIC_E2E_PINS`` without wiring
    the fetch/pin logic below), this still refuses to reach the network on
    invented identities rather than silently doing so.
    """

    if _PUBLIC_E2E_PINS is None:  # pragma: no cover - defensive, see skip above
        pytest.skip(_REASON)

    # Intentionally unimplemented: real network fetching, admission, and
    # `leitir usage verify`/`leitir usage replay` wiring against
    # `_PUBLIC_E2E_PINS` belongs here once the owner approves the pins.
    # Nothing above this point performs network I/O.
    raise AssertionError(
        "public E2E pins were populated but the fetch/verify/replay wiring "
        "was not implemented -- this should not be reachable while "
        "_PUBLIC_E2E_PINS stays None"
    )
