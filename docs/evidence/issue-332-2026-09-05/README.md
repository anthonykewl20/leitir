# Release versioning evidence — 2026-09-05

Actual wheel and sdist builds normalize the requested `0.2.000` to `0.2.0`.
The prior release workflow expected `leitir-0.2.000-*` artifact names and would
reject these legitimate archives. The new verifier accepts the exact normalized
identities, then rejects altered wheel and sdist metadata, malformed/mismatched
tags, and unexpected artifacts. See `tests/test_release_artifacts_live.py` and
`live.txt`: actual builds, isolated installs, CLI versions and live pinned
Packaging materializations. No fake upstream responses are used.

The actual installed MCP2.1.1 SDK client initialized the installed wheel server
as `0.2.000`, listed all five tools and fetched real Packaging context through
`info`. `mcp-handshake.json` records the protocol result.

An isolated clone of this project's actual Git history was tagged locally with
`v0.2.000`. The previous changelog generator omitted it; the revised generator
included the release boundary. `changelog-proof.json` records both executions.
The temporary tag was never published.

These are preparation probes. Final release publication still requires exact
merged-commit CI, provenance attestation and the release notes' remaining gates.
