# Environment and integrity doctor

- Status: accepted
- Date: 2026-08-06
- Implementation: complete

## Context and Problem Statement

Failures can originate in the Python installation, filesystem capabilities, cached
manifests, integrity verification, credentials, or remote services. Users need one
safe command that separates these causes without exposing credentials or depending
on third-party diagnostic libraries.

## Decision Drivers

- Diagnostics must remain useful offline and in automation.
- One failed probe must not prevent the remaining probes from running.
- Integrity and credential handling must preserve leitir's fail-closed posture.
- Output and exit status must be stable enough for support tooling.

## Decision Outcome

Add `leitir doctor` as a stdlib-only diagnostic runner. Checks return typed records
with pass, warning, error, or skip status. Human output uses color only on a TTY;
JSON output is one schema-versioned object; quiet output contains only non-passing
checks. The worst status determines exit code 0, 1, or 2.

Network probes are anonymous, have a one-second timeout, and can be disabled with
`--no-network`. Credential checks expose variable names and formatting status only.
Cache diagnosis validates manifests using the production reader, while an offline
synthetic tree-hash roundtrip confirms byte tampering is still rejected.

### Consequences

- Support reports can distinguish local, integrity, and network failures quickly.
- New checks can be added as independent functions returning `Check` and registered
  in `collect_checks` without changing either renderer.
- A warning from an environment-dependent capability intentionally makes the command
  exit 1, while skipped checks do not affect the exit status.
