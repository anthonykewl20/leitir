# ADR-0038: Release versioning and publication

- Status: Accepted
- Date: 2026-09-05
- Technical story: #332, owner-requested three-digit patch release format

## Decision

Use public `MAJOR.MINOR.PATCH` identifiers with exactly three ASCII patch digits.
Major and minor components have no leading zeros. Substantial capabilities or
compatibility changes increment minor and reset patch during the 0.x series;
corrections increment patch. After patch 999, increment minor and reset patch.
A major increment denotes the next declared major compatibility contract.
Never move versions backwards or reuse an existing release identity.

The literal public identifier lives in `pyproject.toml`. Tags prepend `v`.
Build tools normalize numeric segments under the Python packaging specification:
`0.2.000` becomes `0.2.0` in distribution filenames and metadata. These are one
identity, not separate releases. Runtime presentation pads the installed
three-component final version; pre/dev/local versions keep their original form.
MCP must read that identity instead of carrying a second hardcoded version.

The stdlib release verifier requires exact project/tag agreement, exactly the
normalized wheel and sdist, matching wheel METADATA and sdist PKG-INFO, and the
matching public version in the sdist's project metadata. Missing, duplicate,
mismatched or malformed identity fields reject. Artifact symlinks and unexpected
files reject. Do not rename wheel files to circumvent packaging normalization.

CI builds and tests the distributions. Publication consumes those exact bytes
from a successful push or workflow-dispatch CI run for the exact tagged commit, verifies identity, records
SHA-256 digests, waits for successful provenance attestation, rechecks digests,
and uses `docs/releases/<public-version>.md` from that commit as release notes.
A missing notes document rejects publication. Pull-request runs are ineligible:
GitHub reports their head SHA while the default checkout builds the PR merge
ref. Real CI run31579743105 produced a wheel with three files absent from its
reported head; matching run metadata alone did not establish source identity.
The final release branch therefore receives an actual manually dispatched full
CI run before tagging, or publication uses the successful exact main-push run.
See GitHub's [pull-request event checkout semantics](https://docs.github.com/en/actions/reference/workflows-and-actions/events-that-trigger-workflows#pull_request). Existing containment authority,
review and live-evidence gates remain in force.

## Validation and consequences

Build and install actual wheel and sdist in isolated environments; exercise
installed CLI and upstream materialization. Alter real built archives to prove
wheel/sdist identity rejection. Verify MCP initialization with its actual SDK.
The runtime remains stdlib-only; optional SDKs and build tools remain optional.

Python's normalization is specified in the
[version specification](https://packaging.python.org/en/latest/specifications/version-specifiers/#integer-normalization)
and [wheel format](https://packaging.python.org/en/latest/specifications/binary-distribution-format/).
