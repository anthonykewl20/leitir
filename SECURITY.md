# Security policy

## Reporting a vulnerability

Report vulnerabilities privately through a [GitHub security
advisory](https://github.com/anthonykewl20/leitir/security/advisories/new).

**Do not open a public issue for a suspected vulnerability.** A public report
may expose users before a fix is available.

## Supported versions

| Version | Supported |
|---|---|
| latest | ✓ |
| <latest | ✗ |

## Scope

The following are in scope:

- integrity bypass;
- acceptance of a manifest or tree-hash mismatch;
- path traversal;
- materialization outside the destination;
- unsafe archive handling;
- malicious corpus substitution;
- verification downgrade; and
- secret disclosure.

## Out of scope

The following are outside leitir's security boundary:

- malicious upstream package contents: leitir materializes what registries
  hand it;
- an attacker who already controls the corpus root: corruption detection is
  the boundary, not authenticity; see [ADR-0006](docs/adr/0006-load-time-tree-verification.md);
  and
- bugs in third-party tools that leitir invokes.

## What to include in a report

Please include:

- the leitir version or commit;
- the Python version;
- the operating system;
- the exact command;
- a minimal corpus or source description;
- expected versus actual behavior;
- the full traceback or output; and
- confirmation that sensitive data was removed.

## What NOT to include

Do not include:

- private package URLs;
- credentials;
- proprietary source; or
- full private corpora.

## No SLA

Leitir has a single maintainer and cannot guarantee a response time. Reports
will be acknowledged when possible.
