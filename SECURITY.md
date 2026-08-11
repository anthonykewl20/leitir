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

## Donor-code execution containment

Donor tests and fixtures are arbitrary hostile code. They may try to disclose
credentials, make network connections, write outside staging, import ambient
host code, exhaust memory or CPU, fill filesystems, fork, or leave descendants.
Leitir therefore defaults donor execution off. Only the exact environment value
`LEITIR_ENABLE_DONOR_EXECUTION=1` opts in; the raw value is never retained in a
canonical artifact.

Version 1 supports Linux and one release-pinned external native backend:
**nsjail**. Before launch, Leitir verifies the executable digest and build
identity and rejects unless the policy explicitly applies all required Linux
namespaces, cgroup v2 memory/CPU/pid limits, numeric rlimits (including file
descriptors and zero core size), a default-deny seccomp policy, no inherited
environment or capabilities, no-new-privileges, a read-only allowlisted mount
plan, no network interfaces/routes, and one size/inode-bounded writable tmpfs.
The parent additionally enforces wall time and bounded output. Limit hits,
output overflow, process leaks, or an unverifiable control reject and cannot
produce authorizing canonical evidence.

There is no portable, audit-hook, `resource`-only, or unsandboxed fallback.
Python audit hooks are diagnostic only. Residual risk remains in the Linux
kernel, nsjail, seccomp policy, rootfs, interpreter, runner, and native code;
their pinned identity is integrity evidence, not proof that they are defect-free.
Do not enable donor execution before the policy artifacts and containment path
have received independent security review.

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
