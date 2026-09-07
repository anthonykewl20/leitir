# Issue #347 — automatic skill selection and reference semantics

Observed on 2026-09-07 using the actual Codex CLI and real retrieved source.
This is a skill/documentation change; it does not modify runtime code.

## Actual automatic activation

Installed the repository skill into `~/.agents/skills/leitir` with
`policy.allow_implicit_invocation: true`. Also installed the same files into
`~/.claude/skills/leitir`; Claude automatic selection was not tested.

Ran a fresh Codex process against the main checkout, whose AGENTS.md did not yet
contain this PR's automatic-reference rule:

```sh
codex exec --sandbox read-only -C /home/soultransit/devtony/leitir \
  --json --output-last-message /tmp/leitir-skill-347/automatic-response.md \
  - < /tmp/leitir-skill-347/automatic-request.txt
```

The exact request is in `automatic-request.txt`. It asks about retry jitter
without naming the skill or explicitly invoking it. `automatic-selection.json`
contains the actual completed selection message, successful skill-file read,
and final response from the JSON event stream. The selected skill read predates
a subsequent correction to its JSON-output comment: plain single-spec `get`
does print a bare path to stdout; JSON supplies verification metadata.

The agent inspected the verified Git reference, compared the target's actual
HTTP implementation and dependency constraints, and recommended stdlib-only
code with no backoff/botocore dependency or manifest changes. Its complete
response is in `automatic-response.md`. This demonstrates one actual implicit
selection and reference-oriented investigation, not guaranteed selection for
every possible prompt or proof that the proposed retry change was implemented.

## Real source acquisition and search

Executed `info` and `get --json` for `pypi:backoff@2.2.1`, then acquired
`github:litl/backoff@d9d80a92d5a4483373acdaf9faa4068c85b3d268` into a separate
corpus. The actual successful get outputs are retained in `get.json` and
`git-get.json`. Both report verified source; the registry artifact has Git
parity drift and must not be cited as byte-identical Git source.

Executed the documented search syntax against each real corpus:

```sh
leitir search --corpus --must exact_text:full_jitter --json --root <corpus>
```

The registry corpus reported `partial`, zero matches, and a
`registry_provenance` exclusion. The Git corpus reported
`complete_for_declared_universe`, 14 matches, and no excluded shelves. Thus zero
matches cannot be treated as universal absence. No target dependency files or
source files changed during acquisition or investigation.

An independent agent also inspected the actual reference and target code;
`forward-check.md` records its investigation. That exercise explicitly supplied
the skill and validates reference handling, separately from automatic selection.
No hand-built response or wording-match unit test is used as activation proof.

Full regression, lint, typing, skill validation, documentation checks, CI and
independent review results are recorded in the PR. Runtime dependencies remain
empty; no integrity or materialization behavior changes.
