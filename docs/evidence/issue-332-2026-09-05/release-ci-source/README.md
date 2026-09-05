# Confirmed release CI source-identity defect

Reviewed release workflow at source head `5459b3fe89f077c5681c442e73861d85221a654c` on 2026-09-05. No project edits, tags, releases or GitHub comments were made during this investigation.

## Finding

`.github/workflows/release.yml` selects a completed successful CI run using only `headSha == tagged commit`. `.github/workflows/ci.yml` uses default `actions/checkout` on `pull_request` events. The reported run head and the checked-out merge commit are different identities. A successful PR run can therefore pass the release CI-admission gate while its artifacts contain source absent from the tagged head. Version checks do not establish source identity.

GitHub documents that pull-request workflows check out the PR merge branch by default, with `GITHUB_SHA` naming that merge commit: https://docs.github.com/en/actions/reference/workflows-and-actions/events-that-trigger-workflows#pull_request. The exact pinned checkout action documents the explicit override needed to select the head instead: https://github.com/actions/checkout/blob/11d5960a326750d5838078e36cf38b85af677262/README.md#checkout-pull-request-head-commit-instead-of-merge-commit.

## Actual repository evidence

- PR #106: https://github.com/anthonykewl20/leitir/pull/106.
- Actual successful CI run: https://github.com/anthonykewl20/leitir/actions/runs/31579743105.
- Actual run metadata: `event=pull_request`, `headSha=9d61335fe19176dc1facda3182913ae1305a5252`, `status=completed`, `conclusion=success` (`run-106.json`).
- Package job log: https://github.com/anthonykewl20/leitir/actions/runs/31579743105/job/94059876642. Checkout at 2026-08-12 08:45:04 UTC actually selected `2f997ee8ad862af5cb627d5e5cee526099f6ffd7`, merging the reported head into `82e2304ac9007ae334b11b1739122d3337037d42` (`package-106.log`).
- Downloaded the existing `python-package-distributions` artifact from that run; no rebuild. Its wheel contains three tracked source data files absent from the reported head, all exactly matching bytes from the merge's base: `leitir/benchmarks/ast-vs-regex-v1/README.md`, `comparison.json`, and `corpus/Lib/urllib/parse.py.txt`. See `source-comparison-106.json` and `artifact-identities-106.json`.
- The head's pyproject version and the wheel's METADATA version both equal `0.1.1`; a version comparison cannot detect this mismatch.
- Queried the same actual `gh run list --workflow ci.yml --commit ...` inputs as the release gate. Its current predicate selects run `31579743105`. Adding an allowed-event predicate (`push` or `workflow_dispatch`) rejects that run. See `gate-input-106.json` and `gate-comparison-106.json`.

This is proof of a mismatched-source **CI admission path**. No release was created to demonstrate it. These historical unpadded artifacts are not claimed to pass the new padded-version policy; their source mismatch demonstrates why run identity plus version equality is insufficient in the general supported release workflow.

## Current release distinction

GraphQL showed PR #333 head `5459b3fe89f077c5681c442e73861d85221a654c` and its then-current merge commit `8cc138f8c167e735732374cd8c5eedc8a1d65413` have the same tree `b0e5838766fabe1835dcfa8e36e3ca1b5b7b9a3f`. Therefore this investigation does **not** allege a source-content mismatch for that release candidate. See `current-release-trees.json`.

## Smallest honest correction

Keep PR CI testing the proposed merge. Release admission should accept only successful exact-SHA CI runs from supported events whose default checkout is that SHA, such as `push` or `workflow_dispatch`; filter events for both success selection and pending diagnostics. Then dispatch the actual final release branch, or wait for the final main push CI, and consume that exact run's package artifact. An explicit CI assertion that checkout HEAD equals GITHUB_SHA on these events can make the invariant directly observable. Do not accept PR artifacts merely because their metadata names the tagged head.

## Investigation control

PR #225 was also inspected because its final merged tree differs from its head. Its actual package artifact matched the head; differences arrived in the later final merge. That candidate was rejected as evidence of artifact mismatch. Its retained `*-225` files document the distinction.

Commands used: `gh pr view ... --json ...` / GraphQL for PR and check metadata; `gh run view RUN --json databaseId,headSha,event,status,conclusion,url`; `gh run download RUN --name python-package-distributions --dir ...`; `gh api repos/anthonykewl20/leitir/actions/jobs/JOB/logs`; `git show SHA:PATH`; Python stdlib `zipfile`, `tarfile`, `tomllib`, `hashlib` for actual artifact inspection. No mocked run metadata or synthetic repository was used.

`gate-replay.sh` executes the actual old jq predicate and the event-qualified predicate on the unchanged captured `gate-input-106.json`: `gate-before.txt` selects run31579743105, and `gate-after.txt` is empty. This is a component dry-run of admission, not a publication or a full release workflow test.

## Exact workflow-step execution against live GitHub metadata

Root also extracted the complete before/after production workflow shell steps
and executed them against the actual GitHub API for the historical head.
The original step exited0 and selected the mismatched-source PR build. The
corrected step exited1 and required push/dispatch CI. Commands and outputs are
preserved in `production-gate-*`; no tag or publication was performed.

`evidence.tar.gz` preserves original filenames, logs and the actual downloaded
PR106 distributions. Loose log copies use `.txt` for repository retention.

Loose log/script copies omit trailing whitespace for repository formatting. The archive retains the exact captured bytes and original hashes.
