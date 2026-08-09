# Continuous integration

## Live-provider canary

`.github/workflows/live-canary.yml` is an opt-in canary for the real-provider
end-to-end tests. It runs the test suite on Ubuntu with
`LEITIR_ENABLE_LIVE_E2E=1` and `LEITIR_ENABLE_SCORE_LIVE=1`; the default CI
continues to run with both gates disabled.

To enable the canary, add a repository Actions secret named `GH_TOKEN`. This
is the required opt-in gate and should contain a GitHub token suitable for
read-only access to the public fixtures. The workflow exports it as both
`GH_TOKEN` and `GITHUB_TOKEN`, matching the names read by the live tests and
credential code.

The credential resolver also recognizes these optional repository secrets for
provider authentication: `GITLAB_TOKEN`, `BITBUCKET_TOKEN` (with optional
`BITBUCKET_USERNAME`), `CODEBERG_TOKEN`, `SRHT_TOKEN`, `NPM_TOKEN`,
`PYPI_TOKEN` (or `PIP_TOKEN`), and `CARGO_TOKEN`. Public-provider tests may run
anonymously when their optional credential is absent and provider rate limits
allow it.

Run the canary from **Actions → Live provider canary → Run workflow**. With no
`GH_TOKEN`, its gate job succeeds and records a clear skipped message instead
of running live tests. The live-test job has `continue-on-error: true`, is
separate from normal CI, and is intended to remain a non-required,
non-blocking check. Its job summary records the test outcome.
