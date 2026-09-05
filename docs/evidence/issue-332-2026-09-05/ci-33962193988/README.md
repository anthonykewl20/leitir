# Actual CI distribution validation

[CI run 33962193988](https://github.com/anthonykewl20/leitir/actions/runs/33962193988)
built these downloaded artifacts at commit
`cc134194e6528c34dd364d8a1dae15939093ed16` using `workflow_dispatch`.
The production verifier accepts public `v0.2.000` and distribution `0.2.0`.
[Archive identities](verify-release.stdout) bind the exact downloaded bytes.

Every packaged tracked source/data file matches that Git commit: 127 in the
wheel and 326 in the source archive. All 119 tracked runtime Python files are
present in each. [Source comparison](source-byte-comparison.json) records each
path and hash, and separately identifies generated packaging metadata.

Each archive was installed in its own environment with no runtime dependencies
or source `PYTHONPATH`. Installing the source archive performs its normal
installer build; the publication artifact itself was not rebuilt or replaced.
Both CLIs report `leitir 0.2.000`, and installed metadata reports `0.2.0`.
Both materialize the real pinned Packaging source, report 462 AST API symbols
and produce 10 examples. The downloaded `version.py` independently matches
upstream Git blob `46bc2613086732e34b8863b7ea562ffb6918865b`.

[Commands](commands.json) record 14 successful environment, installation,
version and live operations. [Summary](summary.json) records their results.
The evidence archive retains the actual CI artifacts, original sanitized logs,
exact probe driver and production verifier. A driver initially expected an API
results envelope; the CLI correctly returned its documented direct API object.
That assertion was corrected; no application command failed.

Required workflow checks, independent release review and publication are
recorded separately. This evidence does not claim unexecuted behavior.

A separate installed `doctor --json --no-network` probe returned zero, reported
`0.2.000` and validated the real local corpus. Its command and output are
recorded in `wheel-doctor.command.json` and `wheel-doctor.stdout`. An earlier
unsupported `--root` option correctly rejected; the successful probe selects
the corpus through the documented `LEITIR_HOME` environment variable.
