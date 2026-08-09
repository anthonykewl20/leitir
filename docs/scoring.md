# Deterministic scoring operation

`tools/score_engine.py` is the ADR-002 repository/engine assessment scorer. It
evaluates Leitir itself across six weighted dimensions and is unrelated to the
runtime `leitir trust` seven-factor trust model: it does not implement or
independently verify that model. The systems share only the abstract principle
that unknown is neither zero nor pass. The scorer uses no model, imports no
`leitir` package code, and does not download or upgrade scoring tools.

The runtime corpus-trust policy is instead owned by `src/leitir/trust.py`.
Its drift guard is the deterministic factor/weight contract test
`test_configured_weights_match_the_seven_factor_contract` and the weight-swap
mutation test `test_swapping_age_and_tests_weights_changes_the_golden_score` in
`tests/test_trust.py`. Those tests guard the seven factors and their effect on a
golden runtime score; ADR-002 is not a second implementation of that policy.

## Commands

Run the locally collectible profile and write canonical JSON plus deterministic
HTML:

```bash
PYTHONPATH=src uv run --no-project --with-requirements requirements.txt python \
  tools/score_engine.py run --profile offline \
  --json-out .leitir-score/assessment.json \
  --html-out .leitir-score/scorecard.html
```

Use the `uv` invocation above: the fixed offline collector launches `python -m
pytest`, so a bare interpreter without the test lock cannot produce valid test
evidence.

Run the release profile with opt-in live OpenSSF/GitHub evidence:

```bash
LEITIR_ENABLE_SCORE_LIVE=1 \
PYTHONPATH=src python tools/score_engine.py run --profile release \
  --json-out .leitir-score/assessment.json \
  --html-out .leitir-score/scorecard.html
```

The live collector is credential-free and does not read `GH_TOKEN` or model
credentials. A release run also requires a clean worktree. Enabling live
collection does not fill missing local evidence and cannot turn an unresolved
required check into a pass.

Render an existing canonical assessment without collecting or evaluating:

```bash
python tools/score_engine.py render \
  --assessment .leitir-score/assessment.json \
  --html .leitir-score/scorecard.html
```

The render command returns the decision exit of the assessment it rendered.
Malformed JSON or a non-canonical assessment shape returns exit 2.

## Profiles

`offline` requires only deterministic, locally collectible checks. Network
process/supply-chain and controlled-performance checks retain their policy
facts as advisory unknowns when uncollected; they are never inferred healthy.
An offline pass is only an offline policy pass and the CLI prints
`release_readiness=not_claimed`.

`release` uses the same checks plus required live provenance, GitHub
process/supply-chain facts, an approved controlled-performance baseline, and
required test-adequacy evidence. Only a complete release-profile pass can be
used as a release-readiness claim. Any required `unknown`, `error`, `skipped`,
or missing result keeps release indeterminate unless a known failure already
takes precedence.

Display bands are continuity metadata only: 0–3999 `critical`, 4000–5999
`serious`, 6000–7999 `fair`, and 8000–10000 `good`. They are never read by the
gate.

## Process exits

| Exit | Meaning |
|---:|---|
| 0 | Complete policy pass |
| 1 | Known policy failure |
| 2 | Malformed usage, malformed assessment, or invalid policy |
| 3 | Indeterminate evidence or collector/infrastructure error |

The hard gate, not the diagnostic scalar, selects exits 0, 1, or 3. A low score
cannot change a pass to a failure, and a high observed score cannot change an
indeterminate assessment to a pass.

## Evidence regeneration

`run` always regenerates the fixed ADR-001 pytest JUnit artifact using the
allowlisted argument vector in `tools/score_engine.py`. Additional S3–S7 raw
artifacts are consumed from `.leitir-score/evidence` by default, or from the
directory supplied with `--evidence-dir`. A group is evaluated only when its
complete required file set is present; otherwise its policy checks remain
explicitly unresolved.

The fixed file layout is:

| Adapter | Required files |
|---|---|
| Engine correctness and replay | `benchmark-run.json`, `benchmark-run-repeat.json`, `benchmark-run-permuted.json`, `global-report.json` |
| Output effectiveness | The primary benchmark run above, plus committed `src/leitir/benchmarks/search-v1/manifest.json` and `qrels.json` |
| Code health | `code-scope.json`, `score-tool-versions.json`, `radon-cc.json`, `radon-mi.json` |
| Test adequacy | `code-scope.json`, `score-tool-versions.json`, `coverage.json`, `mutmut.json` |
| Controlled performance | `performance-runner.json`, `baseline-asv.json`, `candidate-asv.json` |
| Advisory live latency | `live-network-latency.json` |

Generate these artifacts in the formats consumed by the S3–S7 adapters, using
the pinned commands/tool versions recorded in the ADR and
`requirements-score.txt`; do not edit normalized
scores into the files. Then rerun the profile command. Every consumed byte is
SHA-256-bound into the assessment. Missing, partial, malformed, mismatched, or
unapproved evidence remains unresolved or becomes a known policy failure as
defined by its adapter.

The current self-assessment evidence was collected with Radon 6.0.1 and
coverage.py 7.15.2. The declared production scope is every Python module under
`src/leitir`; Radon's JSON was normalized to the adapter contract by retaining
an explicit empty block list for `__init__.py` and extracting each reported
`mi` value. Coverage was run with `--branch --source=src/leitir` over the full
offline pytest suite. Mutmut 3.7.0 was then scoped to `docpointers.py` and its
16 focused tests: the clean control passed, the forced-failure sentinel failed
as expected, and all 327 generated mutants completed (243 killed and 84
survived). This closes the fail-closed four-file test-adequacy group without
claiming mutation coverage outside that explicitly recorded scope.

Collector-generated formats are normalized only where their schemas contain
non-semantic run volatility. Pytest JUnit drops suite `timestamp` and
`hostname` plus every `time`/`duration` attribute; coverage.py JSON drops
`meta.timestamp`; ASV drops orchestration dates and durations while retaining
the benchmark samples and controlled-machine identity. The assessment evidence
entry names the versioned normalization and its `sha256` identifies the
canonical bytes used by evaluation. The exact pre-normalization byte digest is
recorded separately in `.leitir-score/run-envelope.json`, alongside host and
run timing, so raw provenance remains visible without changing assessment
identity. OpenSSF's provider observation date and performance samples remain
canonical evidence because they identify the measured snapshot, not local
collector overhead.

## Published Leitir assessment

The canonical dogfood result is
[`scorecard/leitir-assessment.json`](../scorecard/leitir-assessment.json); the
generated view is
[`scorecard/leitir-assessment.html`](../scorecard/leitir-assessment.html). The
published clean pinned run remains `decision=indeterminate`, `complete=false`,
with an unknown exact score, `observed_score_bps=10000`, bounds `476..10000`,
and 29 missing required checks.

The separately generated current-worktree assessment in
`.leitir-score/assessment.json` reports `decision=pass`, `complete=true`, an
unknown exact score, `observed_score_bps=8382`, and bounds `5588..8922`. It has
no missing required checks and no blockers. The fixed offline collector
explicitly deselects the live-gated Go resolver test rather than counting its
intentional offline skip as a failure; the live test remains independently
available under `LEITIR_ENABLE_LIVE_E2E=1`.

Real Radon code-health evidence resolves all four required `code.*` checks;
maintainability index is advisory. Primary, repeat, and input-permuted
`search-v1` runs were reproduced through a local HTTP server from pinned bytes
whose git blob hashes match the committed manifest. Their canonical bytes and
manifest identity are identical. A local-server global search report preserves
`indeterminate_global`; the scorer accepts the current `SearchReport` schema's
`query_translation` field as well as the legacy report shape. Controlled mutmut
evidence makes the existing coverage artifact consumable and resolves all five
required `test.*` checks.

The public OpenSSF API returned HTTP 404 again for this repository. OpenSSF,
ASV controlled performance, and live latency are advisory in the offline
profile and do not block the offline pass. ASV 0.6.6 is installable, but this
repository has no ASV configuration or benchmark suite and no approved
baseline from which honest performance artifacts could be produced.

The collected required evidence therefore reaches an offline-only pass. The
unknown advisory checks keep the exact diagnostic score unknown and prevent any
release-readiness claim. Commit/release timestamps and license statements are
not ADR-002 policy inputs and must not be relabeled as evidence. A
release-profile pass additionally requires opt-in live OpenSSF evidence and an
approved controlled-performance baseline.

Regenerate it without reading identity from a dirty developer worktree:

```bash
subject_dir=$(mktemp -d)
git clone --quiet --no-hardlinks --no-checkout . "$subject_dir/pinned-subject"
git -C "$subject_dir/pinned-subject" checkout --quiet --detach \
  379cc7ae94ddc89ebe261e1fb8ab7a0b57b0768a
git -C "$subject_dir/pinned-subject" remote set-url origin \
  https://github.com/anthonykewl20/leitir.git
PYTHONPATH=src uv run --no-project --with-requirements requirements.txt python \
  tools/score_engine.py run --profile offline \
  --root "$subject_dir/pinned-subject" \
  --json-out "$PWD/scorecard/leitir-assessment.json" \
  --html-out "$PWD/scorecard/leitir-assessment.html" \
  --run-envelope-out "$PWD/.leitir-score/run-envelope.json"
```

Exit 3 is expected for this published indeterminate result. The regeneration
gate is `tests/test_score_dogfood.py`. It builds its own temporary clean clone
at the pin and byte-compares both regenerated files with the published files.
Therefore a hand edit to either JSON or HTML fails, as does a scorer/renderer
change whose artifact was not regenerated. The current worktree may be dirty:
it supplies the scorer code under test but is never represented as the clean
subject. The test also asserts that none of the following manual snapshots is
an evidence path:

- `docs/leitir-engine-scorecard.html`
- `docs/leitir-engine-scorecard.png`
- `docs/leitir-engine-scorecard-v2.html`

Those three files are historical, dated manual research snapshots only. They
must never be consumed as scorer evidence; their editorial values are not a
replacement for the canonical unknown-with-bounds result.

## Rendering contract

The HTML renderer reads scores and judgments from canonical JSON and never
re-evaluates them. Integer basis points are displayed verbatim without percent
conversion. A null exact score is displayed as `unknown` alongside its
`observed_score_bps`, `lower_bound_bps`, and `upper_bound_bps`; it is never
displayed as zero. A measured exact zero remains `0`.

All interpolated values are HTML-escaped. The document also embeds the exact
canonical JSON as escaped text, so its parsed text equals the JSON byte-for-byte.
The renderer uses fixed markup, canonical ordering, integer/null fields, and no
time-, locale-, host-, or random-dependent input. Rendering the same assessment
twice therefore produces byte-identical output.

Unsigned in-toto emission and signing are not implemented in S8. Signing is a
separate later change.
