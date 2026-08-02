# Deterministic scoring operation

`tools/score_engine.py` is the standalone ADR-002 scoring composition root. It
uses no model, imports no `leitir` package code, and does not download or
upgrade scoring tools.

## Commands

Run the locally collectible profile and write canonical JSON plus deterministic
HTML:

```bash
PYTHONPATH=src python tools/score_engine.py run --profile offline \
  --json-out .leitir-score/assessment.json \
  --html-out .leitir-score/scorecard.html
```

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
