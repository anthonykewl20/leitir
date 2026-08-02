# ADR-002: Build a deterministic, evidence-bound scoring engine

- Status: Accepted — implemented through S8; S9 in progress
- Date: 2026-08-02
- Revised: 2026-08-03 (S1–S8 landed)
- Related: ADR-001 deterministic code-search kernel, especially P6
- User-facing shape: standalone script, not a `leitir` CLI subcommand

## Context

The current scorecards are documents. Their cited test runs and code locations
are useful evidence, but their 0-10 judgments were assigned by reviewers. They
cannot be reproduced by running code without a reviewer or an LLM.

That is incompatible with ADR-001's central rule: the same declared input must
produce the same output, and claims must carry evidence. A manually assigned
`6.0/10` is still an opinion even when the surrounding facts are correct.

Leitir needs executable assessment for four different subjects:

1. **Code:** maintainability, measurable test adequacy, security findings, and
   packaging health.
2. **Process:** CI, review, branch protection, dependency hygiene, releases,
   and supply-chain controls.
3. **Output:** whether ranked source results contain the correct pinned code at
   useful ranks.
4. **Engine:** contract correctness, determinism, provenance, coverage honesty,
   reliability, performance, and operability.

It also needs an overall result without allowing strong scores in easy areas to
hide a broken critical invariant. No model call is permitted anywhere in this
assessment path.

The scorecard HTML is therefore a view, not the source of truth. The source of
truth will be a canonical machine assessment bound to its subject, policy,
tools, and raw evidence.

## Research method

This decision is based on executable source code, tests, and exact revisions on
GitHub rather than product pages. For each candidate system, the investigation
traced:

- the result vocabulary and schema;
- the actual scoring or threshold formula;
- aggregation and hard-gate behavior;
- missing, empty, error, skipped, and not-applicable behavior;
- evidence and provenance fields;
- deterministic ordering and serialization;
- boundary tests that pin behavior;
- license and suitability for reuse.

The following revisions were inspected.

| Subject | Revision and executable source | Useful mechanic | Rejected mechanic |
|---|---|---|---|
| SonarQube | `26.7.0.124771` @ [`94766f4`](https://github.com/SonarSource/sonarqube/tree/94766f42c013a6b115ca9b17669da178e7d24cb9), LGPL-3.0-or-later. [`QualityGateEvaluatorImpl`](https://github.com/SonarSource/sonarqube/blob/94766f42c013a6b115ca9b17669da178e7d24cb9/server/sonar-server-common/src/main/java/org/sonar/server/qualitygate/QualityGateEvaluatorImpl.java#L55-L136), [`ConditionEvaluator`](https://github.com/SonarSource/sonarqube/blob/94766f42c013a6b115ca9b17669da178e7d24cb9/server/sonar-server-common/src/main/java/org/sonar/server/qualitygate/ConditionEvaluator.java#L39-L145), [`DebtRatingGrid`](https://github.com/SonarSource/sonarqube/blob/94766f42c013a6b115ca9b17669da178e7d24cb9/server/sonar-server-common/src/main/java/org/sonar/server/measure/DebtRatingGrid.java#L38-L115). | Diagnostic ratings are separate from an any-condition hard gate; raw effort and development cost are aggregated before deriving a ratio; worst severity is retained. | Missing measures evaluate `OK`; small-change exceptions can suppress failures; no Sonar code will be copied because of license and product weight. |
| OpenSSF Scorecard | `v5.5.0` @ [`c395761`](https://github.com/ossf/scorecard/tree/c395761df6afe1a69e476bc60a013a94bcbc153f), Apache-2.0. [`CheckResult`](https://github.com/ossf/scorecard/blob/c395761df6afe1a69e476bc60a013a94bcbc153f/checker/check_result.go#L60-L97), [`GetAggregateScore`](https://github.com/ossf/scorecard/blob/c395761df6afe1a69e476bc60a013a94bcbc153f/pkg/scorecard/scorecard_result.go#L82-L120), [`AsInToto`](https://github.com/ossf/scorecard/blob/c395761df6afe1a69e476bc60a013a94bcbc153f/pkg/scorecard/statement.go#L29-L95). | Per-check reason, details, structured findings, repository commit, tool commit, risk metadata, stable output ordering, and in-toto subject binding. | Its aggregate omits every inconclusive `-1` check, so missing evidence can improve the mean. The aggregate is not a release gate and will not be imported as Leitir's overall score. |
| OpenSCAP | `1.4.4` @ [`4ac56ce`](https://github.com/OpenSCAP/openscap/tree/4ac56ce0e6dfdea7215b5ad202b3db20855d2507), LGPL-2.1-or-later. [`result_scoring.c`](https://github.com/OpenSCAP/openscap/blob/4ac56ce0e6dfdea7215b5ad202b3db20855d2507/src/XCCDF/result_scoring.c#L57-L281), [`xccdf_session_contains_fail_result`](https://github.com/OpenSCAP/openscap/blob/4ac56ce0e6dfdea7215b5ad202b3db20855d2507/src/XCCDF/xccdf_session.c#L1895-L1910). | Closest precedent: publish a weighted score but independently fail on any `FAIL`, `UNKNOWN`, or `ERROR`; preserve typed outcomes and separate policy failure from tool error. | `NOT_CHECKED` can be excluded and nonblocking. Leitir will treat a required skipped/not-checked result as indeterminate. No source will be copied. |
| Lighthouse and LHCI | Lighthouse `v13.4.1` @ [`1d58f5b`](https://github.com/GoogleChrome/lighthouse/tree/1d58f5b06d28e3419b38817a6c7488ec4413c67d); LHCI `v0.15.1` @ [`76a49c7`](https://github.com/GoogleChrome/lighthouse-ci/tree/76a49c7cc26cfc6dcff4248e1f170efb845245bb), Apache-2.0. [`arithmeticMean`](https://github.com/GoogleChrome/lighthouse/blob/1d58f5b06d28e3419b38817a6c7488ec4413c67d/core/scoring.js#L16-L42), [LHCI assertions](https://github.com/GoogleChrome/lighthouse-ci/blob/76a49c7cc26cfc6dcff4248e1f170efb845245bb/packages/utils/src/assertions.js#L51-L129). | A positive-weight error poisons the category score to null; warnings and hard assertions remain distinct; pessimistic repeated-run evaluation exists. | Optimistic aggregation filters missing values. Leitir will use pessimistic required-check semantics. |
| Conftest | `v0.68.2` @ [`36f23bf`](https://github.com/open-policy-agent/conftest/tree/36f23bf930b808c73c4e41c6a4eeac5b620b2225), Apache-2.0. [`CheckResult`](https://github.com/open-policy-agent/conftest/blob/36f23bf930b808c73c4e41c6a4eeac5b620b2225/output/result.go#L137-L213), [`Engine.check`](https://github.com/open-policy-agent/conftest/blob/36f23bf930b808c73c4e41c6a4eeac5b620b2225/policy/engine.go#L299-L408). | A useful proof that a policy decision can be a vector of failures/warnings/exceptions rather than a scalar. | No Rego runtime is needed for Leitir's fixed first-party policy. |
| Radon | `v6.0.1` @ [`5061d86`](https://github.com/rubik/radon/tree/5061d86a649223bdc5490c5dcc113743cc5b47f5), MIT. [`ComplexityVisitor`](https://github.com/rubik/radon/blob/5061d86a649223bdc5490c5dcc113743cc5b47f5/radon/visitors.py#L145-L334), [`cc_rank`](https://github.com/rubik/radon/blob/5061d86a649223bdc5490c5dcc113743cc5b47f5/radon/complexity.py#L15-L56), [`mi_compute`](https://github.com/rubik/radon/blob/5061d86a649223bdc5490c5dcc113743cc5b47f5/radon/metrics.py#L69-L157). | Deterministic AST metrics, explicit complexity bands, and boundary tests. | Maintainability Index is gameable by comments and returns 100 for zero volume/LOC. MI will not be an overall score or hard gate. |
| Xenon | `v0.9.3` @ [`c7364e2`](https://github.com/rubik/xenon/tree/c7364e23bb55ca515322eb9a260b5ebf4bf18c3b), MIT. [`find_infractions`](https://github.com/rubik/xenon/blob/c7364e23bb55ca515322eb9a260b5ebf4bf18c3b/xenon/core.py#L10-L97). | Absolute per-block thresholds prevent a severe outlier from hiding in an average. | Parser errors are skipped, empty input is A, and thresholds are disabled by default. Leitir will not use Xenon as the authority. |
| coverage.py | `7.15.2` @ [`50d8659`](https://github.com/coveragepy/coveragepy/tree/50d865908dfeb21a0bf1e6f05db578c11662f8dd), Apache-2.0. [`Numbers`](https://github.com/coveragepy/coveragepy/blob/50d865908dfeb21a0bf1e6f05db578c11662f8dd/coverage/results.py#L298-L383), [`should_fail_under`](https://github.com/coveragepy/coveragepy/blob/50d865908dfeb21a0bf1e6f05db578c11662f8dd/coverage/results.py#L483-L502), [JSON counters](https://github.com/coveragepy/coveragepy/blob/50d865908dfeb21a0bf1e6f05db578c11662f8dd/coverage/jsonreport.py#L45-L67). | Raw line and branch numerators/denominators are available for independent exact gates. | Rounded `--fail-under`, combined line/branch percentage, and zero-item 100% conventions will not define Leitir policy. |
| mutmut | `3.7.0` @ [`4f12080`](https://github.com/boxed/mutmut/tree/4f1208093517575a9402b99cfdcc7dea54c40e67), BSD-3-Clause. [`status_by_exit_code`](https://github.com/boxed/mutmut/blob/4f1208093517575a9402b99cfdcc7dea54c40e67/src/mutmut/__main__.py#L82-L117), [clean-control and sentinel checks](https://github.com/boxed/mutmut/blob/4f1208093517575a9402b99cfdcc7dea54c40e67/src/mutmut/__main__.py#L671-L789). | Rich categories: killed, survived, no tests, skipped, timeout, suspicious, crash, and not checked; clean baseline and forced-failure sentinel. | Pytest internal errors can be called killed and the command does not fail merely because mutants survived. Leitir will normalize raw categories itself. |
| Cosmic Ray | `v8.4.6` @ [`952fe4d`](https://github.com/sixty-north/cosmic-ray/tree/952fe4d959b49776ef2749defb1a4dedbbf50a9f), MIT. [`survival_rate`](https://github.com/sixty-north/cosmic-ray/blob/952fe4d959b49776ef2749defb1a4dedbbf50a9f/src/cosmic_ray/tools/survival_rate.py#L62-L75). | Independent mutation implementation used to check assumptions. | All non-survived outcomes count as killed, pending work is omitted, and zero completed mutants implies a perfect mutation score. Rejected. |
| ir_measures | `v0.4.3` @ [`bb9ece5`](https://github.com/terrierteam/ir_measures/tree/bb9ece5c1ec6a0027c8a9f7a8ee428614f8a2f44), Apache-2.0, with `pytrec-eval-terrier v0.5.10` @ [`af2270d`](https://github.com/terrierteam/pytrec_eval/tree/af2270d9cca0e75d04861b9f10021873d8dd7815), MIT. [`Evaluator`](https://github.com/terrierteam/ir_measures/blob/bb9ece5c1ec6a0027c8a9f7a8ee428614f8a2f44/ir_measures/providers/base.py#L18-L39), [pytrec adapter](https://github.com/terrierteam/ir_measures/blob/bb9ece5c1ec6a0027c8a9f7a8ee428614f8a2f44/ir_measures/providers/pytrec_eval_provider.py#L60-L175). | Established Precision, Recall, reciprocal rank, AP, nDCG, and Success semantics; missing per-query values can be made explicit zeros. | Its aggregate alone is insufficient: Leitir must first require exact query-set equality and must not allow missing tasks to disappear. Transitive trec_eval licensing needs review before redistribution. |
| NIST trec_eval | Formula reference `v9.0.8` @ [`d95ca64`](https://github.com/usnistgov/trec_eval/tree/d95ca64e14a47d763ae349fb65e6d8cde4141dbd); current `v10.0` @ [`f425365`](https://github.com/usnistgov/trec_eval/tree/f4253652c8efd0d86ddffd0d163cc0a0f813111a). [`P`](https://github.com/usnistgov/trec_eval/blob/d95ca64e14a47d763ae349fb65e6d8cde4141dbd/m_P.c#L49-L78), [`recall`](https://github.com/usnistgov/trec_eval/blob/d95ca64e14a47d763ae349fb65e6d8cde4141dbd/m_recall.c#L41-L73), [`RR`](https://github.com/usnistgov/trec_eval/blob/d95ca64e14a47d763ae349fb65e6d8cde4141dbd/m_recip_rank.c#L33-L51), [`AP`](https://github.com/usnistgov/trec_eval/blob/d95ca64e14a47d763ae349fb65e6d8cde4141dbd/m_map_cut.c#L41-L77), [`nDCG`](https://github.com/usnistgov/trec_eval/blob/d95ca64e14a47d763ae349fb65e6d8cde4141dbd/m_ndcg_cut.c#L43-L125), [`Success`](https://github.com/usnistgov/trec_eval/blob/d95ca64e14a47d763ae349fb65e6d8cde4141dbd/m_success.c#L41-L71). | Authoritative executable formulas and golden tests. | Equal scores use evaluator-specific document-ID tie rules. Leitir must establish a total order before evaluation. |
| BEIR | `v2.2.0` @ [`6ef8c90`](https://github.com/beir-cellar/beir/tree/6ef8c9097ebfb203ad360bd64e0cfb93e64f4a44), Apache-2.0. [`EvaluateRetrieval.evaluate`](https://github.com/beir-cellar/beir/blob/6ef8c9097ebfb203ad360bd64e0cfb93e64f4a44/beir/retrieval/evaluation.py#L69-L122). | Confirms common IR metric selection. | Missing query IDs can leave the denominator, empty results can divide by zero, input is mutated, tie behavior differs across metrics, and the release has no metric tests. Rejected as authority. |
| ranx | `0.3.21` @ [`7363db0`](https://github.com/AmenRa/ranx/tree/7363db0c35e92e90d6fa6fe73907b760678f765e), MIT. [`evaluate`](https://github.com/AmenRa/ranx/blob/7363db0c35e92e90d6fa6fe73907b760678f765e/ranx/meta/evaluate.py#L123-L169). | Independent formula implementation and useful edge-case tests. | Equal-score sorting has no stable document-ID secondary key. It is a cross-check, not the authority. |
| ASV | `v0.6.6` @ [`da01e9e`](https://github.com/airspeed-velocity/asv/tree/da01e9e399f35334c72749e51a0f343be1fb832a) and `asv_runner v0.2.5` @ [`01d4a25`](https://github.com/airspeed-velocity/asv_runner/tree/01d4a2556932ca63e8d7df6536551c6107397e66), BSD-3-Clause. [`compare`](https://github.com/airspeed-velocity/asv/blob/da01e9e399f35334c72749e51a0f343be1fb832a/asv/commands/compare.py#L65-L89), [`is_different`](https://github.com/airspeed-velocity/asv/blob/da01e9e399f35334c72749e51a0f343be1fb832a/asv/_stats.py#L30-L148), [`compute_stats`](https://github.com/airspeed-velocity/asv_runner/blob/01d4a2556932ca63e8d7df6536551c6107397e66/asv_runner/statistics.py#L499-L578). | Median samples, magnitude threshold plus statistical evidence, introduced-failure classification, environment and benchmark-version comparison. | One-sample and underpowered comparisons can fall back to weaker evidence. Leitir will require adequate samples for a hard pass. |
| DORA Four Keys | `v1.0.2` @ [`33f8f33`](https://github.com/dora-team/fourkeys/tree/33f8f33d43b43b4a5ae9a8372b31d22ff480175c), Apache-2.0. [Event processing](https://github.com/dora-team/fourkeys/blob/33f8f33d43b43b4a5ae9a8372b31d22ff480175c/bq-workers/github-parser/main.py#L71-L146), [metric definitions](https://github.com/dora-team/fourkeys/blob/33f8f33d43b43b4a5ae9a8372b31d22ff480175c/METRICS.md#L9-L108). | Shows the event linkage required before deployment metrics are meaningful. | Leitir has no production deployment or incident stream. Zero activity must not become elite performance; DORA is not applicable now. |

Additional code-specific systems were checked and rejected as primary sources:

- Code Climate's current repository redirects to `qlty`, whose current license
  is BSL 1.1, and no supported open repository-grade formula was found.
- CodeSearchNet and CodeXGLUE provide useful historical MRR/nDCG examples but
  have optimistic unjudged-result or thin test behavior.
- SWE-bench's fail-closed patch/test classifications are useful for generated
  patches, but Leitir's current output is ranked source evidence, not generated
  code. Generated-code correctness must remain a separate future gate.

## Findings

### 1. A score and an acceptance decision are different products

SonarQube, OpenSCAP, Lighthouse CI, and Conftest all demonstrate that release
acceptance must not be an arithmetic mean. A critical failure remains a failure
even if every unrelated diagnostic is perfect.

OpenSCAP supplies the closest usable model: compute a diagnostic score, then
independently scan all required checks for failures and unresolved evidence.

### 2. Unknown is neither zero nor pass

Several mature tools fail open:

- SonarQube treats a missing gate measure as OK.
- OpenSSF omits inconclusive checks from its aggregate denominator.
- Radon gives empty/zero-volume input a perfect maintainability score.
- coverage.py can report a measured empty file as 100%.
- Cosmic Ray makes zero completed mutants look perfect.
- Four Keys can map absent observations to apparently excellent buckets.

Leitir must preserve `unknown`, `error`, `skipped`, and `not_applicable` as
different states. A required unresolved check blocks a pass but is not reported
as a measured defect.

### 3. Raw counts come before ratios and grades

Every ratio must retain numerator, denominator, and exclusions by reason.
Repository totals are derived from raw sufficient statistics, not by averaging
file grades, child percentages, or rounded display values.

### 4. Output effectiveness is information retrieval evaluation

Leitir returns ranked source spans. Its output quality therefore uses pinned
qrels and TREC-style metrics, not a code-generation pass rate:

- `nDCG@10` for graded ranking quality;
- reciprocal rank at 10 for the first exact target;
- Recall at 10 for annotated useful targets;
- Success at 1, 5, and 10 for exact-target presence;
- Precision and AP only when relevance annotation is sufficiently complete.

Implementation correctness remains a separate gate. A high nDCG cannot prove
that every eligible blob was indexed, and complete indexing cannot prove that
the best result was ranked first.

### 5. Some measurements are deterministic; collection is not always static

Given the same policy and identical evidence bytes, assessment must be
byte-identical. Live GitHub state and timing samples may change over time; those
snapshots are inputs and must be hashed. This is not nondeterministic scoring:
it is different evidence.

### 6. Passing tests is not test adequacy

Test execution, statement/branch coverage, and mutation outcomes answer
different questions. A test count greater than zero and a green exit are hard
preconditions. Coverage consumes raw counters. Mutation preserves survived,
no-test, timeout, crash, and infrastructure outcomes instead of laundering all
non-survivors into "killed."

### 7. Performance needs a controlled comparison

Wall-clock values from developer machines or GitHub API calls are diagnostics,
not hard gates. A hard regression requires a pinned benchmark, matching runner
fingerprint, an approved baseline, adequate samples, a material slowdown, and
statistical evidence.

### 8. Current process evidence validates the need for typed unknowns

A trial OpenSSF run against Leitir at commit `688f566` observed no GitHub CI
workflow, no branch protection, no dependency updater, no release, and no
platform-recorded review. `CI-Tests` and signed releases were inconclusive due
to missing denominators, while other checks returned known failures. These are
different facts and must not collapse into one `-1` or be silently omitted.
The trial values are a dated research snapshot, not policy or a baseline.

## Decision

### 1. Build one standalone composition root

The user-facing command will be:

```bash
python tools/score_engine.py run --profile offline
python tools/score_engine.py run --profile release
python tools/score_engine.py evaluate --policy scorecard/policy-v1.json \
  --evidence-dir .leitir-score/evidence
python tools/score_engine.py render --assessment .leitir-score/assessment.json \
  --html docs/leitir-engine-scorecard-current.html
```

There will be no `leitir score` product command. The standalone script is the
composition root and must not import the retired Hy3 pipeline or make any model
request.

The script has three operations:

1. `collect`: run a fixed, allowlisted set of collectors and store raw evidence.
2. `evaluate`: pure function of policy bytes, subject bytes, and evidence bytes.
3. `render`: pure JSON-to-HTML transformation.

`run` composes all three for convenience. Policy files may define thresholds,
weights, applicability, and required/advisory status. They may not define shell
commands. Collectors invoke fixed argument arrays with `shell=False`.

The initial implementation remains in one script with internal dataclasses and
small pure functions. It is extracted only if a second caller needs the same
mechanics. External tool adapters consume machine output; their policy meaning
is decided by the evaluator, not by the collector.

### 2. Preserve and reuse existing Leitir invariants without coupling to v1

Existing useful mechanics were found in the retired evaluator:

- `Metric` records numerator, denominator, excluded count, and null on a zero
  denominator (`src/leitir/evaluation.py:122-154`).
- `EvaluationReport.to_json` uses sorted compact JSON and rejects NaN
  (`src/leitir/evaluation.py:192-195`).

Those invariants are reused, but the scoring script will not import that module:
it is coupled to the retired five-step engine. Keeping the new standard-library
implementation local avoids making dead code a dependency. ADR-001 P6 remains
the owner of deterministic ranking and benchmark execution; this scorer
consumes P6's canonical run artifact and does not implement a second search
runner.

### 3. Use a typed assessment contract

Every check result contains:

```json
{
  "id": "engine.scoped_coverage",
  "dimension": "engine_correctness",
  "mode": "required",
  "status": "pass",
  "score_bps": 10000,
  "criterion": {"op": "eq", "value": 10000},
  "reason_code": "DECLARED_UNIVERSE_COMPLETE",
  "numerator": 1,
  "denominator": 1,
  "exclusions": {},
  "evidence": []
}
```

Allowed statuses are:

| Status | Numeric treatment | Required-check gate treatment |
|---|---|---|
| `pass` | Include `score_bps` | Satisfied |
| `fail` | Include `score_bps` | Known gate failure |
| `unknown` | `score_bps=null` | Indeterminate |
| `error` | `score_bps=null` | Indeterminate; collector/evaluator fault |
| `not_applicable` | Exclude only with a policy applicability rule and evidence | Neutral |
| `skipped` | Never silently exclude | Indeterminate unless advisory |

Scores use integer basis points from 0 through 10,000. No floating-point value,
NaN, or infinity is valid in a canonical assessment.

### 4. Use a non-compensating gate

Gate precedence is deterministic:

1. Any known required `fail` makes the decision `fail`.
2. Otherwise, any missing required result or required `unknown`, `error`, or
   `skipped` makes the decision `indeterminate`.
3. Only a complete set of applicable required checks can produce `pass`.
4. A known failure plus unresolved evidence remains `fail`, with
   `complete=false` and both kinds of blocker preserved.
5. Advisory checks never change the gate.

A scalar score can never convert `fail` or `indeterminate` to `pass`.

### 5. Publish exact, observed, and bounded scores

For non-negative integer numerator `n` and denominator `d`, a proportional
score is rounded half up:

```text
score_bps = round_half_up(10000 * n / d)
```

For weighted checks, policy weights are positive integers and the score is:

```text
round_half_up(sum(weight * score_bps) / sum(weight))
```

Raw counts are aggregated before deriving a ratio whenever a metric supplies
counts. Child grades are never averaged.

If any score-eligible check is unresolved:

- exact `score_bps` is `null`;
- `observed_score_bps` reports the known-only diagnostic;
- `lower_bound_bps` treats unresolved scores as zero;
- `upper_bound_bps` treats unresolved scores as 10,000;
- included and eligible weights expose evidence coverage.

Each dimension is scored first. The overall diagnostic gives each configured
dimension its explicit versioned weight, so adding checks to one dimension does
not silently increase that dimension's influence. The first policy uses equal
weights unless a separately reviewed policy change supplies evidence for a
different choice.

The old display bands may be rendered for continuity:

- 0-3999: critical
- 4000-5999: serious
- 6000-7999: fair
- 8000-10000: good

Bands are display metadata, never gate conditions.

### 6. Score four subjects through six dimensions

| User question | Dimension | Required evidence |
|---|---|---|
| Is the engine implemented correctly? | `engine_correctness` | Offline tests collected and passed; repeated output byte identity; deterministic total ordering; provenance validation; scoped coverage invariant; global no-exhaustiveness invariant; retired surfaces absent when ADR-001 removal is complete. |
| Does the output find the right code? | `output_effectiveness` | Pinned scoped benchmark, exact query set, qrels, complete coverage, per-task metrics, language strata, no duplicate result IDs. |
| Is the code maintainable and adequately tested? | `code_health` and `test_adequacy` | Parser success; complexity maxima/distributions; raw line and branch coverage; mutation categories; clean test control; no missing production-file measurements. |
| Is project work governed and supplied safely? | `process_supply_chain` | Specific OpenSSF/raw GitHub checks for CI, review, branch protection, dependency updates/pins, vulnerabilities, fuzzing, and signed release provenance. |
| Is the engine operationally efficient? | `performance_operability` | Controlled offline benchmark comparison, environment fingerprint, samples, baseline, package/install smoke, stable process exits. Live network latency remains advisory. |
| What is the overall engine state? | All configured dimensions | Independent gate vector plus complete diagnostic score or honest bounds. |

ISO/IEC 25010 characteristics may be attached as classification metadata, but
the standard's names do not create evidence and are not themselves a formula.

### 7. Evaluate search output with pinned qrels

ADR-001 P6 will produce a versioned benchmark run. The initial corpus contains
at least 12 scoped tasks, four each for Python, Rust, and Go, at immutable
commits. Global discovery is a separate observational suite because global
recall is unknowable by contract.

Canonical result identity is the full `SourceRef` tuple:

```text
(slug, commit_sha, path, blob_sha, start_line, end_line)
```

Qrels use:

- `2`: exact target implementation or definition;
- `1`: valid alternate or directly useful supporting span;
- `0`: judged wrong.

Every scored task requires at least one grade-2 target. Missing task IDs are an
evaluation error; a present task with an empty result list is valid and scores
zero. Duplicate result IDs are rejected.

The authoritative metrics are calculated through pinned
`ir_measures==0.4.3` and `pytrec-eval-terrier==0.5.10`:

- primary diagnostic: linear-gain `nDCG@10`;
- exact-target diagnostics: reciprocal rank at 10 and Success at 1, 5, 10;
- useful-target diagnostic: Recall at 10;
- Precision at 5/10 and AP at 10 only for sufficiently complete qrels.

Before evaluation, P6 must provide a total order:

```text
(-normalized_score, slug, commit_sha, path, blob_sha, start_line, end_line)
```

The adapter passes unique rank scores to pytrec so trec_eval's equal-score
document-ID ordering cannot change Leitir's order.

Initial hard conditions are contract facts, not an invented mean:

- exact manifest query-set equality;
- complete scoped coverage for every task;
- byte-identical results across repeated runs and input permutations;
- at least one grade-2 result within the manifest's required cutoff for every
  required task;
- no language or predicate stratum silently omitted.

Metric floors and baseline ratchets are adopted in a separate, reviewable
baseline change after the corpus exists. A baseline change cannot be bundled
with an engine implementation change.

### 8. Treat code metrics as bounded evidence

Radon supplies cyclomatic complexity facts. Leitir reports maxima,
distributions, and parser coverage. A parse failure is `error`, not an omitted
file. Maintainability Index is diagnostic-only and excluded from the overall
score in policy v1.

coverage.py supplies raw JSON counts. Leitir gates line and branch ratios
separately with exact integer cross-multiplication, not rounded percentages.
Zero statements or zero branch exits are `not_applicable` only when the
versioned scope proves there can be none; otherwise evidence is `unknown`.

Mutation uses mutmut's raw outcome categories. Leitir computes:

```text
K = valid mutants killed by an expected test failure
S = valid mutants whose tests passed
U = runnable mutants with no associated test
D = K + S + U
mutation_score = 10000 * K / D
```

`D == 0` is not a perfect score. It is `not_applicable` only for a proven
non-mutable scope and otherwise `unknown`. Timeouts, crashes, internal errors,
suspicious exits, and pending mutants remain unresolved and block a required
pass. Equivalent/invalid mutants require reason-coded exclusions.

Absolute floors and baseline ratchets for coverage, complexity, and mutation
are versioned policy, adopted separately after a measured baseline. The scorer
must never change a policy or baseline to make a run pass.

### 9. Consume OpenSSF evidence, not its aggregate

The release profile may execute a checksum-verified OpenSSF Scorecard binary
or consume its raw JSON from a pinned snapshot. It normalizes these specific
facts:

- CI tests on changes;
- branch protection;
- code review;
- dependency update tooling;
- immutable dependency and workflow pins;
- vulnerability findings;
- fuzzing/property-test evidence;
- signed release and provenance evidence.

The OpenSSF aggregate is discarded. Authentication scopes, repository commit,
Scorecard version/commit, observation time, and raw artifact digest are stored.
Heuristic 0/10 checks do not automatically become Leitir hard gates; policy
interprets each raw finding.

DORA deployment frequency, lead time, change failure rate, and restore time are
not applicable while Leitir has no production deployment and incident event
stream. Commits, local Docker tests, and package releases must not be relabeled
as deployments. If that operating model changes, a later ADR can add DORA with
real event provenance and sample adequacy.

### 10. Gate performance only on controlled evidence

The performance adapter consumes pinned ASV output rather than reimplementing
its statistics. Baseline and candidate run interleaved on the same controlled
runner, with matching benchmark version and environment fingerprint.

Policy v1 identifies a regression candidate when:

```text
candidate_median > baseline_median * 1.10
```

Exactly 1.10x passes the magnitude test. A hard regression requires both the
material slowdown and a two-sided Mann-Whitney `p < 0.002`, with at least six
valid samples per side. A material but statistically inconclusive result is
`unknown`, not pass. A candidate functional failure after a successful
baseline is a known failure. Missing baseline, changed benchmark version,
runner mismatch, insufficient samples, or harness errors are unresolved.

Live GitHub and registry latency is always advisory because network state is
outside the engine's control.

### 11. Bind every assessment to provenance

The canonical assessment contains:

- repository URL and exact commit SHA;
- clean/dirty state; release profile requires clean;
- for a development dirty tree, a canonical patch plus untracked-input digest;
- producer script version and source commit;
- policy ID and SHA-256 digest;
- benchmark version and manifest digest;
- exact tool names, versions, source revisions, and configuration digests;
- raw evidence artifact SHA-256 digests;
- command argument arrays, process exits, and collector reason codes;
- source paths, blob digests, and line spans where available;
- observation window and authentication capabilities for live evidence.

Checks, evidence, blockers, and maps are sorted by defined keys. JSON is compact,
UTF-8, `sort_keys=True`, and `allow_nan=False`; canonical assessment uses only
integers for scores. SHA-256 of those bytes is the assessment identity.

Volatile host timing and log paths live in a run envelope whose subject is the
canonical assessment digest. A later slice may wrap the assessment in an
in-toto statement and sign it with DSSE/cosign; signing is not required for the
first executable score.

### 12. Use explicit profiles and exits

`offline` requires only locally collectible deterministic evidence. Network
checks are not silently considered healthy; they are outside that profile's
required set and remain visible as uncollected advisory facts.

`release` includes offline checks, live provenance, GitHub process/supply-chain
evidence, approved performance baseline, and required test-adequacy evidence.
Only the release profile can claim release readiness.

Process exits are:

| Result | Exit |
|---|---:|
| Complete policy pass | 0 |
| Known policy failure | 1 |
| Malformed usage or invalid policy | 2 |
| Indeterminate evidence or collector/infrastructure error | 3 |

## Canonical output shape

The source artifact is JSON similar to:

```json
{
  "schema_version": "leitir-assessment-v1",
  "subject": {
    "repository": "https://github.com/anthonykewl20/leitir",
    "commit_sha": "0000000000000000000000000000000000000000",
    "worktree": "clean"
  },
  "producer": {
    "name": "leitir-score-engine",
    "version": "1",
    "commit_sha": "0000000000000000000000000000000000000000"
  },
  "policy": {
    "id": "leitir-offline-v1",
    "sha256": "0000000000000000000000000000000000000000000000000000000000000000"
  },
  "checks": [],
  "dimensions": [],
  "aggregate": {
    "decision": "indeterminate",
    "complete": false,
    "score_bps": null,
    "observed_score_bps": null,
    "lower_bound_bps": 0,
    "upper_bound_bps": 10000,
    "included_weight": 0,
    "eligible_weight": 1,
    "blockers": []
  }
}
```

HTML and concise terminal output are rendered from this artifact. They may not
add or alter scores. `docs/leitir-engine-scorecard-v2.html` remains a dated,
manual research snapshot and is never consumed as evidence.

## Policy and anti-gaming rules

1. Expected check IDs come from the versioned policy. Missing required checks
   become unresolved; deleting a failed check cannot improve an exact score.
2. Policy, benchmark qrels, baselines, exclusions, and future waivers are
   separately reviewable artifacts. They are not changed in the same slice as
   an implementation merely to get green.
3. Generated, vendored, fixture, and production scopes are declared explicitly.
   Measurement coverage is reported; unparsed files do not disappear.
4. Means are accompanied by extrema, distributions, counts, and coverage.
   Absolute critical thresholds prevent local failures from averaging away.
5. N/A requires a versioned applicability predicate plus evidence. Unsupported,
   unavailable, or unmeasured is not N/A.
6. Policy v1 has no waivers. A future waiver design requires scope, reason,
   approver, issue, expiry, and digest and cannot convert evidence to `pass`.
7. The scorer never downloads or auto-upgrades a tool. Version mismatch is an
   error. Scoring-only dependencies live in a separate hash-pinned lock.
8. The scorer never reads model credentials and has no model/provider adapter.

## Rejected alternatives

### Keep the manual or expert-panel scorecard

Rejected. It is useful editorial diagnosis but cannot be run, reproduced, or
made independent of reviewer judgment.

### Ask multiple LLMs and average their ratings

Rejected. More opinions do not turn an opinion into a deterministic metric.
It also reintroduces cost, model drift, and non-reproducibility.

### Use one weighted 0-10 average as release truth

Rejected. Compensatory averaging permits perfect documentation or process
scores to hide broken correctness, provenance, or output effectiveness.

### Use the OpenSSF aggregate as overall project health

Rejected. Its value depends on the selected checks and omits inconclusive
checks from the denominator. Specific raw findings and provenance are useful.

### Install SonarQube and accept its quality gate

Rejected for the initial tool. It is operationally heavy, source is LGPL, code
search output effectiveness is outside its scope, and missing measures can pass.

### Use Radon Maintainability Index or Xenon grade as code quality

Rejected. Empty code can grade perfectly; MI can improve through comments; a
mean hides severe outliers; parser errors can be skipped.

### Use coverage percentage as test quality

Rejected. Coverage is one evidence dimension, not behavior correctness. It is
paired with collected tests, contract tests, and mutation outcomes.

### Use BEIR, ranx, or CodeSearchNet as the authoritative evaluator

Rejected. Their missing-query, empty-input, unjudged-document, or tie-order
semantics do not meet Leitir's contract. `ir_measures` plus strict Leitir input
validation and total ordering is the selected path.

### Use SWE-bench resolution rate for current output

Rejected. SWE-bench measures generated repository patches. Leitir currently
returns ranked source spans. If a future harness generates code, its tests and
resolution status remain a separate gate.

### Add DORA metrics now

Rejected as not applicable. There is no production deployment denominator or
incident linkage. No activity must not be scored as excellent delivery.

### Make live GitHub latency a hard performance gate

Rejected. External network variance is not an engine regression signal.

## Non-goals

- This ADR does not change source acquisition, package fetching, repository
  resolution, or Tier-3 search. Evaluating `vercel-labs/opensrc` belongs to a
  separate ADR-001 follow-up and is intentionally excluded here.
- This ADR does not restore code synthesis or score generated code. A future
  generation harness requires its own behavioral correctness gate.
- This ADR does not make a release decision from an editorial 0-10 score.

## Consequences

### Positive

- Scoring can run with no LLM, model credential, Docker synthesis sandbox, or
  OpenRouter cost.
- Every number has code, policy, subject, and evidence provenance.
- Critical failures and missing evidence cannot be averaged away.
- Output effectiveness is measured with established IR formulas.
- Process, code, output, and engine health remain separable and explainable.
- HTML can be regenerated and independently checked against canonical JSON.

### Negative

- A complete release assessment requires more than `pytest`: pinned benchmark
  qrels, code-coverage data, mutation evidence, controlled performance samples,
  and live process/supply-chain evidence.
- Early release assessments will likely be `fail` or `indeterminate`. That is
  honest, not a scorer defect.
- Scores are comparable only with the same subject scope, policy digest,
  benchmark version, profile, and tool revisions.
- `ir_measures`/pytrec, Radon, coverage.py, mutmut, ASV, and OpenSSF add a
  separately pinned scoring toolchain. They do not become runtime dependencies.
- Process evidence can change because the GitHub snapshot changes; the evidence
  digest and observation time make that change visible.

## Work slices

Every slice has an offline happy path, offline sad path, deterministic golden
output, and a cumulative gate. Live collectors are opt-in and require both a
successful case and an unavailable/error case. A slice is not complete until
its documented gate is green.

- [x] R0: Inspect executable scoring systems and record the decision.
      Deliverable: this ADR with pinned source revisions, selected mechanics,
      rejected mechanics, licenses, and ownership boundaries.

- [x] S1: Assessment contracts, policy schema, and gate algebra.
      Implement typed statuses, required/advisory mode, integer basis-point
      scores, exact/observed/lower/upper aggregation, dimension aggregation,
      gate precedence, reason codes, and exits. Add
      `scorecard/policy-v1.json` and a strict schema. No collectors yet.
      Files: `tools/score_engine.py`, `scorecard/policy-v1.json`,
      `scorecard/assessment-v1.schema.json`, `tests/test_score_contracts.py`.
      Gate: hand-calculated aggregation fixtures, zero denominator, duplicate
      IDs, missing IDs, all statuses, and fail-plus-error precedence.

- [x] S2: Canonical evidence and subject provenance.
      Add clean commit identity, dirty development patch digest, policy/tool/raw
      artifact digests, stable ordering, canonical JSON, and assessment SHA-256.
      Release profile rejects dirty subjects. Policy cannot specify commands;
      subprocess collectors use fixed argv and `shell=False`.
      Files: `tests/test_score_provenance.py`,
      `tests/fixtures_score/provenance/`.
      Gate: permutations of maps/checks/evidence and different
      `PYTHONHASHSEED` values produce byte-identical JSON and digest; tampered
      evidence and non-finite values fail closed.

- [x] S3: Offline engine-correctness collectors.
      Collect pytest JUnit evidence, require nonzero collection and green
      execution, consume deterministic replay/permutation checks, validate
      result provenance, and verify scoped/global coverage invariants. Reuse
      ADR-001 gate commands; do not create a second search implementation.
      Files: `tests/test_score_engine_checks.py`,
      `tests/fixtures_score/engine/`.
      Gate: passing, failing, zero-test, malformed-JUnit, partial-coverage,
      global-overclaim, provenance-mismatch, and nondeterministic-output cases.

- [x] S4: P6 ranked-output effectiveness adapter.
      Depends on ADR-001 P6's ranked benchmark run artifact. Add at least 12
      scoped qrel tasks (4 Python, 4 Rust, 4 Go), canonical SourceRef IDs,
      strict task-set validation, total-order validation, and pinned
      `ir_measures`/pytrec scoring. The scorer consumes the artifact; P6 owns
      search execution and ranking.
      Files: `src/leitir/benchmarks/search-v1/`,
      `tests/test_score_retrieval.py`, `tests/fixtures_score/retrieval/`.
      Gate: hand-calculated rank-1/rank-3/missing vectors, multiple relevance
      grades, empty result, unjudged first result, duplicate ID, missing task,
      tie, language-stratum regression, and trec golden parity.

- [x] S5: Code-health and test-adequacy adapters.
      Consume pinned Radon and coverage.py JSON. Add parser/file-scope coverage,
      complexity maxima/distributions, exact line and branch counts, and
      mutmut outcome normalization with clean-control and sentinel evidence.
      Add a separate hash-pinned scoring dependency lock.
      Files: `requirements-score.txt`, `tests/test_score_code_health.py`,
      `tests/test_score_test_adequacy.py`, `tests/fixtures_score/code_health/`.
      Gate: parser error, unmeasured file, zero statements, zero branches, zero
      mutants, survived/no-test/timeout/crash/internal-error mutants, exact
      threshold equality, and policy-ratchet fixtures.

- [x] S6: Process and supply-chain adapter.
      Consume a checksum-verified OpenSSF Scorecard v5.5.0 raw artifact and
      normalize only selected checks. Record GitHub/token capabilities,
      repository and tool commits, observation time, and raw digest. Discard
      the OpenSSF aggregate. Offline tests use pinned real-shape fixtures; live
      collection is opt-in.
      Files: `tests/test_score_process.py`,
      `tests/test_score_process_live.py`, `tests/fixtures_score/openssf/`.
      Gate: known failure, inconclusive, API unavailable, unsupported,
      not-applicable, missing check, changed check set, insufficient auth, and
      fresh live happy/sad evidence.

- [x] S7: Controlled performance adapter.
      Consume pinned ASV/runner output, validate environment and benchmark
      versions, require adequate samples, and apply the 1.10 magnitude plus
      `p < 0.002` rule. Live network latency remains advisory.
      Files: `tests/test_score_performance.py`,
      `tests/fixtures_score/performance/`.
      Gate: exact 1.10 equality, significant regression, underpowered result,
      overlapping interval, missing baseline, runner mismatch, introduced
      functional failure, and benchmark-version mismatch.

- [x] S8: Deterministic HTML renderer and release profile.
      Render the canonical assessment without adding judgments. Unknown scores
      display as unknown with bounds, not zero. Add full offline and release
      profile e2e tests and document operation. Optionally emit an unsigned
      in-toto statement; signing remains a later change.
      Files: `tests/test_score_render.py`, `tests/test_score_e2e.py`,
      `tests/test_score_e2e_live.py`, `docs/scoring.md`.
      Gate: HTML values exactly match JSON; rendering the same assessment twice
      is byte-identical; process exits 0/1/2/3 are pinned; release cannot pass
      with any required unresolved evidence.

- [ ] S9: Dogfood on Leitir and retire the manual current score.
      Run the scorer against a clean pinned Leitir commit, publish canonical
      JSON plus generated HTML, add a regeneration drift check, and label the
      v1/v2 scorecards historical. Do not tune policy, exclusions, qrels, or
      baselines in this slice.
      Gate: a clean clone reproduces the same offline assessment digest; live
      differences are attributable to changed, hashed evidence snapshots.

## Required cross-cutting tests

The cumulative suite must prove all of the following:

- A 99/100 diagnostic cannot hide one required failure.
- A required unknown/error/skipped result cannot pass.
- A known failure plus unknown remains fail and preserves both blockers.
- Removing an unresolved or failed check cannot improve an exact score.
- Valid N/A is excluded; unsupported or unevidenced N/A becomes error.
- A zero denominator is null/unknown or proved N/A, never zero or perfect.
- Raw counts aggregate before ratios; rounded displays do not affect gates.
- Partial scoped coverage cannot produce an effectiveness pass.
- Global discovery can never claim exhaustive recall.
- Missing benchmark task IDs are errors; present empty outputs score zero.
- Per-language floors catch a regression hidden by a global mean.
- Equal-score search results have a stable provenance tie-break.
- No tests, unmeasured files, parse failures, and mutation infrastructure errors
  cannot improve any adequacy score.
- Missing/incompatible performance baseline and insufficient samples are
  unresolved, not pass.
- Permuting every unordered input produces byte-identical JSON, HTML, and
  assessment digest.
- Tool-version, policy, benchmark, subject, and evidence digest mismatches fail
  closed.
- The scoring environment has no LLM dependency or model credential path.

## Verification commands for the future implementation

```bash
# Deterministic unit and fixture gate
PYTHONPATH=src uv run --no-project --with-requirements requirements-score.txt \
  python -m pytest tests/test_score_*.py -m "not live"

# Offline assessment; no model and no network
python tools/score_engine.py run --profile offline \
  --json-out .leitir-score/assessment.json \
  --html-out .leitir-score/scorecard.html

# Live release evidence; still no model
LEITIR_ENABLE_SCORE_LIVE=1 GH_TOKEN="$(gh auth token)" \
  python tools/score_engine.py run --profile release
```

Until these artifacts and gates exist, any new overall 0-10 Leitir score remains
an editorial assessment and must be labeled non-executable.
