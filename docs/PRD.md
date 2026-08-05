# Product Requirements Document (PRD): Leitir

> **Historical — describes the retired v1 product.** The Hy3 synthesis pipeline
> this PRD specifies was deleted in ADR-001 slice P0r. Leitir is now a
> deterministic code-search kernel with no model calls, no synthesis, and no
> runtime dependencies. Current design lives in
> [ADR-0001](adr/0001-remove-hy3-deterministic-search.md) and
> [ADR-0002](adr/0002-deterministic-evidence-scoring-engine.md). Kept for the
> requirement history — the Tier 1–3 evidence model and the >100-star Tier 3
> gate are the reasoning behind decisions the kernel still inherits.

**Product:** Leitir  
**Descriptor:** Agentic Technical Search and Code Synthesis Engine  
**Stage:** Prototype

## References

- [OpenRouter API: `tencent/hy3`](https://openrouter.ai/api/v1/models/tencent/hy3/endpoints)
- [OpenRouter model page: Tencent HY 3](https://openrouter.ai/tencent/hy3)
- [docs.rs](https://docs.rs/)
- [pkg.go.dev](https://pkg.go.dev/)
- [GitHub Code Search API](https://docs.github.com/en/rest/search/search#search-code)
- [SearXNG](https://docs.searxng.org/)
- [Trafilatura](https://trafilatura.readthedocs.io/)
- [Docker](https://docs.docker.com/)

---

## 1. Executive Summary and Goals

### 1.1 Problem Statement

Single-pass technical search often returns shallow or stale evidence. For complex programming tasks, this can produce deprecated syntax, invented parameters, missed edge cases, and code that was never executed.

Poor observability compounds the problem. Without step-level traces, evaluators cannot tell whether a failure came from query expansion, discovery, extraction, synthesis, or verification.

### 1.2 Core Objective

Build a lightweight autonomous orchestrator that uses a five-step workflow to:

1. ground syntax and API contracts in official documentation;
2. learn implementation logic and edge cases from source code;
3. synthesize target-language code with `tencent/hy3` through OpenRouter; and
4. verify the result in an isolated Docker sandbox.

The prototype must also record enough telemetry to measure retrieval quality, locate failures, replay trajectories, and optimize latency, token use, and cost.

### 1.3 Product Boundaries

Leitir is the product, `tencent/hy3` is the model, and OpenRouter is the model provider. These entities must remain distinct in code, configuration, traces, and documentation.

The prototype is an orchestrator, not a new search engine, model host, or general-purpose build platform. Its scope is the search, synthesis, verification, and evaluation loop defined below.

---

## 2. High-Level System Architecture

```text
                                  +-----------------------+
                                  |     USER REQUEST      |
                                  +-----------+-----------+
                                              |
                                              v
+-----------------------------------------------------------------------------------+
|                            ORCHESTRATOR HARNESS                                   |
|                      Python preferred; Go supported                              |
|                                                                                   |
|   +--------------------------+               +--------------------------------+   |
|   |   Five-Step State Loop   | <-----------> | tencent/hy3 via OpenRouter     |   |
|   | - Query expansion        |               | Step 1: omit reasoning_effort  |   |
|   | - Door prioritization    |               | Steps 2-3: no model call       |   |
|   | - Repair routing         |               | Steps 4-5/reviews: high        |   |
|   +------------+-------------+               | include_reasoning: false       |   |
|                                               +--------------------------------+   |
+----------------|------------------------------------------------------------------+
                 | Tool commands                        | Responses and usage
                 v                                      v
+------------------------------------+    +-----------------------------------------+
|        EXTERNAL TOOL STACK         |    |      OBSERVABILITY AND EVAL ENGINE      |
| +-------------------------------+  |    | - Structured step-level traces          |
| | SearXNG / DuckDuckGo          |  |    | - Trajectory dumps and replay           |
| | GitHub REST / raw CDN         |  |    | - Latency, token, and cost profiling    |
| | GitIngest / Trafilatura       |  |    | - SER, DRI, FPCR, and SCCR evals        |
| | Readability / AST sanitizer   |  |    +-----------------------------------------+
| +-------------------------------+  |
+----------------+-------------------+
                 |
                 v
+-----------------------------------------------------------------------------------+
|                            LOCAL DOCKER SANDBOX                                   |
|                      Ephemeral execution and verification                         |
|                                                                                   |
|   Runs `cargo test`, `go test`, or `pytest`; captures exit code, stdout, stderr,  |
|   compiler diagnostics, test results, and timeout state.                          |
+-----------------------------------------------------------------------------------+
```

The model configuration shown here is normative: no-think means omitting the top-level `reasoning_effort` field. Step 4, Step 5 repair, and every Hy3 review set it to `"high"`.

Python is the preferred prototype language because the reference integration is Python and uses the standard library. Go remains a supported implementation option.

---

## 3. Four-Tier Door Hierarchy

The hierarchy orders evidence by authority and access cost. Discovery may query Tiers 1–3 together, but selection and conflict resolution must prefer the highest available authoritative tier. Tier 4 is a fallback.

### Tier 1: Official Provider Documentation and OpenAPI Specifications

**Check:** Official API portals, `openapi.json`, and `/llms.txt`.  
**Objective:** Ground API parameters, headers, authentication, response shapes, and version behavior in first-party sources.

### Tier 2: Target-Language Standard Documentation

**Check:** Canonical language and package references such as docs.rs and pkg.go.dev.  
**Objective:** Confirm ecosystem conventions, package versions, type signatures, and supported syntax.

### Tier 3: GitHub Cross-Language Code Search

**Check:** GitHub Code Search at `api.github.com/search/code`.  
**Objective:** Extract control flow, state transitions, error handling, and edge-case logic from real implementations.

Tier 3 may inform logic, but it must not override a conflicting Tier 1 API contract or Tier 2 language contract.

### Tier 4: Headless-Browser Fallback

**Check:** Headless Chrome or Selenium, using tools such as `thirtyfour` for Rust or Playwright for Go.  
**Objective:** Retrieve client-rendered or dynamically hydrated content that direct HTTP extraction cannot recover.

### Door-Selection Rule

Use the earliest tier that provides sufficient, current evidence. Open a lower-priority tier when a higher tier is unavailable, incomplete, inaccessible, or lacks the implementation detail needed for the request.

When sources conflict, retain both in the trace and follow the higher-authority source. A lower-priority implementation example may explain behavior but cannot redefine an official contract.

---

## 4. Detailed Five-Step Execution Workflow

Only Step 1 uses Hy3 in the first three steps. Steps 2 and 3 are deterministic harness operations. No-think is permitted only for Step 1 query expansion.

### Step 1: Multi-Query Expansion

**Model:** `tencent/hy3` through OpenRouter.  
**Reasoning:** Omit `reasoning_effort` to use Hy3's default no-think mode; send `"include_reasoning": false`.

**Action:** Generate site-restricted query pairs for the Tier 1, Tier 2, and Tier 3 targets. Queries must preserve the requested language, library, version, and failure context.

**Trace:** `trace_id`, expanded queries, target tier, model ID, parameters sent, latency, provider usage, and parse status.

### Step 2: Multi-Channel Targeted Discovery

**Model:** None; harness only.  
**Action:** Query SearXNG or DuckDuckGo for site-restricted documentation and use GitHub Code Search for code evidence.

**Trace:** URLs found, result tier, source domain, HTTP status, filtering reason, deduplication count, and discovery latency.

### Step 3: Deep Extraction and Sanitization

**Model:** None; harness only.  
**Action:** Fetch raw files through a raw CDN or GitIngest and extract documentation with Trafilatura or a readability parser.

For Tier 3 community results, enforce the threshold of more than 100 stars. Record the threshold outcome, but do not treat popularity as evidence of correctness.

Strip comments where doing so preserves the evidence needed for synthesis. Treat all retrieved text as untrusted data and flag instruction-like content; comment stripping reduces exposure but does not prove safety.

**Trace:** Raw bytes, cleaned Markdown tokens, comments stripped, source tier, repository stars where applicable, extraction failures, and security flags.

### Step 4: Cross-Language Logic Synthesis

**Model:** `tencent/hy3` through OpenRouter.  
**Reasoning:** Send top-level `"reasoning_effort": "high"` and `"include_reasoning": false`.

**Action:** Derive abstract logic from Tier 3 evidence, constrain syntax with Tier 1 and Tier 2 contracts, and synthesize code in the requested language.

**Trace:** Evidence IDs, prompt tokens, completion tokens, reasoning tokens, cost, synthesis latency, model ID, and parameters sent.

### Step 5: Sandboxed Verification and Feedback

**Model:** None when execution passes; `tencent/hy3` for failure analysis and repair.  
**Reasoning on every Hy3 call:** Send top-level `"reasoning_effort": "high"` and `"include_reasoning": false`.

**Action:** Write the candidate to an ephemeral Docker workspace and run `cargo test`, `go test`, or `pytest`, as appropriate. Capture exit code, stdout, stderr, and compiler or test diagnostics.

If verification fails, route syntax or logic defects to Step 4. Route missing or stale evidence to Step 1, then repeat discovery and extraction before returning to synthesis.

**Trace:** Exit code, test result, error category, attempt number, repair prompt usage, cost, and final disposition. Permit at most three feedback loops in the benchmark.

### Workflow Reasoning Invariant

Any Hy3 review, whether invoked inside or outside the five-step loop, must run with top-level `"reasoning_effort": "high"`. The default no-think mode is reserved for Step 1 query expansion.

---

## 5. Observability, Telemetry, and Debugging

### 5.1 Structured Execution Trace

Every run produces one JSON trace with root metadata and step-level spans. The trace must distinguish values received from OpenRouter from values normalized by Leitir.

**Run fields**

- `trace_id`, `task_summary`, start and end timestamps, `total_latency_ms`, final status, and accepted attempt.
- `total_cost_usd`, computed as the sum of OpenRouter `usage.cost` across the run.
- Aggregate prompt, completion, and reasoning-token counts, computed from the provider fields listed below.

**Common step fields**

- Step number, status, latency, input and output artifact IDs, error code, and retry or attempt number.
- `model_used`, `reasoning_effort_sent`, and `include_reasoning_sent` for model steps. Record the effort field as absent when it was omitted.
- Discovery counts, extracted bytes, cleaned tokens, comments stripped, and security flags for tool steps.
- Sandbox exit code, `test_passed`, stdout reference, stderr reference, and timeout state for Step 5.

**OpenRouter usage mapping**

| Leitir field | OpenRouter response field |
|---|---|
| `cost_usd` | `usage.cost` |
| `prompt_tokens` | `usage.prompt_tokens` |
| `completion_tokens` | `usage.completion_tokens` |
| `reasoning_tokens` | `usage.completion_tokens_details.reasoning_tokens` |

Expect `reasoning_tokens` to be approximately zero for the Step 1 no-think call and greater than zero for high-reasoning calls, subject to the provider response.

Token fields must not be inferred from text length when the provider reports them. Missing provider fields remain null and are flagged; they must not be silently converted to zero.

### 5.2 Error Attribution Taxonomy

| Error code | Owner | Meaning |
|---|---|---|
| `ERR_EXPANSION_MALFORMED` | Step 1 / model | Query expansion could not be parsed or violated its schema. |
| `ERR_SEARCH_ZERO_RESULTS` | Step 2 / tool | All configured discovery channels returned no usable result. |
| `ERR_SCRAPE_BOILERPLATE_LEAK` | Step 3 / tool | Extracted content retained material boilerplate. |
| `ERR_SECURITY_PROMPT_INJECTION` | Step 3 / guardrail | Retrieved content contained instruction-like or otherwise unsafe text. |
| `ERR_SYNTAX_COMPILATION_FAIL` | Step 5 / sandbox | The candidate did not compile or parse. |
| `ERR_VERIFICATION_TIMEOUT` | Step 5 / sandbox | Compilation or tests exceeded the configured execution timeout. |

This taxonomy preserves the failure classes while making the responsible step and subsystem explicit.

### 5.3 Trajectory Replay and Diffs

Write an execution replay record that references exact prompts, tool outputs, cleaned evidence, model responses, and step configuration. It must support replay from Step 3 or Step 4.

Replay artifacts must redact credentials and authorization headers. The configured credential path may be recorded, but its contents and the API key must never enter a trace.

Track the generated-code diff between Step 5 attempts so evaluators can see whether a repair addressed the reported failure or repeated it.

---

## 6. Evaluation Suite and Inefficiency Metrics

### 6.1 Benchmark Tasks

The benchmark contains 50 version-sensitive or API-breaking-change tasks: 20 Rust, 15 Go, and 15 Python. Each task records its target dependency version and evidence date.

Each task ships with a Dockerfile and a hidden `eval_test` suite that is unavailable during generation. The suite is revealed only to the evaluation harness during Step 5.

### 6.2 Key Performance Indicators

| KPI | Unambiguous definition | Prototype goal |
|---|---|---|
| Search Efficiency Ratio (SER) | Tokens from unique, cleaned source chunks retained in the first Step 4 synthesis prompt ÷ tokens in all unique, cleaned candidate chunks produced by Step 3 before selection. It excludes instructions, model output, and final emitted code. | `SER > 0.25` |
| Door Resolution Index (DRI) | Distribution by the lowest-priority door required for the accepted solution: Tier 1 alone; Tiers 1–2; Tiers 1–3; or Tier 4 browser fallback. Merely retrieving unused lower-tier results does not change the tier. | At least 80% resolved at Tier 1 or Tier 2 |
| First-Pass Compilation Rate (FPCR) | Tasks whose first Step 5 attempt passes the complete hidden test suite ÷ all valid benchmark tasks started. Infrastructure-invalid runs are reported separately. | `FPCR > 0.70` |
| Self-Correction Convergence Rate (SCCR) | Tasks that fail the first valid Step 5 attempt but pass within the next three repair loops ÷ tasks with a valid first-pass failure. Infrastructure failures are excluded and reported separately. | `SCCR > 0.85` within three loops |

SER measures retained retrieval evidence, not tokens in the generated source file. This distinction makes selection efficiency measurable independently of code verbosity.

### 6.3 Automated Inefficiency Diagnosis

| Observed pattern | Likely cause to test | Required investigation |
|---|---|---|
| High latency and `SER < 0.10` | Extraction retained too much irrelevant page content. | Inspect Step 3 documents, cleaning, deduplication, and chunk selection. |
| Low FPCR with heavy Tier 3 dependence | Implementation syntax may have displaced official contracts. | Check whether Steps 1–3 found and retained Tier 1 and Tier 2 evidence. |
| SCCR does not improve across attempts | Repair prompts may omit diagnostics or repeat an ineffective edit. | Confirm Step 5 stderr, error category, evidence, and prior diff reached the next Step 4 call. |

These rules identify investigation starting points, not proven root causes. Each diagnosis must link back to the trace fields that triggered it.

---

## 7. Functional Requirements and Technical Specifications

### 7.1 Orchestrator and OpenRouter Client

**Language.** Implement the prototype in Python by default because the working reference uses Python standard-library `urllib`. Go is acceptable if it preserves the same HTTP contract.

**Transport.** Send raw HTTP `POST` requests to `https://openrouter.ai/api/v1/chat/completions` with `Content-Type: application/json`. No SDK is required.

**Authentication.** Send `Authorization: Bearer <key>`. Load the key from the `openrouter` entry in `~/.local/share/opencode/auth.json`, accepting `key`, `apiKey`, or `api_key`.

The implementation must never hardcode, log, or serialize the key into traces. It must not invent a second credential source for the prototype.

**Model.** Use the exact model ID `tencent/hy3`. A separate `tencent/hy3-preview` listing exists, but it is not the configured Leitir model.

**Timeout.** The reference calls use a 900-second HTTP timeout. Mirror that value as the prototype default while recording timeout failures in Step 5 or the calling model step.

**Observed baseline request.** The current local calls send this body shape, with no reasoning selector:

```json
{
  "model": "tencent/hy3",
  "messages": [
    {
      "role": "user",
      "content": "..."
    }
  ],
  "temperature": 0,
  "max_tokens": 20000
}
```

Those existing calls therefore use Hy3's default no-think mode. Leitir must add the top-level fields required by the workflow policy below.

**Accepted parameters.** OpenRouter currently lists these parameters for `tencent/hy3`:

- Sampling and penalties: `frequency_penalty`, `min_p`, `presence_penalty`, `repetition_penalty`, `temperature`, `top_k`, and `top_p`.
- Tokens and stopping: `max_completion_tokens`, `max_tokens`, and `stop`.
- Reasoning: `include_reasoning`, `reasoning`, and `reasoning_effort`.
- Output and determinism: `response_format`, `seed`, and `structured_outputs`.
- Tools: `tool_choice` and `tools`.

Leitir must send only listed parameters and must keep raw-HTTP parameters at the top level of the JSON body.

**Reasoning control.** OpenRouter's effort ladder is `minimal`, `low`, `medium`, and `high`. Hy3 advertises default no-think plus low and high reasoning modes.

For Hy3, no-think is selected by omitting `reasoning_effort`; there is no `"no_think"` value. `include_reasoning` controls whether reasoning text is returned, not how much reasoning the model performs.

Leitir uses the following normative mapping:

| Workflow use | Hy3 invocation | Top-level `reasoning_effort` | Top-level `include_reasoning` |
|---|---|---|---|
| Steps 1–3 | Step 1 query expansion only; Steps 2–3 make no model call | Omit | `false` on Step 1 |
| Step 4 synthesis | Required | `"high"` | `false` |
| Step 5 verification repair | Conditional on execution or test failure | `"high"` | `false` |
| Every other Hy3 review | Whenever a review is requested | `"high"` | `false` |

Setting `include_reasoning` to `false` keeps response payloads lean while provider usage can still report reasoning tokens. It does not downgrade a `"high"` request.

### 7.2 External Tool Integrations

| Capability | Prototype integration | Requirement |
|---|---|---|
| Web search | SearXNG or DuckDuckGo | Support site-restricted discovery; SearXNG may use `http://localhost:8080/search?format=json`. |
| GitHub search | `api.github.com/search/code` | Return repository and file metadata needed for Tier 3 filtering and traceability. |
| Raw code retrieval | `raw.githubusercontent.com/{owner}/{repo}/{branch}/{file}` or GitIngest | Preserve source URL, revision when available, and retrieval status. |
| Documentation extraction | Trafilatura or a readability implementation | Emit cleaned Markdown and extraction metrics for Step 3. |
| Telemetry | OpenTelemetry-compatible spans plus JSON output | Emit the schema in Section 5 without exposing credentials. |

### 7.3 Sandbox Execution

Use an ephemeral Docker workspace for generated files and tests. Select `cargo test`, `go test`, or `pytest` from the requested language and capture the full verification result.

The sandbox result, rather than model confidence, determines whether an attempt passes. A model repair is allowed only after the failed execution evidence has been recorded.

---

## 8. Success Metrics and Verification Criteria

The prototype is successful when it satisfies all of the following:

1. **Search efficiency:** SER exceeds 25% under the definition in Section 6.2.
2. **Evidence quality:** At least 80% of accepted benchmark tasks resolve at Tier 1 or Tier 2 under the DRI definition.
3. **First-pass correctness:** FPCR exceeds 70% on valid benchmark runs.
4. **Self-correction:** SCCR exceeds 85% within three repair loops after a valid first-pass failure.
5. **API accuracy:** No emitted API parameter contradicted by the official contract is accepted as valid; the target is 0% hallucinated parameters in audited outputs.
6. **Failure observability:** 100% of failed runs have a complete trace, attributed error, replay references, and attempt diffs.
7. **Cost:** Mean OpenRouter `usage.cost` per completed benchmark task remains below USD 0.02.
8. **Reasoning policy:** Step 1 omits `reasoning_effort`; Steps 4–5 and every Hy3 review send `"reasoning_effort": "high"`.
9. **Integration fidelity:** Requests use the endpoint, model ID, Bearer authentication, credential source, and usage fields specified in Sections 5 and 7.

All metric reports must include numerator, denominator, excluded-run count, and benchmark version. A percentage without those values does not satisfy verification.
