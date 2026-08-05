# Leitir v1 operations guide

> **Historical — describes the retired v1 prototype.** ADR-001 slice P0r deleted
> the pipeline this guide operates: there is no orchestrator, Docker sandbox,
> SearXNG dependency, or OpenRouter credential any more, and the `leitir run` /
> `leitir eval` commands it documents were removed in P4. The kernel exposes
> `leitir search` and runs on the standard library alone. See
> [ADR-0001](adr/0001-remove-hy3-deterministic-search.md).

This guide describes the shipped prototype, not the broader target design.
Leitir v1 is design-stage software and should not be treated as a production
service or a security boundary for hostile multi-tenant workloads.

## 1. Setup

### Required services

Leitir's default composition expects:

- Python 3.11 or newer;
- a Docker daemon available through the normal Docker client environment;
- a local, unauthenticated SearXNG JSON API at
  `http://localhost:8080/search`;
- anonymous access to `https://api.github.com/search/code` and raw GitHub
  content; and
- access to OpenRouter and the Docker/Python package registries.

V1 sends no authorization header to SearXNG or GitHub. GitHub's anonymous rate
limits therefore apply. There is no shipped DuckDuckGo fallback or GitHub-token
configuration.

### Pinned installation

`requirements.txt` is the fully pinned development and runtime dependency
closure. From the repository root:

```bash
python -m venv .venv
. .venv/bin/activate
python -m pip install -r requirements.txt
python -m pip install --no-build-isolation --no-deps -e .
leitir --help
```

The second install uses the already pinned build dependencies and registers
the `leitir = leitir.cli:main` console script.

### OpenRouter credential

The only supported credential document is:

```text
~/.local/share/opencode/auth.json
```

It must contain an `openrouter` object with `key`, `apiKey`, or `api_key`. If
more than one alias is present, the values must be identical. For example,
using a non-secret placeholder:

```json
{
  "openrouter": {
    "key": "REDACTED"
  }
}
```

No environment-variable, CLI, or alternate-file credential source is
implemented. Do not paste a key into `--task`, logs, traces, test fixtures, or
bug reports. Keep the auth document out of version control and limit its file
permissions. The client reads the value only when making a request, puts it in
the `Authorization: Bearer ...` header, and does not intentionally log or
serialize it. Errors and trace values pass through redaction, but operators
must still avoid supplying secrets as task data.

## 2. CLI

The verified command surface is:

```text
usage: leitir [-h] {run,eval} ...
usage: leitir run [-h] --task TASK [--language {python}]
usage: leitir eval [-h]
```

There are no config-file flags, output flags, replay command, dry-run flag, or
fixture mode in v1.

### Run one task

```bash
leitir run --task "TASK DESCRIPTION"
leitir run --task "TASK DESCRIPTION" --language python
```

`--task` is required and must not be blank. `--language` defaults to `python`;
no other value is accepted. A real run uses SearXNG, GitHub, OpenRouter, and
Docker and may incur provider charges.

After a completed run, stdout reports:

```text
status=DISPOSITION trace=/home/user/.local/state/leitir/traces/FILE.json
```

Traces are stored under `~/.local/state/leitir/traces/`. If trace persistence
itself fails, the CLI writes the JSON trace to stdout, reports the persistence
error on stderr, uses `trace=stdout`, and returns an infrastructure failure.
An error before an orchestrator result exists can return without a trace.

### Run the smoke evaluation

Evaluation is an explicitly paid/live operation:

```bash
LEITIR_ENABLE_LIVE_EVAL=1 leitir eval
```

Without that exact opt-in, `leitir eval` returns exit 3 before the evaluation
driver runs. A live evaluation prints each task's status/trace line, then the
JSON report, then `status=accepted trace=driver-managed` if the driver itself
completed. That final status means evaluation execution completed; it does
not mean every benchmark task passed. Details are in
[smoke-evaluation.md](smoke-evaluation.md).

### Exit codes

| Exit | Meaning |
|---:|---|
| 0 | `run` accepted the candidate, or the evaluation driver completed |
| 1 | task failed or exhausted its repairs |
| 2 | malformed CLI usage |
| 3 | infrastructure/configuration failure, including gated `eval` |
| 4 | run stopped after observing a spend-cap breach |
| 130 | cancelled run |

The run-level JSON `final_status` is one of `accepted`, `failed`,
`repair_exhausted`, `spend_cap_exceeded`, `infrastructure_error`, or
`cancelled`.

## 3. Workflow, evidence authority, and model policy

### Five steps

1. **Query expansion:** Hy3 creates site-bound queries covering all three
   evidence tiers.
2. **Discovery:** SearXNG searches Tier 1–2 documentation; anonymous GitHub
   Code Search finds Tier 3 candidates.
3. **Extraction:** Leitir fetches and cleans content, deduplicates it, strips
   Python comments from Tier 3 where possible, requires more than 100 GitHub
   stars, and quarantines instruction-like retrieved text. Retrieved pages and
   source are untrusted data.
4. **Synthesis:** Hy3 receives retained evidence and emits a Python candidate
   with citations to evidence chunks.
5. **Verification and feedback:** Docker runs `pytest`. Syntax or logic
   failures route to repair. A missing/stale-evidence classification routes
   back through Steps 1–3 before repair.

The configured limit is three feedback/repair loops. Thus there can be one
initial candidate plus at most three repaired candidates (attempts 1–4).
Timeout and sandbox-infrastructure failures terminate rather than consuming
unbounded repairs.

### Evidence authority

- **Tier 1:** official provider documentation and API contracts.
- **Tier 2:** canonical Python and package documentation.
- **Tier 3:** GitHub source examples for control flow and edge cases.

When evidence conflicts, the lower numbered, more authoritative tier wins.
Tier 3 can explain implementation behavior but cannot redefine a Tier 1 or
Tier 2 contract. Tier 4/headless-browser retrieval is not shipped.

### Exact `tencent/hy3` policy

Leitir sends raw HTTP `POST` requests to:

```text
https://openrouter.ai/api/v1/chat/completions
```

The model is fixed to `tencent/hy3`, authenticated with a Bearer header from
the credential source above. The default request timeout is 900 seconds, with
up to three transport attempts. Default generation values are
`temperature: 0` and `max_tokens: 20000`.

Hy3 recognizes the effort ladder `minimal`, `low`, `medium`, `high`, but the
v1 workflow uses only these two policies:

- Step 1 query expansion **omits** the top-level `reasoning_effort` field
  (the no-think behavior).
- Step 4 initial synthesis and every Step 5 repair send the top-level
  `reasoning_effort: "high"`.
- A review-purpose client method would also send `"high"`, but the v1
  workflow makes **zero internal Hy3 review calls**.
- Every call sends top-level `include_reasoning: false`.

There is no `no_think` value and requests do not use `extra_body`. Both are
rejected by the client rather than translated.

## 4. Spend control

`Config.per_run_spend_cap_usd` defaults to USD 0.05 and is capped at the
orchestrator run, not across a whole `leitir eval`. The CLI has no flag or
environment variable to change it; programmatic embedders may inject a
validated `Config`.

After each paid model span, Leitir adds the provider's reported `usage.cost`.
The stop condition is accumulated known cost **greater than** the cap, so the
triggering call can overshoot the limit. Once observed, no later paid workflow
step is started. A missing provider cost is recorded as missing, not assumed
to be zero; therefore the cap is not a prepaid guarantee when OpenRouter omits
cost data.

A breach produces `final_status: "spend_cap_exceeded"`, CLI exit 4, and a
`spend_cap_breach` object containing the configured cap, accumulated known
cost, triggering span/step/attempt, completeness, and indexes of spans with
missing cost.

## 5. Inspecting a PRD §5.1 trace

Capture the path printed by the CLI, then pretty-print and schema-validate it:

```bash
TRACE="$HOME/.local/state/leitir/traces/FILE.json"
python -m json.tool "$TRACE"
python -c 'import sys; from leitir import ExecutionTrace; t=ExecutionTrace.read_json(sys.argv[1]); print(t.trace_id, t.final_status.value)' "$TRACE"
```

Use the actual path from `trace=...`; `FILE.json` is only a placeholder.
`ExecutionTrace.read_json` validates schema version 1.0, types, artifact
references, aggregate usage, and spend-breach consistency.

### Root and spans

Start with:

- `trace_id`, redacted `task_summary`, timestamps, `total_latency_ms`,
  `final_status`, and `accepted_attempt`;
- `spans[]` in execution order, using numeric `step` values 1–5;
- each span's `status`, `latency_ms`, `attempt_number`, `retry_number`,
  input/output artifact IDs, and optional `error_code`;
- step-specific `expansion`, `discovery`, `extraction`, `security`,
  `synthesis`, `sandbox`, and `model` objects.

For a model span, verify `model_used`,
`reasoning_effort_was_sent`, `reasoning_effort_sent`, and
`include_reasoning_sent` against the policy above. For verification, inspect
`sandbox.exit_code`, `test_passed`, `timed_out`, `infrastructure_status`,
`classification`, `repair_used`, and `disposition`.

### OpenRouter provider mapping and missing values

Leitir maps only these response paths:

| Trace usage field | OpenRouter field |
|---|---|
| `cost_usd` | `usage.cost` |
| `prompt_tokens` | `usage.prompt_tokens` |
| `completion_tokens` | `usage.completion_tokens` |
| `reasoning_tokens` | `usage.completion_tokens_details.reasoning_tokens` |

The raw provider usage object is retained after redaction. Missing fields stay
JSON `null` and appear in `missing_fields`; they are never inferred as zero.
At the root, `total_cost_usd` and token totals are sums only when every relevant
model span supplied that field. `provider_usage_complete` and
`missing_provider_fields` make this distinction explicit.

### Evidence accounting and SER

`evidence_accounting` records total cleaned evidence tokens/chunk IDs and the
tokens/chunk IDs retained for synthesis. The same token totals are copied to
root convenience fields. SER is:

```text
retained first-synthesis evidence tokens / total cleaned first-synthesis evidence tokens
```

The evaluation report aggregates those raw counts, excludes invalid/no-data
runs, and reports `null` percentage when the denominator is zero.

### Artifacts, replay metadata, and diffs

`artifacts[]` is the ID/type/reference/digest index used by spans.
`replay` records configuration, prompt, tool-output, cleaned-chunk, and model
response artifact lineage and declares replayable starting points at Steps 3
and 4. `attempt_diffs[]` links consecutive candidate artifacts to a unified
diff artifact and includes the redacted unified diff.

V1 has **no replay CLI** and JSON traces do not guarantee that process-local
`memory://` artifact payloads remain available after exit. Treat replay as
recorded lineage for tooling, not as a claim that the CLI can rerun a trace.

### Error taxonomy

Stable trace error codes are:

- `ERR_EXPANSION_MALFORMED`
- `ERR_SEARCH_ZERO_RESULTS`
- `ERR_SCRAPE_BOILERPLATE_LEAK`
- `ERR_SECURITY_PROMPT_INJECTION`
- `ERR_SYNTAX_COMPILATION_FAIL`
- `ERR_VERIFICATION_TIMEOUT`

Normalized `error_message`, discovery/extraction failure categories, and
sandbox `error_category` add detail without exposing provider bodies,
credentials, or hidden-test source.

## 6. Docker security model

Generated and retrieved code is untrusted. Step 5 builds from
`python:3.11-slim`, pins sandbox `pytest==9.0.2`, and runs only:

```text
python -m pytest
```

Candidate code, public tests, and evaluator-only hidden tests are mounted
read-only. The runtime container:

- is ephemeral and is force-removed;
- runs as unprivileged UID/GID `65532:65532`;
- has no network, no added Linux capabilities, no new privileges, and no
  privileged mode;
- has a read-only root filesystem and read-only workspace;
- exposes only a bounded, `noexec` `/tmp` tmpfs;
- defaults to 120 seconds, 512 MiB RAM/swap, 1 CPU, 64 processes, a 64 MiB
  tmpfs/shared-memory limit, and 1,000,000 captured output bytes.

The base-image build may use the network to install the pinned pytest. If a
task declares dependencies, Leitir validates package-index
names/specifiers, rejects replacement of sandbox tooling, and builds a
task-scoped image with only those declarations using binary wheels and
`--no-deps`. Dependency installation happens during the image build with
network access; the candidate runtime remains networkless. The task image is
removed afterward.

This is defense in depth, not a production multi-tenant sandbox guarantee.
Never mount the Docker socket, home directory, credential directories, or
other broad host paths as hidden tests.

## 7. Troubleshooting

### `leitir: command not found`

Activate the virtual environment and repeat the editable install. Confirm
`python -m pip show leitir` and `leitir --help`.

### OpenRouter credential errors

Confirm the file path and JSON shape exactly. The provider object must be named
`openrouter`; only `key`, `apiKey`, and `api_key` are accepted. Conflicting
aliases, whitespace around a key, or newline characters are rejected. Do not
print the file while diagnosing it.

### Search failures or zero results

Confirm SearXNG is reachable at `http://localhost:8080/search` and supports
`format=json`. Check anonymous GitHub rate limits. V1 has no automatic
authenticated fallback.

### Docker infrastructure failures

Confirm the daemon is running and the current user can access it. The first run
may need registry/package-index access to build the pinned base image. A
timeout, output-limit breach, image build failure, invalid pytest exit, or
container cleanup failure is reported as a failed/invalid sandbox span rather
than a passing test.

### Exit 4 / spend cap exceeded

Inspect root `spend_cap_breach`, then the referenced model span and its
`model.usage`. The current CLI does not expose a cap override. A new run starts
with a new per-run ledger.

### Safe diagnosis

The CLI does not provide a dry run. Use help commands and
`python -m pytest --ignore=tests/test_verification_docker.py` for
Docker-free validation. Redact task text, artifact content, filesystem paths,
and all credential-like values before sharing a trace.
