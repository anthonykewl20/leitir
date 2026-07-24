# Leitir v1 — Status (2026-07-24)

## Where we are
**v1 is BUILT, LIVE-TESTED GREEN, and pushed to main.** 12 implementable issues (v1-01..v1-12), all closed. 322 automated tests pass. hy3 reviewed the 4 critical modules at high reasoning (sound + hardened). A live end-to-end run on the `urlencode-doseq` smoke task passed all 5 steps (sandbox pytest ✓, first-try, $0.014). GPT-5.6 and hy3 both scored the research report **8/10**.

## What's on main (latest commit)
All code + Phase 3 robustness fixes:
- 12 modules (scaffold, trace, hy3 client, Steps 1-5, orchestrator, CLI, eval harness, docs).
- Phase 3a hardening: 9 fixes from hy3 code review (max_repairs guard, verify_once contract, content-type, truncation, dedup, evidence-error, redaction, span guard).
- Phase 3b live-e2e fixes: robust model-output parsing (extract_json_obj), discovery auth (GitHub token), SearXNG engines-blocked detection, best-effort sanitization, tolerant citations, accounting fix, Step-1 retry-on-malformed, transient-response retry, discovery reliability (Retry-After, inter-query delay), `--smoke-task` CLI.

## How to run a live task
```bash
# 1. Start SearXNG (one-time; container already exists, just stopped)
docker start leitir-searxng   # port 8888, json+limiter-off configured

# 2. Set up a venv with the pinned deps
python3 -m venv /tmp/leitir-venv
/tmp/leitir-venv/bin/pip install -r requirements.txt

# 3. Edit config.py: search_endpoint → localhost:8888/search
#    (SearXNG runs on 8888, not the default 8080)
#    Optionally raise per_run_spend_cap_usd for live runs (default $0.05 → $2.0)

# 4. Run a smoke task (with hidden tests for real verification)
cd /home/soultransit/devtony/leitir
GH_TOKEN=$(gh auth token) PYTHONPATH=src /tmp/leitir-venv/bin/python -m leitir.cli run --smoke-task urlencode-doseq

# Or freeform (no hidden tests, Step 5 runs generated code only)
GH_TOKEN=$(gh auth token) PYTHONPATH=src /tmp/leitir-venv/bin/python -m leitir.cli run --task "implement X using Y"
```

## Known gaps (for the next session)
- **SearXNG free engines block** after a few queries (DuckDuckGo rate-limits SearXNG). GitHub (Tier 3, with token) carries discovery. For reliable Tier 1-2, SearXNG needs API-key engines (Brave/Bing) — see eval-strategy issue #13.
- **Config override**: no env-var/CLI-flag mechanism — edit `config.py` for environment-specific values (search_endpoint, spend cap). The eval-strategy issue notes adding env overrides.
- **Test suite small**: 2 hidden tests per smoke task. The full 50-task eval suite + SWE-bench/DeepEval (#13) would strengthen verification.
- **hy3 non-determinism**: Step 1 output sometimes malformed (mitigated by retry-on-malformed, but parser isn't bulletproof). Transient OpenRouter malformed responses (mitigated by transient-retry).

## Next steps
1. **DeepEval + SWE-bench** (issue #13) — the eval-strategy issue documents how/when/where.
2. **More smoke tasks green** — run the other 3 (retry-after, tomllib-contract, batched-backport).
3. **Reliable search backend** — SearXNG with API-key engines or a different search provider.
4. **Config override** (env vars) — so config.py doesn't need manual edits per environment.
5. **Full eval harness** (`leitir eval`) — all 4 tasks, metric reporting (SER/DRI/FPCR/SCCR).

## Architecture summary
Leitir is a 5-step pipeline: **hy3 query expansion → SearXNG+GitHub discovery → Trafilatura extraction+sanitization → hy3 synthesis (high) → Docker pytest sandbox (≤3 repair loops)**. It uses `tencent/hy3` via OpenRouter (Step 1 omits `reasoning_effort`; Steps 4-5/review send `"high"`). Secrets (OpenRouter key, GitHub token) are never logged. Every run produces a §5.1 JSON trace with cost/tokens/latency/evidence/SER.
