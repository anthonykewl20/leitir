# Leitir v1 — Status (2026-07-25)

> **Read this first.** The prior "proven green" was a **false green**. This session
> audited all 8 live runs, found the engine is weak (7 of 13 components score
> "critical" by blind expert consensus), filed the defects as issues #15 and #16,
> built a fail-closed grounding gate (in a worktree, **not landed** — blocked), and
> landed an expert-consensus health scorecard to `docs/`. **main is docs-only
> clean; the gate is unfinished work in a worktree.**

## TL;DR
- **main HEAD: `b9c29f3`** — `docs/leitir-engine-scorecard.html` + `.png` + README section (3-expert blind consensus). No code changes on main this session.
- **The "green" run was a false green:** the one accepted live run (`urlencode-doseq`, manifest requires Tier 2) was `accepted` on **Tier-3-only** evidence (8 byte-identical GitHub mirrors of the official docs), pytest-passing. 1 accepted / 7 failed across 8 live runs — **all the same trivial task.**
- **A fail-closed grounding gate is built but NOT landed.** It is blocked on a verified defect (see below). This is the next session's #1.
- **Expert consensus (hy3, DeepSeek, GPT-5.6-sol, blind):** 7/13 components critical, 0 good. Unanimous next step = **land the grounding gate** (+ flip the star gate).

## The diagnosis (filed)
- **#15** — fail-open acceptance gate (the false green) + the silent `trafilatura` env-parity hole + star-gate-off-by-default. Full evidence + fix + prevention.
- **#16** — the eval/verification model (hard gates + distributions, wire existing trace metrics, prod-image readiness, held-out oracle).
- Weakest bolts (consensus 0–10): Tier-3 star gate **0.8**, acceptance/gate **1.0**, Step 3 extraction **1.5**, eval harness **2.0**. See `docs/leitir-engine-scorecard.html`.

## In-flight: the grounding gate (NOT landed)
- **Worktree:** `.claude/worktrees/grounded-acceptance-gate` · **branch:** `worktree-grounded-acceptance-gate` · 2 commits ahead of main (`f43b37f` gate, `2cf83f3` hy3-driven fixes incl. the unified `chunk.tier <= max(declared_tiers)` predicate).
- **What it does:** `ACCEPTED = tests_passed AND authority_satisfied` via `_grounding_satisfied` (cited chunk tier ≤ max declared tier); new `TerminalDisposition.GROUNDING_UNAVAILABLE`; `WorkflowRequest.declared_tiers` threaded into the CLI `--smoke-task` path **and** `SmokeEvaluationDriver`. 330 tests pass (Docker-free).
- **Measured before/after (deterministic re-score of the real false-green trace):** `accepted` → `grounding_unavailable`.
- **Panel verdict — SPLIT:** hy3 **PASS**, DeepSeek **PASS (9/8/8)**, **GPT-5.6-sol FAIL (6/7/6)**.
- **★ Land blocker (GPT, verified):** the exported `Step5Controller.verify()` (`src/leitir/verification.py:795/843`, exported via `src/leitir/__init__.py:125/261`) still maps PASS → `ACCEPTED` **without the gate**. The gate only protects the orchestrator's internal loop, not the public API.

## Next session's #1 (in order)
1. **Close the `Step5Controller.verify()` bypass** so the grounding invariant is inescapable on every acceptance path (centralize it, or remove `verify()` from the acceptance surface). Re-run the panel (hy3 mandatory; GPT must flip to PASS).
2. **Land the gate** (rebase worktree branch onto main tip, `git -C <main> merge --ff-only`, remove the worktree).
3. **Flip `github_min_stars`** to the PRD value (>100) — the #2-weakest bolt, one-line.
4. **Then** the trafilatura env-parity fix (Step 3): a `leitir doctor` prod-image readiness check + make `cleaned_tokens==0` a loud `infrastructure_invalid`. (Was the head-chef's pick; experts said land the gate first.)

## How to run (working command — `/tmp/leitir-venv` from the old notes does NOT exist)
```bash
# Tests (Docker-free): uv is the working runner (python3.14 + pytest via uv)
cd /home/soultransit/devtony/leitir
PYTHONPATH=src uv run --no-project --with-requirements requirements.txt python -m pytest --ignore=tests/test_verification_docker.py

# Live smoke task (needs Docker + SearXNG on :8888 + GH_TOKEN + OpenRouter key)
docker start leitir-searxng
GH_TOKEN=$(gh auth token) PYTHONPATH=src uv run --no-project --with-requirements requirements.txt \
  python -m leitir.cli run --smoke-task urlencode-doseq
```
SearXNG config: `/tmp/searxng-leitir.yml` (`limiter: false`, `use_default_settings: true`) — the engines-blocked is upstream (DuckDuckGo rate-limiting SearXNG), not the limiter.

## Known gaps (expert-identified, this session)
- **trafilatura env-parity:** `extraction.py:141` lazy import raised `ModuleNotFoundError` in the live run env → 13 fetched docs → 0 tokens (`sanitization_failed`, traced per-span, fail-open at run level). Pinned in requirements but not importable there.
- **Discovery single-channel:** SearXNG `engines_blocked` 3/8 runs; GitHub 401 without token. No deterministic retrieval (`objects.inv`/`llms.txt`) or API-keyed fallback.
- **Eval validity:** 4 smoke tasks, all 8 live runs = 1 trivial task; aggregate-only metrics; traces don't persist `declared_tiers`.
- **Verification oracle:** hidden tests readable in-container; exit-0 alone = PASS; no held-out/mutation oracle.
- **Spend:** cap fires after the overshooting call; missing cost excluded (can't fire the cap).

## Issues
- [#15](https://github.com/anthonykewl20/leitir/issues/15) — false green / fail-open acceptance + trafilatura + star gate.
- [#16](https://github.com/anthonykewl20/leitir/issues/16) — eval/verification model (hard gates + distributions).
- #13 — eval-strategy (DeepEval/SWE-bench, reliable search backend) — pre-existing.

## Architecture summary (unchanged)
Leitir is a 5-step pipeline: **hy3 query expansion → SearXNG+GitHub discovery → Trafilatura extraction+sanitization → hy3 synthesis (high) → Docker pytest sandbox (≤3 repair loops)**. `tencent/hy3` via OpenRouter (Step 1 omits `reasoning_effort`; Steps 4–5/review send `"high"`). Secrets never logged. Every run emits a §5.1 JSON trace.

---
*Expert-review artifacts from this session (local):* `/tmp/hy3_gate_review2.txt`, `/tmp/deepseek_audit.txt`, `.codex-runs/leitir-gate-audit/`, `/tmp/{hy3,deepseek}_scorecard.txt`, `.codex-runs/leitir-scorecard/`. *Memory:* `~/.claude-glm/projects/-home-soultransit-devtony-leitir/memory/leitir-expert-panel.md` (how to invoke the mandated expert panel).
