# Competitive landscape — GitHub code scavenging for AI agents (2026-09)

Dated research record (2026-09-27). Repository metadata from `gh api repos/...` on that
date; product claims are the vendors' own unless stated. Positioning and scope decisions
are the owner's (see [the audit](../evidence/audit-2026-09-27/README.md)); work is tracked
in [milestone 7](https://github.com/anthonykewl20/leitir/milestone/7), epic
[#410](https://github.com/anthonykewl20/leitir/issues/410).

## Positioning

Leitir is **code referencing with extra power** for the phase where an AI agent collates
information to plan and create: it scavenges GitHub for a mature, working implementation to
use as a base or reference, reads it from byte-verified commit-pinned source, and records
what was used. Its purpose is to stop agents from hand-waving architecture and code. It is
not an IDE suggestion filter (GitHub Copilot code referencing) and not a documentation
server (Context7 — out of scope by owner decision).

## The problem is real

- Package hallucination: 19.7% of package references across 576k samples from 16 models
  (USENIX Security 2025); 4.62–6.10% on 2026 frontier models
  ([arXiv 2605.17062](https://arxiv.org/abs/2605.17062)); exploited as "slopsquatting"
  ([Socket](https://socket.dev/blog/slopsquatting-how-ai-hallucinations-are-fueling-a-new-class-of-supply-chain-attacks)).
- Deprecated/version-mismatched APIs ([LibEvoBench](https://arxiv.org/pdf/2606.25402)).
- 66% of developers cite AI output that is "almost right, but not quite"; trust in accuracy
  29% ([Stack Overflow 2025](https://survey.stackoverflow.co/2025/ai)).
- Unattributed reuse is litigated (Doe v. GitHub, 9th Cir. argued 2026-02-11,
  [BakerHostetler](https://www.bakerlaw.com/the-copilot-litigation/)); GitHub added code
  referencing to the Copilot coding agent on 2026-02-18
  ([changelog](https://github.blog/changelog/2026-02-18-copilot-coding-agent-supports-code-referencing/)).

## Competitors

| Tool | What it does | Maturity/ranking | Provenance | Code license |
|---|---|---|---|---|
| [Octocode](https://github.com/bgauryy/octocode) (944★) | 17 tools: GitHub code/repo/PR/issue/commit search, file read with `symbols` skeleton and `matchString` slices, clone cache, local ripgrep+AST, LSP, npm lookup; `next` hints, token-cost docs | GitHub `sort=stars|forks|updated` only | paths + line anchors; no verification | MIT (reusable, TS/Rust) |
| [DeepWiki MCP](https://docs.devin.ai/work-with-devin/deepwiki-mcp) | LLM wiki + `ask_question` for ~50k top public repos | none | commit-pinned blob links, not verified | proprietary (idea-only) |
| [package-intel-mcp](https://github.com/datakoot/package-intel-mcp) (0★) | npm/PyPI/crates info, downloads, deps (deps.dev), health verdict | days since release, deprecation, advisories | none | MIT |
| [Exa Code](https://exa.ai/blog/exa-code) | semantic code-example retrieval over GitHub + web, few-hundred-token answers | proprietary rerank | none | proprietary |
| [Copilot code referencing](https://docs.github.com/en/copilot/concepts/completions/code-referencing) | flags ~150-char matches of Copilot's own suggestions against public GitHub; index refreshed every few months | n/a | URL + license name, no commit pin | proprietary |
| [grep.app MCP](https://vercel.com/blog/grep-a-million-github-repositories-via-mcp) | regex/whole-word search over ~1M repos | snippet relevance | none | proprietary |
| [Sourcegraph MCP](https://sourcegraph.com/docs/api/mcp) | keyword/semantic/deep search, def/refs, commit/diff search (Enterprise) | n/a | revisions | closed |
| [GitMCP](https://github.com/idosal/git-mcp) (8.4k★) | per-repo docs/code MCP (llms.txt → README) | none | none | Apache-2.0 |
| [opensrc](https://github.com/vercel-labs/opensrc) (3.0k★) | fetch/cache package source at version tag, `opensrc path` | none | none (no hash verification) | Apache-2.0 |
| [Chroma Package Search](https://github.com/chroma-core/package-search) | hybrid/grep/read over 3k+ curated packages | none | tag-resolved | no license |
| [Nia](https://github.com/nozomio-labs/nia) | indexes repos/docs/packages; LLM research agents | none | none | SaaS |
| [SCANOSS](https://github.com/scanoss/scanoss.py) | snippet winnowing (GRAM 30, WINDOW 64) against 100M+ files; free `api.osskb.org`; SPDX/CycloneDX export | n/a | file/snippet → component, license | client MIT; engine GPL-2.0 (idea-only) |
| [GitHub MCP server](https://github.com/github/github-mcp-server) (33k★) | raw code/repo/PR search — the baseline agents already have | none | none | MIT |

Data sources worth consuming: [deps.dev v3](https://docs.deps.dev/api/v3/) (stars, forks,
Scorecard, advisories, content-hash query; CC-BY 4.0), OpenSSF Scorecard, OSV.

## Gaps nobody fills — Leitir's opening

1. **Maturity-ranked discovery for a task** (projects, not snippets), reproducibly →
   [#376](https://github.com/anthonykewl20/leitir/issues/376) scout,
   [#380](https://github.com/anthonykewl20/leitir/issues/380) maturity signals,
   [#381](https://github.com/anthonykewl20/leitir/issues/381) grouping,
   [#382](https://github.com/anthonykewl20/leitir/issues/382) BM25.
2. **One cited research pack for planning** across several mature projects →
   [#377](https://github.com/anthonykewl20/leitir/issues/377),
   [#383](https://github.com/anthonykewl20/leitir/issues/383) compare,
   [#386](https://github.com/anthonykewl20/leitir/issues/386) read modes,
   [#387](https://github.com/anthonykewl20/leitir/issues/387) map,
   [#391](https://github.com/anthonykewl20/leitir/issues/391) tests-for.
3. **Grounding enforcement** — verify that plans and changes cite verified mature
   references → [#378](https://github.com/anthonykewl20/leitir/issues/378).
4. **Provenance at the moment of reuse** (base/adopt records, drift alerts, SPDX snippets)
   and on-demand origin lookup →
   [#379](https://github.com/anthonykewl20/leitir/issues/379),
   [#393](https://github.com/anthonykewl20/leitir/issues/393),
   [#394](https://github.com/anthonykewl20/leitir/issues/394) winnowing,
   [#395](https://github.com/anthonykewl20/leitir/issues/395) origin,
   [#396](https://github.com/anthonykewl20/leitir/issues/396) drift,
   [#397](https://github.com/anthonykewl20/leitir/issues/397) export.
5. **Hallucinated-API gate for TS/JS** against installed versions →
   [#399](https://github.com/anthonykewl20/leitir/issues/399).

Parity items adapted from competitors: token-budgeted reads and `next` hints (Octocode) →
[#386](https://github.com/anthonykewl20/leitir/issues/386),
[#401](https://github.com/anthonykewl20/leitir/issues/401); history mining (Octocode,
Sourcegraph) → [#390](https://github.com/anthonykewl20/leitir/issues/390); def/refs →
[#388](https://github.com/anthonykewl20/leitir/issues/388); path verb (opensrc) →
[#402](https://github.com/anthonykewl20/leitir/issues/402); optional semantic search and
repo Q&A extras behind ADRs →
[#385](https://github.com/anthonykewl20/leitir/issues/385),
[#392](https://github.com/anthonykewl20/leitir/issues/392); benchmark and distribution →
[#408](https://github.com/anthonykewl20/leitir/issues/408),
[#407](https://github.com/anthonykewl20/leitir/issues/407),
[#409](https://github.com/anthonykewl20/leitir/issues/409).

## Reuse rules for competitor code

Permissively licensed code (Octocode MIT, package-intel-mcp MIT, scanoss.py MIT, GitMCP and
opensrc Apache-2.0, Kodit Apache-2.0) may be ported with attribution recorded — by Leitir's
own adoption records once [#393](https://github.com/anthonykewl20/leitir/issues/393) lands.
GPL-2.0 (SCANOSS engine/ldb), FSL (Sourcebot), unlicensed (Chroma package-search) and
proprietary services are idea-only. Ports must respect the stdlib-only runtime and
determinism conventions.

## Unverified

Nia pricing, grep.app homepage (HTTP 429), Exa pricing beyond "free for the public", and
the OSSKB free-tier rate limit were not verifiable on 2026-09-27.
