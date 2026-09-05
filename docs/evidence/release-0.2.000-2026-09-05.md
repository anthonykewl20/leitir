# Release 0.2.000 validation record — 2026-09-05

This record covers the code/specification remediation and release preparation.
Publication, final live-cohort completion and signed Phase C remain pending.
The original audit examined commit `73f57b66`; the latest combined source tested
here is `66b88c24ff97f18669fe1c48e18c74e949cc84e1`.

## Defect disposition and independent oracles

| Finding | Issue / PR | Real execution and result |
|---|---|---|
| Class source omitted its nested runtime dependencies | #309 / #320 | Published Packaging `version.parse` rejects unsupported closure. Actual `noxfile.tests` retains six/seven blockers at budgets two/three; rejection dominates budget exhaustion. |
| Authenticated source lent authority to fabricated API/example cache entries | #310 / #321 | Actual Ed25519-signed Packaging control passes; forged caches are derived again from verified bytes; invalid signatures and changed source reject. |
| Artifact/normalized bytes received unsupported Git identities | #311 / #325 | Requests exact Git indexes successfully; Zod artifact mismatch rejects. Actual Vitest CRLF normalization cannot invent upstream blob identity. |
| Valid Go source was called corrupt during indexing; unrelated Git links blocked indexing | #311 / #325 | Actual Go shelves report honest ineligibility; actual Requests Git links are indexed as link bytes without following them; mutation rejects. |
| Streaming-exclusion allegation | Withdrawn | The original comparison mixed span and file processing. Actual pinned Linux bytes through both complete file-processing paths agree. No public exclusion change was needed. |
| Go syntax and dependency-coverage overclaim | #314 / #323 | Official Go 1.27.1 and actual published module files establish valid quoted/escaped grammar and distinguish direct requirements from the MVS graph. |
| PyPI funding links displaced source metadata; repository-free artifacts rejected | #313 / #322 | Actual attrs source-purpose links select the repository. BeautifulSoup4 materializes from its checksum-verified artifact with explicit degraded provenance. |
| Query replay, optional boosts, method evidence and masking documentation diverged | #312 / #326 | Actual Requests query replay and independently optional boosts agree; AST/heuristic method survives output. Actual Linux buffered/streamed exclusions agree. |
| Bare-name/qualified-path checking falsely reported valid APIs | #315 / #324 | Actual Requests consumers and installed runtime controls distinguish reexports, loaded modules, missing attributes, class-as-module imports and ambiguous bindings. |
| Qualified checking regressed removed-owner impact reporting | #315 / #324 | Actual Flask 2.2.5→2.3.0 runtime/CLI controls detect removed `JSONEncoder` through direct, aliased and member accesses; retained Flask use stays unaffected. |
| Repeated complete tree walks and shared cache eviction race | #316 / #327 | Complete CLI benchmark reuses immutable listings. Actual concurrent calls using five upstream pins reproduce and then reject the lost-hit race through atomic cache access. |
| Ordinary `.h` headers omitted by explicit C++ searches | #328 / #329 | All four fmt benchmark definitions are found; source lines and Git blob identities independently match upstream bytes. |
| Platform cache isolation and lock-order assumptions in validation | #330 / #331 | Actual concurrent Packaging materialization/trust succeeds; changed bytes reject. PR331 merged and issue330 auto-closed. |
| Intermittent macOS full-suite timeout | #334 / #335 | Identical source/test trees: baseline 768.21 seconds, worksteal 445.24 seconds, identical outcomes. Actual PR macOS run passed in 425.93 seconds with the original deadline. |
| Existing diagnostic mutations escaped observation | #306–308 / #317–319 | Production rejection remains intact; diagnostic mutations are now detected. |
| Public/distribution/release version mismatch | #332 / #333 | Actual wheel/sdist builds and installs agree on public `0.2.000` and Python metadata `0.2.0`; modified archive identities reject. |

Per-issue pins, commands, before/after output and rejection evidence are in the
adjacent `issue-N-2026-09-05` directories. The original 224-command audit,
complete downloaded corpora and full historical report are retained in the
session's `/tmp/leitir-audit-20260905` evidence directory. F04 is explicitly
withdrawn there rather than silently erased.

## Current release-source proof

| Surface | Actual evidence |
|---|---|
| Canonical serial suite | 3,742 passed, 159 gated skips, four warnings in 840.97 seconds on `66b88c24`. [Output](issue-332-2026-09-05/suite.txt), [command/head](issue-332-2026-09-05/suite.meta.json). |
| Static gates | Ruff and mypy passed. These and the existing suite are regression gates; they do not replace real upstream proof. |
| Distribution installation and rejection | Actual wheel and sdist installed into separate environments, reported the expected versions and materialized pinned Packaging. Wrong tags, extra artifacts and altered metadata rejected. [Identities](issue-332-2026-09-05/artifact-identities.json), [live result](issue-332-2026-09-05/live.txt). |
| MCP | Actual MCP 2.1.1 client/server exercised all five tools, 12 concurrent calls, malformed arguments, unknown tool and source tamper/recovery. Actual Flask diff matched independent hashes: seven added, 12 removed and 77 modified files. [Protocol cases](issue-332-2026-09-05/mcp-sad-paths.json), [diff oracle](issue-332-2026-09-05/mcp-diff-summary.json). |
| Process crash recovery | SIGKILL during actual Packaging extraction left three complete files and a fourth partial file, without a published manifest/shelf/catalog. Incomplete staging rejected. A normal exact-pin rerun reclaimed staging and produced a fully verified exact-parity shelf. [Evidence](issue-332-2026-09-05/crash-recovery/README.md). |
| SBOM | Four actual Requests/Packaging CLI documents passed official SPDX 2.3/CycloneDX 1.5 schemas, external references and format validators. Two altered actual outputs rejected. Generation/final validation ran without network access. [Evidence](issue-332-2026-09-05/sbom-validation/README.md). |
| Complete tree recovery | Actual TypeScript pin `b465fdbfe175304d9b977da137b2c178ae1091d3`: 53,309 visible blobs expanded to 81,368 recovered blobs; sorted/unique full universe passed in 1,376.90 seconds. [Output](issue-332-2026-09-05/recovery-live.stdout), [source head/command](issue-332-2026-09-05/recovery-live.meta.json). |
| Full CLI benchmark | Completed on earlier combined source `abfc90ab`: 32 tasks, 33 results, every expected source record found. Twenty-eight complete reports and four recovered-TypeScript PARTIAL reports conform to ADR-0001. The final repeat remains pending. |
| Determinism and concurrency | Actual Requests search/index output agrees across seeds 0/1/42, UTC/Kathmandu and C/C.UTF-8 except observation timestamps. Actual concurrent Packaging get/trust and info/API/example views preserve verified source and stable API output. |

The current broad live suite runs separately from its heavy tree walks to
respect provider quota. Its initial attempt's quota failures remain preserved;
subsequent successful runs are recorded separately. Provider/environment skips
are not converted into passes.

## Independent review

Every current defect PR has both required main checks present and successful:
`CodeQL` and `required checks pass`. Missing contexts after base retargeting were
identified and run; absence was never accepted as a completed final gate.

The owner authorized independent Codex reviewers as substitutes for unavailable
reviewer-hy3/reviewer-qwen. Reviewers one and two reviewed the sensitive changes.
PR324's final whole-diff reviews are by reviewers one and three because reviewer
two implemented its Flask correction. Root independently reviewed PR335,
implemented by reviewer one. No reviewer approved their own implementation.
Exact head records and full review reports remain in the session's remediation
evidence directory; final merge readiness must recheck the current heads.

## Containment and authority

[Phase A run 33960563929](https://github.com/anthonykewl20/leitir/actions/runs/33960563929)
used the final release source under the actual pinned nsjail/rootfs substrate.
All five donors completed, each with two passes, zero failures/skips, exact
rerun parity, donor-ban proof and complete probes. The runtime digest is again
`sha256:901bf7ac3cdfc5e7fcb59a9f6c153d24724c7525d7398174478d3d1322b40f69`.
The [complete report](issue-332-2026-09-05/contained-phase-a/exit-gate-report.json)
and [summary](issue-332-2026-09-05/contained-phase-a/summary.json) preserve the
aggregate REJECT: only the independent authority match remains unsatisfied.

Phase C requires the independently signed sidecar for the prepared projection,
using the existing trusted owner key. No signature or trust root is fabricated.
The separate optional six-task BTS evaluation contains unsupported/rejected
integrations and is not an all-pass result. Proposed Go containment is not
claimed as implemented by Python-to-Go contract generation.

Schema validation does not prove dependency-graph completeness. Process
termination does not prove every power-loss boundary or non-Linux behavior.
Static checking establishes conservative symbol existence, not arity/types or
arbitrary dynamic dispatch. These boundaries remain explicit in the release
notes and relevant specifications.
