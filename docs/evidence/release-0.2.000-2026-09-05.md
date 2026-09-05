# Release 0.2.000 validation record — 2026-09-05

This record covers the code/specification remediation and release preparation.
All selected live probes have completed; three explicit skips remain.
Signed Phase C completed and `v0.2.000` was published on 2026-09-05; the publication evidence is in [issue-338-2026-09-05/](issue-338-2026-09-05/README.md).
The original audit examined commit `73f57b66`; runtime, verifier and final help runs below identify their exact source heads.
Application integration [PR337](https://github.com/anthonykewl20/leitir/pull/337)
merged as `bf886e1eb59f9e3126826e8a940c94fd28b38a0b`; all13 component PRs
were indirectly merged and their linked issues automatically closed.

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
| Query replay, optional boosts, method evidence and masking documentation diverged | #312 / #326 | Actual Requests query replay and independently optional boosts agree; AST/heuristic method survives output. Actual Linux buffered/streamed exclusions agree; final CLI help matches actual official Go comment behavior. |
| Bare-name/qualified-path checking falsely reported valid APIs | #315 / #324 | Actual Requests consumers and installed runtime controls distinguish reexports, loaded modules, missing attributes, class-as-module imports and ambiguous bindings. |
| Qualified checking regressed removed-owner impact reporting | #315 / #324 | Actual Flask 2.2.5→2.3.0 runtime/CLI controls detect removed `JSONEncoder` through direct, aliased and member accesses; retained Flask use stays unaffected. |
| Repeated complete tree walks and shared cache eviction race | #316 / #327 | Complete CLI benchmark reuses immutable listings. Actual concurrent calls using five upstream pins reproduce and then reject the lost-hit race through atomic cache access. |
| Ordinary `.h` headers omitted by explicit C++ searches | #328 / #329 | All four fmt benchmark definitions are found; source lines and Git blob identities independently match upstream bytes. |
| Platform cache isolation and lock-order assumptions in validation | #330 / #331 | Actual concurrent Packaging materialization/trust succeeds; changed bytes reject. PR331 merged and issue330 auto-closed. |
| Intermittent macOS full-suite timeout | #334 / #335 | Identical source/test trees: baseline 768.21 seconds, worksteal 445.24 seconds, identical outcomes. Actual PR macOS run passed in 425.93 seconds with the original deadline. |
| Existing diagnostic mutations escaped observation | #306–308 / #317–319 | Production rejection remains intact; diagnostic mutations are now detected. |
| PR merge-ref artifact could qualify under a different head SHA | #332 / #333 | Historical green CI31579743105 built a wheel with three files absent from its reported head. The actual workflow step accepted it before the correction and rejects it afterward; release qualification requires exact-commit push/dispatch CI. |
| Corrupt archives passed release metadata checks; malformed fields produced tracebacks | #332 / #333 | Actual CRC-corrupt CI wheel passed the old verifier and Twine but failed installation. Gzip trailer corruption also escaped verification. Complete payload checks, duplicate-path rejection and typed malformed-input handling now reject 36 changed actual archives while accepting two valid controls. |
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
| Final verifier canonical suite | 3,742 passed, 159 gated skips, four warnings in846.32s. The recorded command started from cc134194 with the uncommitted verifier/test bytes later committed at64a90ef; SHA2564818d3d7ec4b8450cc0f7357e2e322800644607656ec8614fa792f37b74c7059 identifies that exact verifier. This is not misreported as a clean64a checkout. [Output](issue-332-2026-09-05/verifier-suite.txt), [command and hashes](issue-332-2026-09-05/verifier-suite.meta.json). |
| Final application integration suite | Exact a2dafae659b0bdbb7ed2fba427adc24247b4b972: 3,742 passed, 158 gated skips, four warnings in851.34s, including the final CLI help correction. [Output](issue-332-2026-09-05/integration-help-suite.txt), [command/head](issue-332-2026-09-05/integration-help-suite.meta.json). Hosted CI33965309804 and CodeQL33965309789 passed. |
| Static gates | Ruff and mypy passed. These and the existing suite are regression gates; they do not replace real upstream proof. |
| Distribution installation and rejection | Actual wheel and sdist installed into separate environments, reported the expected versions and materialized pinned Packaging. Wrong tags, extra artifacts and altered metadata rejected. [Identities](issue-332-2026-09-05/artifact-identities.json), [live result](issue-332-2026-09-05/live.txt). |
| Archive corruption and malformed metadata | Independent final rerun: 38 unchanged real archive cases, 36 clean rejections, two valid controls, zero tracebacks. Fresh wheel/source builds, isolated installs and the expanded live rejection cases passed in 9.53 seconds. [Before/after proof](issue-332-2026-09-05/archive-rejections/README.md), [final matrix](issue-332-2026-09-05/archive-rejections/final-results.json). |
| Exact-commit CI artifacts | Actual workflow-dispatch run 33962193988 passed its complete hosted matrix. Downloaded wheel/source archive match the exact commit: 127/326 tracked packaged files, all 119 runtime Python files. Separate installations complete real Packaging get/info/API operations. [Source comparison and install evidence](issue-332-2026-09-05/ci-33962193988/README.md), [complete CI result](issue-332-2026-09-05/ci-33962193988/run.json). |
| Corrected verifier CI artifacts | Exact head64a90ef completed CI33964007155 and CodeQL33964008898. Both downloaded artifacts match all127 packaged src/data files, pass payload verification and complete14 install/version/live Packaging commands. [Evidence](issue-332-2026-09-05/ci-33964007155/README.md). |
| MCP | Actual MCP 2.1.1 client/server exercised all five tools, 12 concurrent calls, malformed arguments, unknown tool and source tamper/recovery. Actual Flask diff matched independent hashes: seven added, 12 removed and 77 modified files. [Protocol cases](issue-332-2026-09-05/mcp-sad-paths.json), [diff oracle](issue-332-2026-09-05/mcp-diff-summary.json). |
| Process crash recovery | SIGKILL during actual Packaging extraction left three complete files and a fourth partial file, without a published manifest/shelf/catalog. Incomplete staging rejected. A normal exact-pin rerun reclaimed staging and produced a fully verified exact-parity shelf. [Evidence](issue-332-2026-09-05/crash-recovery/README.md). |
| SBOM | Four actual Requests/Packaging CLI documents passed official SPDX 2.3/CycloneDX 1.5 schemas, external references and format validators. Two altered actual outputs rejected. Generation/final validation ran without network access. [Evidence](issue-332-2026-09-05/sbom-validation/README.md). |
| Broad live cohort | 82 passed, three environment/provider skips, zero failures. Two heavy tree cases were separated to reserve provider quota. [Output](issue-332-2026-09-05/live-rest.stdout), [command/head](issue-332-2026-09-05/live-rest.meta.json). The 2,970-second wall time includes an intentional 1,125-second quota pause; it is not application performance. |
| Complete tree recovery | Actual TypeScript pin `b465fdbfe175304d9b977da137b2c178ae1091d3`: 53,309 visible blobs expanded to 81,368 recovered blobs; sorted/unique full universe passed in 1,376.90 seconds. [Output](issue-332-2026-09-05/recovery-live.stdout), [source head/command](issue-332-2026-09-05/recovery-live.meta.json). |
| Public tree-listing wrapper | Actual TypeScript pin enumerated81,368blobs using2,486APIcalls; passed in1,422.43s. [Output](issue-332-2026-09-05/fallback-live.stdout), [command/head](issue-332-2026-09-05/fallback-live.meta.json). |
| Complete unique live inventory | 87 selected nodes:84passes, three explicit skips, zero failures/pending across separately recorded runs. [Per-node ledger](issue-332-2026-09-05/live-coverage-ledger.json). Final Bitbucket retry remained skipped after28.92s: [output](issue-332-2026-09-05/bitbucket-final.stdout), [command/head](issue-332-2026-09-05/bitbucket-final.meta.json). |
| Full installed-wheel CLI benchmark | 32 tasks, 33 results, every expected source record found in 1,435.41 seconds. Twenty-eight complete reports and four recovered-TypeScript PARTIAL reports conform to ADR-0001. Complete output is byte-identical to the earlier successful run. [Record-by-record validation](issue-332-2026-09-05/benchmark-validation.json), [actual output](issue-332-2026-09-05/bench.stdout), [installed artifact/command](issue-332-2026-09-05/bench.meta.json). |
| Determinism and concurrency | Actual Requests search/index output agrees across seeds 0/1/42, UTC/Kathmandu and C/C.UTF-8 except observation timestamps. Actual concurrent Packaging get/trust and info/API/example views preserve verified source and stable API output. |

The broad live suite completed separately from two heavy tree cases to respect
provider quota. Its three skips are two local placeholder entries that defer to the dedicated
nsjail/donor workflow and one anonymous Bitbucket rate limit; those two local
functions are not counted as executed donor proof. Hosted containment has separate real donor
evidence below. The initial attempt's quota failures remain preserved;
subsequent successful runs are recorded separately. Provider/environment skips
are not converted into passes. Both the final public tree-listing wrapper and independent full-universe recovery
cases passed. The final Bitbucket retry still skipped; provider limitations are
not counted as successful validation.

## Independent review

Every current defect PR has both required main checks present and successful:
`CodeQL` and `required checks pass`. Missing contexts after base retargeting were
identified and run; absence was never accepted as a completed final gate.

The owner authorized independent Codex reviewers as substitutes for unavailable
reviewer-hy3/reviewer-qwen. Reviewers one and two reviewed the sensitive changes.
PR324's final whole-diff reviews are by reviewers one and three because reviewer
two implemented its Flask correction. Root independently reviewed PR335,
implemented by reviewer one. No reviewer approved their own implementation.
PR333 release-only head `cc134194` completed two independent sensitive reviews.
A subsequent production verifier correction added complete archive payload checks;
it was not merely a documentation change. Both reviewers one/two independently
reviewed exact corrected head `64a90ef978ca9c3485a9b767c9076a0202ea2856` after
CI33964007155 and CodeQL33964008898 passed, and each reran the unchanged38-case
actual archive matrix:36cleanrejections, two valid controls, zero tracebacks.
Final application integration `a2dafae` completed independent reviews by one/three
after its exact CI/CodeQL passed; corrected component326 also completed one/two.
The final preparation documentation head needs its own hosted checks and review;
those exact records are maintained in PR333 to avoid claiming this document
already proves its own future commit. No self-authored component is self-approved.

## Completion scope

Implementation issues306–316,328,330,334 and integration336 are closed through
merged PRs. Release preparation332/333 includes the version, curated notes,
release verifier and publisher. Issue338 separately requires the independent
signed sidecar, actual PhaseC, exact-commit CI artifacts, attested publication,
downloaded-asset verification and tag-dependent documentation. At the time of
this preparation record no tag or release had been published; `v0.2.000` was
published later on 2026-09-05 (see the Independent review and Containment
sections, and [issue-338-2026-09-05/](issue-338-2026-09-05/README.md)).

## Release source binding

[Actual artifact and gate evidence](issue-332-2026-09-05/release-ci-source/README.md)
establishes a historical publication-admission defect: PR CI metadata names the
head while the default checkout builds a merge ref. Matching that head SHA and
a successful run did not prove the artifact came from the tagged source.
The corrected gate admits only successful push/workflow-dispatch CI runs for
that exact commit. The current release head/PR merge trees were independently
compared and match; the historical defect is not misrepresented as a current
candidate mismatch. The unchanged production gate rejected this branch while CI was pending and
selected run 33962193988 after its success. [Live gate result](issue-332-2026-09-05/release-ci-source/current-green-gate.json).
Final publication still requires a qualifying run for the final tagged commit.

## Containment and authority

[Phase A run 33960563929](https://github.com/anthonykewl20/leitir/actions/runs/33960563929)
used the final release source under the actual pinned nsjail/rootfs substrate.
All five donors completed, each with two passes, zero failures/skips, exact
rerun parity, donor-ban proof and complete probes. The runtime digest is again
`sha256:901bf7ac3cdfc5e7fcb59a9f6c153d24724c7525d7398174478d3d1322b40f69`.
The [complete report](issue-332-2026-09-05/contained-phase-a/exit-gate-report.json)
and [summary](issue-332-2026-09-05/contained-phase-a/summary.json) preserve the
aggregate REJECT: only the independent authority match remains unsatisfied.

Phase C: on 2026-09-05 the owner signed that projection with the existing
trusted owner key (no trust-root rotation, no fabricated signature) and the
gate was rerun with `--trusted-keys` on the ratifying branch
([run 33974049348](https://github.com/anthonykewl20/leitir/actions/runs/33974049348));
its summary is `complete` with the same digest. The ceremony log, rejection
probes and retained gate artifacts are in
[issue-338-2026-09-05/](issue-338-2026-09-05/README.md).
The separate optional six-task BTS evaluation contains unsupported/rejected
integrations and is not an all-pass result. Proposed Go containment is not
claimed as implemented by Python-to-Go contract generation.

Schema validation does not prove dependency-graph completeness. Process
termination does not prove every power-loss boundary or non-Linux behavior.
Static checking establishes conservative symbol existence, not arity/types or
arbitrary dynamic dispatch. These boundaries remain explicit in the release
notes and relevant specifications.
