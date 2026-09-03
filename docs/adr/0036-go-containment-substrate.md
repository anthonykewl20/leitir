# ADR-0036: Go containment substrate — proving an executed Go port under containment

- Status: proposed
- Implementation: not-started
- Deciders: leitir maintainers
- Date: 2026-09-02
- Technical Story: Issue #277 ("D1 remainder: execute an agent-written port against the translated contract under containment") — the containment-proof half of #270 that [ADR-0033](0033-evidence-assisted-cross-language-port.md) explicitly scoped out

## Context and Problem Statement

ADR-0033 delivered the deterministic, offline half of the cross-language port
pipeline: donor Python behaviour → portable contract → deterministic Go
contract-test rendering (`src/leitir/port_contract.py`) → license-gated port
attribution. Its own CLI output says, honestly, that nothing was executed:
`leitir bts-port-contract` emits `"containment_proof": "not_executed_v1"`
(`src/leitir/cli_bts.py`, the `bts-port-contract` payload) because ADR-0009's
containment substrate is Linux/CPython-shaped end to end — a published
`containment-rootfs-v1` asset carrying a pinned CPython and its
stdlib/native ELF closure, a hash-locked runtime-dependency site-packages,
and the `/harness/runner.py` contained runner, under a seccomp allowlist
measured for exactly that closure.

Issue #277 asks for the other half: prove an agent-written Go implementation
against the translated contract **under containment**, with the donor provably
absent, and reflect the executed proof in the pipeline's own output instead of
`not_executed_v1`. That requires deciding what "a Go-capable containment
substrate" even is, before any implementation PR can start. Per ADR-0009 §3,
a substrate change is categorically not a same-PR decision: it requires a new
published asset, manifest-pin update, fresh Phase-A measurement, and
out-of-band re-ratification.

This ADR makes those decisions. It does not implement them. It was authored in
an environment with no `nsjail` binary, no materialized rootfs, and no Go
toolchain (verified: `command -v go nsjail rustc` all report not found) — the
same conditions ADR-0033 recorded — so every syscall-surface claim below is a
**measurement mandate**, not a measurement.

## Decision Drivers

- ADR-0009 §3: "A substrate change requires a new published asset,
  manifest-pin update, fresh Phase-A measurement, and out-of-band
  re-ratification; an image rollout cannot silently repin a passing run."
  Whatever we choose must fit this ceremony, and must not drag the existing,
  ratified Python exit gate through a re-ratification it does not need.
- Fail-closed pinning and minimal seccomp surface are non-negotiable
  (`AGENTS.md`). The current allowlist (`exec_sandbox.PermittedSyscall`) is a
  closed enum where every entry cites the measured trace that justifies it;
  a Go extension must preserve that discipline — measured entries with
  recorded justifications, never guessed lists.
- Determinism: evidence must be `PYTHONHASHSEED`-independent here as
  everywhere, and the Go additions introduce a new determinism hazard — the
  compiled binary itself. ADR-0021's lesson applies verbatim: "deterministic
  in principle" is not evidence; two runs must measure byte-identical
  digests before anything is ratified.
- ADR-0033 Decision 4's division of labour is fixed: Leitir renders
  assertions, the agent writes the implementation, and no output may claim a
  proof that was not executed.
- Donor execution stays default-off and Linux-only
  (`LEITIR_ENABLE_DONOR_EXECUTION=1`, `pipeline_cli._require_substrate`);
  Go execution cannot weaken or bypass that gate.

## Considered Options

**Asset strategy.**

1. **A1 — extend `containment-rootfs-v1`** with a pinned Go toolchain (and
   whatever build machinery `go test` needs inside the sandbox). Rejected:
   it necessarily changes the asset's canonical tree digest
   (`sha256:ec28886a…`), which is pinned in `containment-environment-v1.json`,
   in the exit-corpus manifest's `runnable.substrate` block, in AGENTS.md and
   README.md, and in the ratified runtime digest chain — so every Python
   donor-execution run would need re-measurement and re-ratification for zero
   Python-side change. It also bloats the trusted computing base of *every*
   Python run with an entire Go toolchain. And, decisively: with the
   pre-compilation approach chosen below, no toolchain is needed inside the
   sandbox at all, so A1 pays its enormous blast radius for nothing.
2. **A2 — ship a second, Go-specific pinned asset** (`containment-rootfs-go-v1`)
   with its own canonical tree digest, its own descriptor, and its own
   ratifiable gate digest. **Chosen.** The Python substrate stays
   byte-identical; only new pins appear; the ceremony cost is paid once, by
   the Go lane that needs it. Crucially, with pre-compilation this asset is
   *minimal* — see below — so "second asset" does not mean "second giant
   asset".
3. **A0 — no new asset; execute the port uncontained.** Not an option.
   ADR-0033 Decision 5 already rejects uncontained execution as a
   substitute for a containment proof; nothing here reopens that.

**Compilation locus.**

1. **C1 — run `go test` inside the sandbox.** Rejected: it requires the full
   toolchain inside the rootfs (the `go` driver `execve`s its `compile`,
   `link`, and `asm` sub-tools), a writable **and executable** build cache —
   but the current mount model deliberately makes the only writable bind
   (`/work`) `noexec` (`exec_sandbox._render_config`) — plus a module cache
   or vendored dependency graph, and a seccomp surface that includes
   everything a parallel compiler needs. That surface is large and drifts
   with every Go release; it cannot be measured to a stable fixed point at
   acceptable cost, and it violates the minimal-surface driver.
2. **C2 — pre-compile `go test -c` OUTSIDE the sandbox; execute only the
   compiled static test binary inside.** **Chosen.** The executed surface is
   then the Go runtime + `testing` framework + Leitir-generated tests —
   bounded, measurable, and independent of build machinery. The residual
   (a trusted, pinned compiler parsing untrusted source outside containment)
   is stated honestly in Consequences and mitigated structurally.

**Outcome normalization.**

1. **N1 — `go test -json` / `test2json` output, parsed by the controller.**
   Rejected: `-json` is a `go`-command-side converter we would have to run
   inside or feed through the sandbox boundary, and its fields (durations,
   package paths) are version-drifting and nondeterministic — the exact
   "raw attacker-influenced text as evidence" shape ADR-0009 §11 forbids.
2. **N2 — controller-side parsing of `-test.v` output.** Rejected: the
   verbose format is an internal, version-sensitive contract of the
   `testing` package; parsing it makes the gate's authority depend on
   unspecified output formatting.
3. **N3 — Leitir-generated harness emits a closed canonical JSON frame.**
   **Chosen.** The translated test file is already Leitir-rendered trusted
   bytes; extend that trust to the outcome channel (details in Decision 3).

## Decision Outcome

Chosen options: **A2 + C2 + N3** — a second, minimal, Go-specific pinned
substrate asset; pre-compilation outside the sandbox with only the compiled
static test binary executed inside; and a Leitir-generated harness that emits
the canonical outcome frame. The three choices reinforce each other: because
compilation happens outside, the substrate needs no toolchain, so the second
asset is a near-empty mount-target skeleton rather than a toolchain image;
because the binary is compiled by the controller, its embedded build
information is trusted input to the donor-ban proof.

### 1. Substrate: `containment-rootfs-go-v1`, minimal and toolchain-free

The Go substrate is a **new published release asset**, built by the same
deterministic discipline as `containment-rootfs-v1` (sorted tar with fixed
mtime/uid/gid, `chmod -R a-w`, canonical tree digest recomputed by every
consumer before policy construction). Its contents are deliberately minimal:

- the deterministic mount-target skeleton — a Go-specific analogue of
  `exec_sandbox.ROOTFS_MOUNT_TARGETS` covering `/`, `/proc`, `/work`, and the
  fixed read-only destination the compiled test binary mounts at (e.g.
  `/port`) — and nothing else. No interpreter, no runner script, no Go
  toolchain, no package site.
- The Python constants, the Python asset, the Python descriptor, and the
  Python seccomp policy remain byte-identical. `ROOTFS_MOUNT_TARGETS` itself
  is not edited; a separate Go target tuple is defined alongside it.

The executed harness lives *inside the compiled binary* (Decision 3), so the
rootfs needs no `/harness/runner.py` analogue. A static `CGO_ENABLED=0`
binary needs no libc, loader, or runtime files from the image; the rootfs
exists to give nsjail a digest-bound, donor-free mount root.

Accompanying pins, all new (no existing pin is edited):

- `src/leitir/containment-environment-go-v1.json` (schema
  `leitir-containment-environment-go-v1`), following ADR-0009 Amendment 1's
  descriptor discipline exactly: it carries the four shared nsjail identity
  pins (unchanged values, since the backend is the same nsjail), the
  **Go rootfs tree digest**, the **pinned Go toolchain identity** (exact
  upstream version string plus the recorded SHA-256 of the pinned toolchain
  archive — the toolchain is an external native prerequisite in the nsjail
  sense, fetched and digest-verified by the controller, never a Leitir
  dependency; `pyproject.toml` stays `dependencies = []`), and the **Go
  seccomp policy digest** (Decision 4). It self-verifies the way Amendment 1
  requires (internal consistency, reject on any mismatch), and resolution
  (`bts_cli.resolve_containment_substrate`-style, per-substrate) remains a
  convenience over — never a substitute for — measured runtime verification.
- A **new Go port-execution gate manifest** with its own `corpus_id` and its
  own `runnable.substrate` block carrying the Go pins.
  `benchmarks/exit-corpus/corpus-v1.1.json`, `ratification-v1.json`,
  `trusted-keys-v1.json`, and the ratified digest
  `sha256:72949674…` are **not touched**: mutating the Python corpus manifest
  would change `corpus_manifest_digest` and invalidate the standing owner
  signature for zero Python-side reason — the exact silent-repin ADR-0009 §3
  forbids.

### 2. Execution model: controller-owned pre-compilation, contained execution

The future `bts-run`-equivalent for ports (implemented as a **distinct
command** — `bts-run`'s flag surface and runner contract are bound to Python
donor relocation and must not be overloaded; the concrete verb name is
non-normative, the separation is) works as follows:

1. **Stage.** The controller assembles the port package from exactly:
   the agent-written implementation source file(s) (untrusted **input**,
   never executed at this stage), the Leitir-generated contract-test file
   (`translate_contract` output, bound by `source_sha256` and
   `contract_digest`), and the Leitir-generated harness (Decision 3). The
   staged tree uses the existing canonical sorted-tree digest discipline.
   The agent never supplies a prebuilt binary — compilation is
   controller-owned, which is what makes the binary's build information
   trustworthy evidence later.
2. **Compile** outside the sandbox with the pinned toolchain and pinned
   flags: `CGO_ENABLED=0`, `GOOS=linux`, `GOARCH=amd64` (the only supported
   target — the substrate is Linux-only, matching ADR-0009 §3),
   `-trimpath` (strips absolute build paths so the binary is
   location-independent), `-buildvcs=false` (no VCS stamping), and a fixed
   `-ldflags` freeze. `CGO_ENABLED=0` is load-bearing three ways: it
   produces a static binary with no dynamic loader or `dlopen` surface, it
   removes cgo's build-time execution of a C toolchain on untrusted source,
   and it shrinks the runtime syscall surface to the pure-Go runtime.
   The measured binary SHA-256 is recorded as evidence.
3. **Inspect** the compiled binary's embedded build information
   (controller-side, via the same pinned toolchain's `go version -m`; the
   output is canonicalized and digest-bound). See Decision 3.
4. **Execute** the binary inside nsjail under the Go containment policy:
   the binary bind-mounted **read-only** (read-only binds are executable —
   only the writable `/work` bind is `noexec`, and the binary deliberately
   does not live there), launched as the PID-1 process of the one-shot
   clone, with `/work` as the noexec scratch. The child environment
   allowlist is the Go policy's own (e.g. `GOMAXPROCS=1` to bound thread
   creation and scheduling variance, `TZ=UTC`, `LANG=C.UTF-8`); numeric
   limits (memory, pids, CPU, wall) are per-substrate policy inputs — this
   ADR requires but does not choose them, exactly as ADR-0009 treats
   `DonorExecutionPolicy` values. A Go runtime creates OS threads even at
   `GOMAXPROCS=1`; `cgroup_pids_max` must be measured in Phase A against
   the real binary, not inherited from the Python policy.
5. **Verify** exactly as the Python pipeline does: the harness's startup
   attestation validated by the existing attestation machinery, cgroup-kill
   teardown, output limits, post-launch scratch quota — unchanged mechanisms,
   re-pointed at the Go policy.

`LEITIR_ENABLE_DONOR_EXECUTION=1` and the Linux/nsjail availability check
(`pipeline_cli._require_substrate`) gate this path identically; the pinned
Go toolchain availability is an additional fail-closed precondition.

### 3. The Go analogues: relocation, donor-ban, exact parity

**Relocation → staged port package + reproducible compile.** The Python
pipeline relocates donor bytes into a recipient namespace and proves the
relocated artifact donor-free. A port shares zero donor bytes (ADR-0033
Decision 2), so there is nothing to relocate in that sense; the analogous
invariant is over the *compile unit*: the staged port package (agent source
+ generated test + generated harness) has a canonical tree digest; compiling
it under the pinned toolchain and flags must reproduce a **byte-identical
binary** across runs and runner images. That reproducibility is not assumed —
Phase A and Phase C both measure the binary digest, and a mismatch is drift
to reject and investigate, not a fresh value to ratify (ADR-0021's lesson,
applied before ratification instead of after).

**Donor-ban → mount absence + linked-content proof.** Two layers, mirroring
ADR-0009 §6's "the OS/filesystem claim is the boundary; diagnostics never
prove absence":

1. *Filesystem layer, unchanged in kind:* the Go mount plan mounts no donor
   snapshot and no donor parent — only the Go rootfs, the read-only test
   binary, and the `/work` scratch. The generated harness emits a
   `leitir-contained-startup-attestation-v1` receipt (PID 1 in the cloned
   namespace, `Seccomp: 2`, `NoNewPrivs: 1`, namespace-identity comparison)
   as its first output line, before any contract test runs; the controller
   validates it with the same validator the Python runner's receipt uses.
2. *Linked-content layer, new:* a compiled artifact can embed code the
   filesystem proof says nothing about, so the controller additionally
   requires — from the binary's build information, which is trustworthy
   precisely because the controller performed the compilation — that the
   linked module set is exactly **{the staged port module} ∪ {standard
   library}**. Zero third-party modules, full stop: the portable contract's
   value domain (bool/int/float/string/list compared via `reflect.DeepEqual`)
   needs only stdlib, so any linked non-stdlib module is rejected
   (`REJECT_PROVENANCE_MISMATCH`, detail code on the pattern
   `port_go_nonstdlib_module_linked_v1`). This closed allowlist is also the
   honest answer to "what about a donor-published Go SDK?" — nothing can be
   linked, donor-derived or otherwise. The build-info block's digest is
   bound into the evidence, and the harness frame echoes it so the executed
   binary is cross-checked against the inspected one. The residual this
   does *not* cover — an agent re-typing donor logic by hand — is not a
   containment question at all: that is ADR-0033's behavioural-descent
   model, where the contract bounds the behaviour and the attribution
   carries the obligations. A static `CGO_ENABLED=0` binary additionally
   has **no dynamic loading path at all** (no `dlopen`, no plugin mechanism
   reachable), a structural strengthening relative to Python's import
   surface.

**Exact parity → suite-case-set equality, all-PASS.** For a Python
transplant, parity compares donor-present baseline vs donor-absent rerun
outcomes. For a port, the donor-present baseline *is the portable contract*:
every case asserts the donor function's outcome for given args, and the
suite is digest-bound to the `COMPLETE` BTS. Therefore the Go run must emit,
for **exactly** the case set the suite names (case name →
`TestPortableContract_<Ident>`, collision-checked at translation time by
`_validate_go_identifier_namespace`), the outcome PASS for every case:

- zero/extra/missing/duplicate case IDs, or any mismatch between the
  emitted outcome set and the suite's case set, is the
  `REJECT_COVERAGE_MISCOUNT` analogue — a skipped or dropped case is never
  silently excused;
- any FAIL is the `REJECT_SEMANTIC_DEGRADATION` analogue — a Go
  implementation that fails the translated contract is never admitted;
- missing/malformed startup attestation, harness failure, non-zero exit,
  timeout, or output-truncation is the `REJECT_HARD_GATE_FAILED` /
  noncanonical-abort-envelope analogue — no canonical report is published
  for an operational failure.

**Outcome channel (N3).** The Leitir-generated harness — trusted bytes in
the same package, digest-bound alongside the translated test file — is a
`TestMain` plus per-case outcome registration: each generated test function
records its own terminal outcome (via a `defer`-based registration that
observes `t.Failed()` even when `t.Fatalf` unwinds the goroutine), and
`TestMain` flushes one strict canonical JSON frame after the run: the
startup attestation, the per-case `{case_id, outcome}` vector, the
build-info echo, and a `recorder_complete`-style teardown flag — a
`leitir-port-runner-frame-v1` analogue of the Python runner's
`leitir-rerun-runner-frame-v1`. The controller parses **only** this frame;
`t.Fatalf` messages remain inside the binary's bounded, noncanonical
stdout. No `test2json`, no `-json` flag, no version-sensitive output
parsing anywhere in the authority path. The wrapper evidence
(`PortExecutionEvidence`, schema `leitir-port-contract-execution-v1`,
canonical-JSON digest per ADR-0009 §11's discipline: closed typed values,
no timestamps/PIDs/paths) binds: suite and contract digests, the staged
tree digest, the toolchain pins, the binary SHA-256, the build-info digest,
the Go policy and mount-plan digests, the startup attestation, the per-case
outcome vector, and counts. `containment_proof` in the CLI payload moves
off `not_executed_v1` only when backed by such evidence — never before.

### 4. Seccomp and policy delta: measured, typed, separate

The current allowlist is measured for the pinned CPython/runner closure.
The Go policy is **not** that list plus a guessed delta:

- The Go allowlist is a **separate typed policy artifact** (e.g.
  `CANONICAL_GO_SECCOMP_POLICY`), selected per substrate. Today
  `ContainmentPolicy.seccomp_string` is hard-wired to the single canonical
  Python policy; the implementation must make the policy instance carry its
  own seccomp binding so the Python canonical policy text stays
  byte-identical. Extending the shared enum instead would silently widen
  the syscall surface of every Python donor-execution run — a substrate
  change smuggled inside a code edit, exactly what ADR-0009 §3 forbids.
- The Go list is **measured from scratch** for the pinned binary closure,
  starting from the typed model, by the existing diagnostic paths
  (`LEITIR_NSJAIL_DEBUG=1` seccomp logging inside nsjail, plus `strace` on a
  measurement host outside policy construction), iterated to a fixed point:
  re-run until there are no denied calls and no unmeasured retained
  entries, and every enum entry cites the recorded trace that justifies it,
  matching the justification discipline visible on every current entry of
  `PermittedSyscall`.
- **Candidates to measure** (expectations from the pure-Go runtime, stated
  as measurement targets, not conclusions): thread management (`clone3`
  with fallback to `clone` on current Go releases — argument-constrained in
  the Kafel rule to thread-creation flag shapes, mirroring the existing
  `epoll_create1 { flags == 524288 }` precedent, since unconstrained clone
  is namespace-joining territory; `tgkill` for preemption/GC signals);
  signal plumbing (`rt_sigreturn`, `sigaltstack`); memory management
  (`madvise`; `mmap`/`mprotect`/`mremap` are already permitted for CPython
  but must be re-measured for the Go allocator's flag usage); scheduling
  (`sched_yield`; `clock_nanosleep`/`nanosleep` for the sysmon thread); and
  the netpoller entries (`epoll_create1`/`epoll_ctl`/`epoll_pwait`) **only
  if** measurement shows the pinned closure initializes netpoll — the
  generated contract tests import no `net`, so the expectation is that it
  does not. Conversely, glibc-justified entries in the Python list
  (`rseq`, `set_robust_list`, `prlimit64` startup probing) are expected to
  be absent from a `CGO_ENABLED=0` binary's trace; if measurement
  contradicts any expectation, the measurement wins and the expectation is
  corrected in the ADR's implementation notes.
- Any measured requirement intersecting `_FORBIDDEN_SYSCALLS` (the socket
  family, `ptrace`, `mount`, `unshare`, …) is a **design stop**, not an
  allowlist edit: it means the artifact's closure is wrong for containment,
  and the pipeline rejects rather than widens. The same holds for a future
  Go runtime revision whose syscall surface crosses a forbidden class.

### 5. Publication, repin, and re-ratification ceremony (ADR-0009 §3/§10)

Mapped to concrete artifacts, following the precedent of the 2026-08-17
Python ceremony recorded in `benchmarks/exit-corpus/README.md`:

1. **Publish.** A workflow path (new inputs or a sibling workflow — the
   existing `bts-containment.yml` rootfs-job pattern is the template) builds
   `containment-rootfs-go-v1` deterministically and publishes it as its own
   release asset with notes recording the canonical tree digest and
   tarball SHA-256. It never uploads to, clobbers, or edits the
   `containment-rootfs-v1` release.
2. **Repin.** `containment-environment-go-v1.json` and the new Go gate
   manifest land with the measured digests, in a change separate from the
   asset publication, exactly as Amendment 1 prescribes for descriptor
   updates. No existing pin file changes.
3. **Phase A (unratified measurement).** The Go gate runs unratified on CI;
   it must **honestly reject** while publishing the stable Go runtime
   digest — which binds the staged package digests, translated-contract
   digest, measured binary SHA-256, build-info digest, measured seccomp
   policy text, Go rootfs tree digest, and toolchain pins. Stability is a
   precondition: at least two independent runs must measure the identical
   digest (and byte-identical binaries) before Phase B, per ADR-0021's
   drift lesson; an unstable digest is held, not hand-waved.
4. **Phase B (out-of-band ratification).** The owner signs the canonical
   projection `{corpus_id, corpus_manifest_digest,
   ratified_runtime_digest}` with the long-term owner ratifier key
   (`7baec2e9…`, or a successor rotated per ADR-0022) and publishes a
   `ratification-go-v1.json` sidecar (schema `leitir-manifest-auth-v1`)
   outside the donor shelf. **The private key is owner-held out of band
   (never in the repository, never in CI); no agent, PR, or workflow can
   perform this step.** This boundary is the ceremony's entire point: a
   digest computed by this repository binds content but cannot ratify it.
5. **Phase C (ratified rerun).** The Go gate reruns with `--trusted-keys`;
   the summary must flip from reject to complete. Only then may
   `containment_proof` move off `not_executed_v1` in any output, and only
   for runs whose evidence actually executed under the ratified substrate.

Any later change to the Go rootfs, seccomp policy, pinned toolchain
(including a Go version bump — the runtime syscall surface drifts across
releases), or gate composition restarts this ceremony from Phase A. There
is no routine repin.

## What this ADR does not do

- It does not replace `"containment_proof": "not_executed_v1"` today. That
  string remains the honest description of `bts-port-contract` until the
  implementing pipeline and the Phase-C complete run land; nothing in the
  interim may claim an executed proof.
- It makes **no Windows or macOS containment claim**. The Go substrate, like
  the Python one, is Linux/nsjail-only; anything else rejects.
- Go execution tests stay **gated** (`LEITIR_ENABLE_DONOR_EXECUTION=1` plus
  substrate availability, exactly as ADR-0009 §10 fixes for the Python
  lane) and out of the default suite — the dev environment for this ADR
  has no nsjail, rootfs, or Go toolchain, and ungating would fake the very
  evidence this pipeline exists to make unfakeable.
- It does not widen ADR-0033's portable subset: RETURN-only,
  scalar/list-of-scalar, RAISES still rejects; no cgo; no third-party Go
  modules; no target language beyond Go; `GOOS=linux/GOARCH=amd64` only.
- It does not touch the Python transplant pipeline, `corpus-v1.1.json`, the
  standing ratification, or `containment-rootfs-v1` — Python-side artifacts
  are unchanged by construction.
- It decides the substrate and proof semantics, not the future command's
  full flag surface; that follows the Amendment-1 resolution pattern once
  implementation starts.

## Positive Consequences

- Issue #277's blocker dissolves into buildable steps: a small asset, a
  measured policy, a harness, and a ceremony with an existing precedent.
- The second asset is *minimal* (a mount-target skeleton), keeping the new
  trusted computing base tiny; no Go toolchain ever enters any sandbox.
- The executed syscall surface is the Go runtime of one pinned toolchain
  version under a measured, typed, separately-ratified policy — the Python
  lane's guarantees are neither reused loosely nor weakened.
- Controller-owned compilation turns build information into trustworthy
  evidence, closing the forged-build-info hole by construction rather than
  by heuristic.
- The Python exit gate, its ratified digest, and its signature remain valid
  throughout — zero forced re-ratification for the existing lane.

## Negative Consequences and residual risks

- **Two substrates to maintain.** Each Go toolchain bump is a substrate
  change (fresh Phase A, likely fresh policy measurement, possibly
  re-ratification). Pinning the exact version and digests is mandatory;
  "just upgrade Go" is never routine.
- **Compile step outside containment processes untrusted source with a
  trusted pinned compiler.** A compiler-parsing vulnerability in the pinned
  toolchain is a pre-execution attack surface the Python lane does not
  have. Mitigations are structural, not eliminative: the toolchain is
  digest-verified before use, `CGO_ENABLED=0` removes the cgo/gcc
  build-time execution vector, and the compiled artifact is still only ever
  *executed* inside the sandbox. This residual is accepted knowingly and
  must be recorded in `SECURITY.md` alongside the existing kernel/nsjail
  residuals.
- **Go runtime syscall-surface drift** across toolchain versions (new
  syscalls, changed flag usage) can break a ratified policy on upgrade —
  fail-closed by design (denied call → kill → noncanonical abort), at the
  cost of ceremony repetition.
- **Threads and grandchildren.** A Go test binary is multi-threaded where
  the Python runner is effectively single-threaded: thread-creation
  syscalls must be permitted (measured, argument-constrained), and the kill
  story leans entirely on the existing cgroup v2 `cgroup.kill` authority —
  which ADR-0009 §3 already makes the only success-producing path, so no
  weakening is needed, but `cgroup_pids_max` and CPU budgets need
  Go-measured values rather than Python's.
- **Reproducible-build dependence.** If the pinned toolchain + flags do not
  yield byte-identical binaries across runner images, Phase A/C digest
  stability fails; the ceremony holds (rejects) until the cause is found —
  the ADR-0021 experience suggests path/time stamping is the likely first
  culprit, hence `-trimpath -buildvcs=false` up front.
- The harness-in-binary design means the trusted outcome channel ships
  compiled with untrusted implementation code in one artifact; the boundary
  is maintained by digest-binding the trusted inputs (generated files) and
  by the closed frame schema, but reviewers must treat any harness change
  as security-relevant (independent review per the repo's review
  discipline).

## Links

- Issue [#277](https://github.com/anthonykewl20/leitir/issues/277) — D1 remainder: execute an agent-written port against the translated contract under containment
- Issue [#270](https://github.com/anthonykewl20/leitir/issues/270) — D1: evidence-assisted cross-language port
- [ADR-0009](0009-transplant-validation.md) — Transplant validation; §3 (substrate change rule), §10 (E4a/E4b ratified corpus authority), Amendment 1 (containment environment descriptor)
- [ADR-0033](0033-evidence-assisted-cross-language-port.md) — Evidence-assisted cross-language port (this ADR supersedes, **for Go only**, its premise that a Go-capable substrate means "adding a Go toolchain to the pinned rootfs" (Decision 3) and, once the pipeline and Phase-C run land, its "explicitly unproven" status for executed Go proof (Decision 5); its Decision 4 hard boundary and its portable-subset rejection semantics are unchanged)
- [ADR-0021](0021-deterministic-donor-mount-projection.md) — digest-stability lesson applied to binary reproducibility
- [ADR-0022](0022-trusted-key-lifecycle.md) — key rotation for any future re-signing
- [ADR-0020](0020-go-module-authenticity-via-sumdb.md) — Go module authenticity (shelf acquisition; orthogonal to this ADR, and intersecting it only trivially since the v1 module allowlist is stdlib-only)
- `benchmarks/exit-corpus/README.md` — the Phase A→B→C ceremony precedent and the owner-key boundary
- `src/leitir/exec_sandbox.py`, `src/leitir/pipeline_cli.py`, `src/leitir/bts_cli.py`, `src/leitir/port_contract.py`, `src/leitir/containment-environment-v1.json`, `.github/workflows/bts-containment.yml`
