# ADR-0009: Transplant validation

- Status: Accepted
- Implementation: (B6, E1, S2, E2, E3, E4a, E4b complete)
- Deciders: leitir maintainers; consensus reviewers (consensus-luna, consensus-terra)
- Date: 2026-08-11
- Technical Story: Epic #52; B6, E1, E2, E3, E4a, E4b, and S2 (#55, #60-#64, #73)
- Proposed repository filename: `docs/adr/0009-transplant-validation.md`

## Context and Problem Statement

ADR-0008 defines a deterministic, content-addressed Behavioral Transplant Set
(BTS). Its `BTSStatus.COMPLETE` result is necessary but does not establish that
the authorized bytes can be relocated into an empty project and preserve their
pinned behavior without using the donor at rerun time.

This decision defines deterministic relocation, baseline capture, contained
execution of untrusted donor code, a filesystem-enforced donor ban, exact
behavioral parity, diagnostic runtime evidence, reviewed probes, and the
v0.1.2 corpus gate. It extends but does not alter ADR-0008's
`COMPLETE`/`PARTIAL`/`REJECT` algebra: only an ADR-0008 `COMPLETE` result has a
`BTS` and may enter relocation. Runtime evidence cannot clear an ADR-0008
blocker or change an existing result.

## Decision Drivers

- Reruns must exercise transplanted bytes, never an installed or materialized
  donor copy.
- Python import hooks are diagnostic mechanisms, not security boundaries.
- Donor production code, tests, fixtures, plugins, extensions, and child
  processes are untrusted arbitrary code.
- Test collection, canonical test identity, pass/fail/skip counts, and each
  per-test outcome must remain accountable.
- Relocation may perform proved import rewrites and add already-authorized
  scaffold, but may not guess a binding, collide with a reserved namespace, or
  silently enlarge the BTS.
- Every canonical artifact binds the same full donor-tree identity and primary
  `bts_digest` authorized by ADR-0008. Digests establish integrity and subject
  binding, not producer or donor authenticity.
- Outputs must be bounded, deterministic, `PYTHONHASHSEED`-independent, and
  fail closed.
- Leitir remains fully typed Python 3.11+ using
  `from __future__ import annotations` and only the standard library at runtime.

## Considered Options

- Copy and test the whole donor package.
- Relocate a `COMPLETE` BTS, rewrite a pinned test subset, and require exact
  baseline parity with the donor absent from the rerun filesystem (chosen).
- Accept a green test-process exit or aggregate counts alone.
- Use Python import/audit hooks to establish donor absence.
- Let runtime observations repair static blockers.
- Execute after opt-in with Python `resource`, audit hooks, or timeouts alone.
- Support one pinned Linux-native containment backend, nsjail (chosen for v1).

## Decision Outcome

Chosen option: "relocate a pinned `COMPLETE` BTS and validate it under two
attested nsjail executions with distinct mount plans", because the OS/filesystem
boundary can exclude donor bytes from the rerun while exact pinned outcomes
test preservation without weakening ADR-0008.

### 1. Validation contract and state algebra

All normative records are frozen, slotted dataclasses. Enums serialize by
`.value`; unions have closed tags; unknown fields, versions, enum values,
unbounded integers, malformed digests, and duplicate exhaustive ordering keys
reject.

```python
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

class ValidationStatus(str, Enum):
    COMPLETE = "complete"
    REJECT = "reject"

class TestOutcome(str, Enum):
    PASS = "pass"
    FAIL = "fail"
    SKIP = "skip"

@dataclass(frozen=True, slots=True, order=True)
class OutcomeCounts:
    passed: int
    failed: int
    skipped: int

@dataclass(frozen=True, slots=True, order=True)
class TestOutcomeEvidence:
    canonical_test_id: str
    outcome: TestOutcome
    detail_category: str
    detail_digest: str

@dataclass(frozen=True, slots=True)
class ValidationInputs:
    schema_version: str
    donor: DonorProvenanceEvidence
    bts_digest: str
    member_equivalence_digest: str
    relocation_policy_digest: str
    baseline_digest: str
    shared_execution_policy_digest: str
    baseline_execution_policy_digest: str
    rerun_execution_policy_digest: str
    baseline_mount_plan_digest: str
    rerun_mount_plan_digest: str
    runtime_evidence_contract_digest: str
    probe_set_digest: str

@dataclass(frozen=True, slots=True)
class TransplantValidationReport:
    schema_version: str
    status: ValidationStatus
    inputs: ValidationInputs
    relocation: RelocationEvidence
    donor_ban: DonorBanEvidence
    baseline: ContractBaselineEvidence
    rerun: RerunEvidence
    runtime: RuntimeDiagnosticEvidence | None
    probes: tuple[ProbeOutcomeEvidence, ...]
    blockers: tuple[ValidationBlocker, ...]
    validation_digest: str

def validate_transplant(
    result: BTSResult,
    tests: PinnedContractTestSet,
    baseline: ContractBaselineEvidence,
    relocation: RelocationPolicy,
    execution: DonorExecutionPolicy,
    probes: PinnedProbeSet,
) -> TransplantValidationReport: ...
```

The boundary recomputes and validates the ADR-0008 report, `bts_digest`, donor
provenance, and `BTSStatus.COMPLETE`/non-null-BTS consistency. `PARTIAL` remains
non-relocatable with `bts=None`; `REJECT` remains terminal. Validation has no
score or compensating success path.

Child output is always untrusted. A frame digest detects corruption but does not
authenticate its producer. The trusted controller independently checks the
read-only input manifests, mount/cgroup/backend receipts, expected result shape,
and all authorizing-byte hashes. Trust in the execution claim comes from that
validated controller/backend boundary, not from a child-authored digest.

### 2. Deterministic relocation and namespace safety (E1)

Relocation writes a sibling temporary root and atomically publishes it with the
existing tempfile, flush/fsync, `os.replace`, and directory-fsync discipline.
The initial recipient is exactly a pinned empty-project scaffold. Absolute or
parent paths, symlinks, case-fold or Unicode-normalization aliases, duplicate
outputs, and file/directory prefix conflicts reject before a write.

`RelocationPolicy` content-pins a total one-to-one `ModuleMap`, package root,
finite ADR-0008 ADAPT catalog references, scaffold algorithm, rewrite algorithm,
reserved-module manifest, recipient binding manifest, and claimed platform
identities. Collision checks cover both output paths and Python binding scope:
each rewritten import's local binding and each emitted top-level definition must
be unique and compatible in its recipient scope. The relocator never relies on
import precedence, overwrites a binding, or chooses a suffix.

The reserved-module manifest includes all modules and prefixes owned by the
pinned interpreter build, pure stdlib, `BuiltinImporter`, `FrozenImporter`,
importlib bootstrap, selected test runner and plugins, and the trusted Leitir
launcher/scaffold. A target name already present in the launcher's initial
`sys.modules`, or mapping onto names such as `json`, `pytest`, or an importlib
bootstrap module, rejects. Reservation is manifest-based; host discovery cannot
widen it.

V1 rewrites only statically proved `ast.Import` and non-star `ast.ImportFrom`
sites. It normalizes relative imports against ADR-0008's unique package root,
preserves aliases/local bindings, and rewrites donor-root imports in pinned
tests. Star/dynamic/conditional/fallback imports, ambiguous exports, namespace
packages, and an unrewritten donor reference reject with the applicable
`REJECT_UNSUPPORTED_CONSTRUCT` or `REJECT_UNRESOLVED_EDGE` detail code.

Relocation begins with exactly the ADR-0008 member spans and required scaffold.
If valid emission requires a wider decorator, suite, declaration, future import,
docstring, or other span, it returns `REJECT_UNDER_COLLECTION` with
`RequiredSpanExpansionEvidence`. A caller must recompute ADR-0008 and obtain a
new `bts_digest`; relocation never silently expands authorizing bytes.

The interim canonical staging layout is fixed now, while ADR-011 owns eventual
public packet paths:

```text
staging-v1/
  manifests/{input,relocation,source,test,probe,runner}.json
  src/                 # relocated production bytes
  tests/original/      # original selected tests
  tests/rewritten/     # relocated tests
  probes/              # reviewed probe bytes
  harness/             # trusted pinned launcher/adapter
```

Every regular file appears exactly once in a sorted manifest with relative POSIX
path, role, bounded size, mode, and SHA-256. Undeclared entries reject.

### 3. One backend, two mount plans, immutable execution inputs (S2/E2)

V1 supports Linux only and exactly one backend: a release-pinned **nsjail**
binary invoked as a subprocess. Its version, executable SHA-256, build identity,
configuration-schema digest, rootfs digest, and architecture are policy inputs.
NsJail is an external native execution prerequisite, not a Python package and
not a runtime dependency of Leitir; `pyproject.toml` remains `dependencies = []`.
An unsupported OS, architecture, kernel capability, nsjail build, binary digest,
configuration, cgroup delegation, or rootfs rejects before donor code executes.
There is no portable, `resource`-only, bubblewrap, Firejail, container, or
unsandboxed fallback.

The separately versioned, corpus-measured `DonorExecutionPolicy` supplies every
positive numeric limit; this ADR does not select values. It pins locale,
timezone, architecture, rootfs, CPython build, environment allowlist, runner
closure, cgroup v2 controls, seccomp policy, output/evidence limits, and a shared
policy digest. Each role then has a distinct execution-policy digest that binds
the shared digest, role, and mount-plan digest. Consequently baseline and rerun
cannot claim the same `execution_policy_digest` while exposing different donor
mounts.

Both generated nsjail configs must explicitly set and the controller must verify:

- `mode: ONCE`, `keep_env: false`, and read-only `mount_proc: true`;
- `clone_newnet`, `clone_newuser`, `clone_newns`, `clone_newpid`,
  `clone_newipc`, and `clone_newuts` to `true`;
- exactly one down `lo` interface and no route (`iface_no_lo: true` prevents
  nsjail from bringing loopback up); every other interface or `lo` state rejects;
- positive `cgroup_mem_max`, `cgroup_pids_max`, and
  `cgroup_cpu_ms_per_sec`, using a verified cgroup v2 hierarchy;
- a `seccomp_string` generated only from Leitir's typed canonical syscall/action
  model: one closed minimal allowlist and `DEFAULT KILL`. Caller-authored Kafel
  (including comments, `LOG` blocks, and numeric syscall forms) is not parsed or
  accepted; networking, socket, mount/namespace joining, privilege, ptrace, and
  other policy-forbidden syscalls are absent from the allowlist. The sole
  argument-constrained exception is CPython's `ioctl(TCGETS)` terminal probe,
  rendered from a typed rule as `ioctl { cmd == 21505 }`; it cannot issue other
  ioctl operations; and
- pinned rlimits for address space, CPU, file size, open files, processes,
  stack/core and every applicable limit, as defense in depth rather than the
  containment boundary.

The immutable rootfs runner emits a startup receipt before it discovers or
imports contract-test input. It reads `/proc/self/status`, requires
`Seccomp: 2` or `NoNewPrivs: 1`, requires itself to be PID 1 in the cloned PID
namespace, and compares all six `/proc/self/ns/*` identities with the parent
identities injected only into the one-shot nsjail config. A missing, malformed,
or nonmatching receipt rejects the rerun. This is the authoritative
post-install verification for the pinned nsjail semantics; parent process-group
observation plus `SIGSTOP` remains forbidden because it is racy. Offline
inspection never emits a verified execution receipt.

There are two explicit sorted mount manifests:

- **Baseline:** mounts the verified donor snapshot read-only, original selected
  tests read-only, trusted interpreter/rootfs/runner/bootstrap/manifests
  read-only, and one policy-pinned writable staging scratch bind at `/work`.
- **Rerun:** does not mount the donor or any donor parent; mounts relocated
  source, rewritten tests, probes, trusted interpreter/rootfs/runner/bootstrap,
  and manifests read-only below the separate policy-pinned writable staging
  scratch bind at `/work`. NsJail creates each bind target while building the
  mount tree, so file-granular rerun targets are below `/work/staging-v1`, not
  the digest-bound rootfs; exact source digests and read-only mount flags are
  unchanged.

At rerun entry the controller re-derives the relocation digest from the complete
canonical file and authorization records and requires exact mount-destination
set equality with the relocation plus trusted runtime/rootfs closure. Missing
and extra mounts both reject. Relocation and rerun also re-derive both BTS
identity digests from a supplied `BTSResult` report/artifact pair, so a genuine
report wrapped around substituted BTS records has no authority.

The rootfs source is a directory pinned by a canonical sorted tree digest that
includes every directory path/mode and every regular-file path/mode/SHA-256;
symlinks and special files reject. Other read-only mount sources remain
regular-file SHA-256 pins. A pre-created, writable `<staging>/scratch` directory
is a policy-pinned bind source over the immutable rootfs's pre-created `/work`
target; it is the only writable mount and supplies CWD, temporary files, result
frames, and bytecode cache if enabled. The controller clears it before every
launch so baseline and rerun cannot communicate through stale writable state.
The bind is `rw,noexec,nosuid,nodev`; its target and source path are pinned.
`rlimit_fsize` bounds each file written by the child. Unlike the replaced tmpfs,
the bind has no policy-enforced aggregate byte or inode cap: output/frame
retention remains bounded, but staging storage capacity is an explicit
operational tradeoff managed by the execution host.
Interpreter binaries/libraries, baseline donor bytes,
relocated source, original/rewritten tests, probes, runner, bootstrap, and every
authorizing manifest remain read-only. The controller hashes them before and
after execution; any change or inability to re-read rejects. No host home,
repository, corpus, credential/socket, arbitrary `/tmp`, device, or package site
is visible.

Because nsjail opens bind sources as the mapped invoking identity, immutable
staging ancestors are searchable. When a sudo-root controller published an
owner-only relocation tree, it transfers that tree's ownership to the mapped
invoking identity without changing its modes or bytes. This is required for
mount construction while preserving the directory-tree digest pinned by policy.

Execution additionally requires exact opt-in
`LEITIR_ENABLE_DONOR_EXECUTION=1`; only `opt_in_satisfied` is retained. Live
acquisition separately requires `LEITIR_ENABLE_LIVE_E2E=1`. The parent enforces
a wall deadline and bounded stdout/stderr/frame retention, then on every outcome
(success, crash, timeout, or truncation) uses cgroup v2 `cgroup.kill` to kill the
complete tree and verifies `populated 0`. `killpg` is only a nonauthoritative
fallback and therefore can never produce success. Limits and
mount controls are non-compensating. `SECURITY.md` must document these controls
and residual kernel/nsjail escape risk before S2 ships.

### 4. Deterministic interpreter and runner contract

The child does **not** use CPython `-I`: isolated mode implies `-E` and ignores
all `PYTHON*` variables, including `PYTHONHASHSEED`. V1 launches the pinned
CPython build with `-S -s -P` and a controller-created exact environment that
contains a fixed numeric `PYTHONHASHSEED`, fixed UTF-8 locale, `TZ=UTC`, fixed
encoding settings, and only policy-listed names. The launcher verifies the
effective flags, hash-seed sentinel, locale, timezone, `sys.path`, architecture,
and interpreter/rootfs identity before loading untrusted bytes.

The test runner is a pinned external tool in the execution rootfs, not a Leitir
runtime dependency. The receipt binds its command/argv, executable and package
bytes, configuration bytes, import mode, complete plugin/autoload closure, and
adapter bytes. Pytest, when selected, must explicitly pin a non-`prepend` import
mode because pytest's default `prepend` mode mutates `sys.path`; ambient plugin
autoload is disabled. Any undeclared runner/plugin/config import is an
infrastructure failure.

### 5. Attestable baseline and exact parity (E2)

Baseline capture runs original, unmodified selected tests against the read-only
verified donor under the baseline mount plan. It binds a trusted controller and
backend capability receipt, reviewed corpus/case manifest, runner/config/plugin
closure, shared and baseline execution policies, environment, interpreter, and
original test bytes. A baseline cannot be hand-edited or refreshed in the same
change merely to make a transplant pass.

`PinnedContractTestSet` contains maintainer-reviewed canonical test IDs and
source/parameter provenance. IDs are runner-independent tuples serialized to a
pinned string form from manifest-relative source path, lexical test identity,
and canonical parametrization key. Runner-generated node IDs are only
noncanonical diagnostics and never authority.

The same validation applies while constructing a baseline and while comparing a
rerun:

- zero/extra/missing/duplicate IDs, collection/selection/ID/count/skip mismatch,
  or outcome-vector shape/totals mismatch is `REJECT_COVERAGE_MISCOUNT`;
- a different outcome for the same canonical ID is
  `REJECT_SEMANTIC_DEGRADATION`; and
- setup/collection adapter crash, undeclared plugin, malformed runner frame,
  teardown failure, or other runner/infrastructure failure is
  `REJECT_HARD_GATE_FAILED` unless a more specific execution-threat reason
  applies.

Acceptance requires exact canonical-ID tuple equality, exact passed/failed/
skipped counts, exact per-ID outcome equality, successful teardown, and all
independent gates. Issue #63 currently overuses `REJECT_HARD_GATE_FAILED` for
count deltas; its text must be updated to this aligned split.

Generic parity may preserve a pinned nonzero-failure baseline. The v0.1.2 E4b
exit policy is stricter and independently requires `baseline.failed == 0` for
every corpus case.

### 6. Donor-ban proof and diagnostic import recording (B6)

Rerun donor absence is proved by the nsjail mount namespace: the donor and its
parents are absent, while every visible executable/importable input is an
immutable read-only allowlisted manifest entry. The trusted controller compares
the realized mount receipt to `rerun_mount_plan_digest`. Python path filters,
`sys.modules` inventories, audit hooks, import guards, and recorders do not prove
absence and are not part of the security boundary.

The B6 recorder is diagnostic-only. It records a bounded closed classification
of attempted and successful imports, initial/final module inventory digests, and
loader/origin classifications. Malicious child code may bypass or disable it;
therefore an absent event proves nothing. An observed donor-prefix import or
origin matching donor bytes is nevertheless terminal
`REJECT_DONOR_IMPORT_OBSERVED`, even if caught or if tests otherwise match.
Recorder failure cannot weaken the filesystem proof, but it fails the required
diagnostic gate and emits no canonical report.

Canonical output contains only bounded typed categories, counts, sorted digest
records, and fixed reason/detail codes. It never retains raw module names,
paths, exception strings, reprs, denied import arguments, or other
attacker-controlled event text. An optional separately protected noncanonical
envelope may retain bounded escaped detail. Evidence-size overflow rejects
before retention; events are never silently dropped or summarized into a
passing report.

Loader identity is explicit, never inferred from `sys.stdlib_module_names`:

- `BuiltinImporter` entries bind the exact interpreter-build identity;
- `FrozenImporter` entries bind interpreter build, frozen-module name, and
  frozen byte/code digest where representable by the pinned build manifest;
- pure-source/bytecode loaders bind manifest path role and exact bytes digest;
- `ExtensionFileLoader` entries bind interpreter ABI/build, architecture,
  canonical origin role, extension artifact bytes, and transitive native-library
  closure digest; and
- bootstrap/test/scaffold loaders have separate reserved manifest roles.

Unknown, synthetic, originless, changed, or preloaded target modules reject
unless represented exactly by the applicable closed manifest. Target ModuleMap
names already preloaded by the trusted launcher reject before arming.

### 7. Runtime evidence is diagnostic-only (B6)

V1 runtime evidence can report a candidate need and may initiate a **fresh**
`compute_bts` over newly collected static scope. It may never resolve a binding,
append a member, turn the current artifact into `COMPLETE`, or clear an
ADR-0008 terminal blocker. The existing algebra remains:

```text
static REJECT   + runtime evidence = REJECT
static PARTIAL  + runtime evidence = PARTIAL; no relocation
static COMPLETE + conforming diagnostic = validation may continue
static COMPLETE + out-of-set observation = REJECT; fresh analysis required
```

If runtime evidence is carried, every event uses a closed schema binding: the
corresponding ADR-0008 manifest entry/candidate scope entry; source-site or
CPython audit-event provenance; explicit loader kind; exact loaded bytes digest;
donor tree and `bts_digest`; relocated tree; test/probe set; interpreter build;
stdlib/rootfs/environment/execution and mount-policy digests; typed result
category; and prospective/retained byte and event counters. A record lacking any
applicable field rejects. Name coincidence and free-form traces have no
authority.

### 8. Required probes in a fresh child (E3)

Every validation input contains an explicit `PinnedProbeSet`; `None` is not
accepted. The set consists only of maintainer-authored, independently reviewed,
content-pinned assertions linked by pinned `TESTED_BY` edges. V1 does not infer
expected values from prose or synthesize semantic assertions. An explicit empty
set is valid only when a deterministic applicability walk proves that no
`TESTED_BY` probe in the ratified probe catalog applies to the current seed or
BTS members; the derivation and catalog digest are retained.

Probes execute after contract-test rerun in a **fresh nsjail child**, with the
same rerun donor-absent mount plan and a role-distinct execution receipt. They
have a separate outcome vector and cannot alter baseline counts. Missing,
duplicate, malformed, or inapplicable-required probes reject. Any probe result
other than its exact expected outcome is independently
`REJECT_SEMANTIC_DEGRADATION`; probe success cannot compensate for any other
failure.

### 9. Noncanonical abort envelope

A watchdog kill, output truncation, evidence overflow, malformed/truncated
frame, child crash, incomplete teardown, child leak, or recorder failure
produces **no canonical `TransplantValidationReport`**. It may produce one
bounded noncanonical `ValidationAbortEnvelope` containing only subject input
digests, stage/role, one `BTSRejectReason`, typed detail category, bounded
counter values, and sorted blocker summaries. It carries no validation digest
and cannot authorize acceptance.

Abort ordering is `(stage_ordinal, role_ordinal, reason_ordinal,
detail_category, subject_digest)`; duplicate keys reject the envelope. Explicit
mappings are: wall/CPU/memory/pids/output/scratch-storage limit or child leak ->
`REJECT_EXECUTION_THREAT`; frame corruption/truncation, child crash, incomplete
non-leak teardown, or recorder failure -> `REJECT_HARD_GATE_FAILED`. A directly
observed donor import retains the higher-precedence
`REJECT_DONOR_IMPORT_OBSERVED`. No raw child output is copied canonically or into
the abort envelope. An exact, controller-only `LEITIR_NSJAIL_DEBUG=1` opt-in may
raise nsjail's parent-process log level for noncanonical abort diagnostics; it
does not alter the digest-bound `FATAL` policy or the child environment.

### 10. E4a and ratified E4b corpus authority

E4a is one pinned well-behaved offline donor case with a valid ADR-0008
`COMPLETE` BTS, both execution plans, relocation artifacts, green baseline,
rewritten tests, probes, and expected canonical report.

E4b uses a release/ADR-approved `ValidationCorpusManifest` with schema version,
authority, release ID, sorted unique case entries, source provenance, case
digests, review receipt digests, and one ratified manifest digest. A manifest's
self-hash is integrity evidence, not authority or cherry-pick resistance. CI
accepts only the digest named by the release policy/ADR-approved authority.

For v0.1.2, membership is monotonic and `N >= 5` materially different donor
repositories are retained. Ordinary changes are additive expansion only.
Removal, replacement, or exclusion is prohibited during v0.1.2 except a
documented security or legal emergency with independent review, a superseding
ratified manifest, explicit removed-case tombstone/reason/evidence, and release
note. A failed case cannot be silently omitted.

Each case independently requires: an ADR-0008 `COMPLETE` BTS; collision-free
relocation; an attestable zero-failure baseline; exact rerun collection/count/
per-test parity; OS-proved donor absence; no observed donor import; all observed
imports classified diagnostically; all applicable probes passing in a fresh
child; and every execution gate passing. Corpus acceptance is the AND of all
cases, sorted by case ID; scheduling is unobservable.

Benchmark candidate discovery is not transplant validation. A task runner may
inspect structurally materialized immutable candidates to collect C3 suitability
and ranking evidence, but promotion of every planned execution identity into
BTS, relocation, baseline, or rerun still requires the exact full-tree snapshot
defined by ADR-0008. If promotion fails, the benchmark records the typed reason
on that task and marks only its execution-dependent metrics not applicable; it
does not execute the donor, silently drop the task, or invalidate independent
task observations.

The normal suite does not globally export donor opt-in. A dedicated offline
Linux/nsjail containment job sets `LEITIR_ENABLE_DONOR_EXECUTION=1`; live refresh
also sets `LEITIR_ENABLE_LIVE_E2E=1`. This is the **v0.1.2** milestone exit
criterion. `AGENTS.md` and milestone 2 are authoritative; issue #73's stale
`v0.3.0` text and tracking statements must be corrected.

### 11. Canonical identity, output, and reason precedence

`validation_digest` is lowercase `sha256:<64 hex>` over strict UTF-8 JSON,
schema `leitir-transplant-validation-v1`, `sort_keys=True`,
`separators=(",", ":")`, `ensure_ascii=False`, `allow_nan=False`, and one LF,
with the digest field omitted. It binds donor provenance/full tree hash,
ADR-0008 `bts_digest`, non-authorizing member-equivalence digest, relocation and
staging manifests, original/rewritten tests, canonical IDs and outcomes, trusted
runner receipt, baseline, shared/role execution policies, both mount plans,
realized containment receipts, bounded donor-ban categories/digests, runtime
diagnostics, probes, and all blockers.

Canonical fields contain only closed typed values, bounded integers, relative
logical paths, and digests. No timestamps, PIDs, host/temp paths, raw child
strings, measured wall time, secrets, or scheduling appear. Every tuple has an
exhaustive key; genuine ties reject. Writes use the existing atomic/fsync
discipline.

Where multiple completed-run failures are knowable, all are retained and the
summary precedence is: `REJECT_DONOR_IMPORT_OBSERVED`,
`REJECT_EXECUTION_THREAT`, `REJECT_PROVENANCE_MISMATCH`,
`REJECT_MOVING_REFERENCE`, `REJECT_DUPLICATE_RESULT`,
`REJECT_COVERAGE_MISCOUNT`, `REJECT_SEMANTIC_DEGRADATION`,
`REJECT_UNSUPPORTED_CONSTRUCT`, `REJECT_UNRESOLVED_EDGE`,
`REJECT_UNDER_COLLECTION`, `REJECT_BUDGET_EXCEEDED`, then
`REJECT_HARD_GATE_FAILED`. Precedence never suppresses evidence. Abort cases use
section 9 and publish no canonical report.

### Upstream validation

The decision was checked against current upstream documentation:

- Bubblewrap explicitly says it is "not a complete, ready-made sandbox"; its
  caller must define the security model and arguments. It is therefore not the
  v1 backend, and selecting it later would require an explicit composition with
  cgroup v2 and seccomp policy.
- NsJail describes itself as a Linux process-isolation tool using namespaces,
  cgroups, rlimits, and seccomp-bpf. Its upstream `config.proto` contains
  `ONCE`, `keep_env`, all six required `clone_new*` fields, `iface_no_lo`,
  `cgroup_mem_max`, `cgroup_pids_max`, `cgroup_cpu_ms_per_sec`, cgroup v2
  controls, read-only mounts/tmpfs, and `seccomp_string` used above.
- Linux cgroup v2 documents memory, CPU, and pids controllers and `cgroup.kill`,
  whose write kills the cgroup and descendants while handling concurrent forks.
- Firejail describes itself as Linux/SUID, warns that SUID programs can be
  dangerous on multiuser systems, and carries its own profiles, release, and
  security surface. V1 does not support it.
- Python documents `resource` as Unix-only and its limits as process-oriented;
  it is defense in depth, not filesystem/network/process-tree containment.
- CPython explicitly says `sys.addaudithook()` is not suitable for a sandbox and
  malicious code can trivially disable or bypass Python-added hooks.
- CPython documents that `-I` implies `-E` and ignores every `PYTHON*`
  environment variable, while `PYTHONHASHSEED` is the startup control for
  repeatable hashing. This requires the selected `-S -s -P` launch contract.
- Pytest documents that its default `prepend` import mode inserts test/package
  directories at the front of `sys.path`; the runner receipt must pin import
  mode rather than inherit that default.
- Nix content addressing can pin the CI environment/rootfs, but content identity
  neither supplies the donor-absent mount namespace nor upgrades integrity to
  authenticity.

### Determinism and fail-closed invariants

1. Only a recomputed valid ADR-0008 `COMPLETE` result and primary `bts_digest`
   may relocate; `PARTIAL` and `REJECT` are unchanged and non-relocatable.
2. V1 executes only on Linux through the exact pinned nsjail backend. Missing or
   unproved controls reject before execution; no fallback runs donor code.
3. Baseline and rerun bind distinct role/mount-plan execution digests. Donor
   bytes are read-only in baseline and absent in rerun.
4. All authorizing bytes are read-only and hash-stable; only the policy-pinned,
   per-launch-cleared `/work` scratch bind is writable. It is `rw,noexec,nosuid,
   nodev`, and `rlimit_fsize` bounds each child-written file rather than imposing
   a total scratch-byte cap.
5. Donor absence is an OS/filesystem claim. Import recording is diagnostic-only;
   an observation rejects, while non-observation proves nothing.
6. Module paths and recipient binding scopes are collision-checked against a
   pinned reserved namespace and preloaded module inventory.
7. Baseline and rerun apply the same miscount/semantic/infrastructure reason
   split and exact runner-independent ID/outcome comparison.
8. `-I` is forbidden. Hash seed, locale, timezone, architecture, rootfs,
   interpreter, pytest command/config/import mode, and plugin closure are pinned.
9. Probes are explicit, reviewed, content-pinned, required, and run in a fresh
   child. Empty applicability must be proved.
10. Static blockers are non-compensating. Runtime diagnostics may trigger fresh
    static analysis but cannot resolve or erase an ADR-0008 blocker.
11. Canonical evidence is a bounded closed schema of typed categories and
    digests. Overflow rejects; raw attacker-controlled data is noncanonical.
12. Operational aborts publish no canonical report and map deterministically to
    a bounded nonauthorizing abort envelope.
13. E4b uses an authority-ratified, monotonic corpus with `N >= 5` and zero
    baseline failures; every case is a non-compensating AND gate.
14. All hashes establish integrity and subject binding, not authenticity,
    ownership, licensing, or occupied-recipient suitability.

### Positive Consequences

- The donor-ban claim rests on a concrete Linux filesystem boundary rather than
  bypassable Python hooks.
- Exact canonical IDs and outcomes expose hidden skips, under-collection, and
  outcome swaps.
- Separate immutable baseline/rerun plans make the allowed donor difference
  explicit and digest-bound.
- Reserved namespace and binding checks prevent a transplant from shadowing
  stdlib, pytest, or bootstrap behavior.
- Bounded diagnostic evidence can reveal missed requirements without weakening
  ADR-0008.
- Ratified monotonic corpus membership prevents ordinary cherry-picking.

### Negative Consequences

- V1 donor execution is Linux/nsjail-only and rejects otherwise.
- Pinning nsjail, kernel capabilities, rootfs, CPython, runner/plugin closure,
  two mount plans, probes, and corpus authority adds substantial release work.
- Strict namespace/import rewriting rejects dynamic imports, namespace packages,
  and complex donor test suites.
- Kernel, nsjail, CPython, runner, or native-extension defects remain residual
  escape or reproducibility risks and require security maintenance.
- The writable scratch bind trades tmpfs's aggregate byte/inode cap for a
  policy-pinned host staging directory: per-file `rlimit_fsize` and bounded
  retained output do not bound aggregate scratch consumption, so operators must
  provision and monitor its storage capacity.
- Generic parity may preserve existing donor failures, although E4b requires a
  green baseline.

## Pros and Cons of the Options

### Copy the donor package

- Good, because package-relative imports often work without rewriting.
- Bad, because it does not validate a minimal BTS and can accidentally test the
  donor itself.
- Bad, because it imports unrelated code, dependencies, license obligations,
  and attack surface.

### Accept green exit or aggregate counts

- Good, because it is simple to integrate.
- Bad, because missing tests, extra skips, or offsetting outcome transitions can
  remain green.

### Python hooks or `resource` as containment

- Good, because they are available from Python on some hosts and add diagnostics
  or defense in depth.
- Bad, because audit hooks are bypassable, `resource` is Unix/process-oriented,
  and neither establishes a donor-absent filesystem or contains a process tree.

### Pinned nsjail backend

- Good, because it composes Linux namespaces, read-only and policy-pinned
  scratch bind mounts, cgroups, rlimits, and seccomp in one inspectable native
  configuration.
- Good, because unsupported capability sets can reject before execution.
- Bad, because support is Linux-only and backend/kernel defects remain in the
  trusted computing base.

### Runtime repair of static blockers

- Good, because observations can identify candidates for later static scope.
- Bad, because one run is finite and cannot prove a binding or absence for all
  inputs.
- Bad, because repair would contradict ADR-0008's terminal blocker semantics.

## Resolved by consensus

1. **Q1:** V1 is Linux-only and uses one pinned native backend, nsjail.
2. **Q2:** Numeric limits live in a separately versioned, corpus-measured
   execution-policy artifact; this ADR requires but does not choose them.
3. **Q3:** Generic parity permits nonzero baseline failures; E4b requires
   `baseline.failed == 0`.
4. **Q4:** Exact per-test canonical outcome equality is normative, using
   runner-independent canonical IDs.
5. **Q5:** Coverage miscount and semantic degradation remain distinct and apply
   identically to baseline and rerun; issue #63 must be aligned.
6. **Q6:** Canonical runtime output is bounded typed categories and digests only,
   never raw attacker-controlled data.
7. **Q7:** V1 runtime evidence is diagnostic-only and uses the closed schema in
   section 7 if carried.
8. **Q8:** V1 probes are maintainer-authored, reviewed, and content-pinned;
   semantic generation is deferred.
9. **Q9:** E4b retains `N >= 5` plus an authority-ratified corpus digest and
   monotonic membership/change control.
10. **Q10:** Section 2 defines the interim staging layout; ADR-011 assigns public
    packet paths later.
11. **Q11:** Builtin, frozen, source/bytecode, extension, and bootstrap loader
    kinds are separate; interpreter build and extension bytes/origins are pinned.
12. **Q12:** The exit milestone is v0.1.2; issue #73's `v0.3.0` text is stale and
    must be corrected.

There are no unresolved semantic questions for the v1 contract. Numeric limits,
the exact ratified corpus digest, backend binary/rootfs digests, and probe/test
contents are required release artifacts to be measured and approved before
execution can ship, not open design choices.

## Links

- [Epic #52 — Behavioral Transplant Set](https://github.com/anthonykewl20/leitir/issues/52)
- [#55 — E4a walking skeleton](https://github.com/anthonykewl20/leitir/issues/55)
- [#60 — B6 runtime import recorder](https://github.com/anthonykewl20/leitir/issues/60)
- [#61 — E1 import-rewrite relocator](https://github.com/anthonykewl20/leitir/issues/61)
- [#62 — S2 donor execution threat model](https://github.com/anthonykewl20/leitir/issues/62)
- [#63 — E2 donor-banning rerun harness](https://github.com/anthonykewl20/leitir/issues/63)
- [#64 — E3 behavioral probes](https://github.com/anthonykewl20/leitir/issues/64)
- [#73 — E4b N-donor gate](https://github.com/anthonykewl20/leitir/issues/73)
- [ADR-0008 — BTS foundation](https://github.com/anthonykewl20/leitir/blob/main/docs/adr/0008-behavioral-transplant-set.md)
- [NsJail configuration schema](https://github.com/google/nsjail/blob/master/config.proto)
- [Bubblewrap sandbox-security statement](https://github.com/containers/bubblewrap#sandbox-security)
- [Linux cgroup v2](https://docs.kernel.org/admin-guide/cgroup-v2.html)
- [CPython audit hooks](https://docs.python.org/3/library/sys.html#sys.addaudithook)
- [CPython command line and environment](https://docs.python.org/3/using/cmdline.html)
- [CPython `resource`](https://docs.python.org/3/library/resource.html)
- [Pytest import modes](https://docs.pytest.org/en/stable/explanation/pythonpath.html)
- [Nix content-addressed store objects](https://nix.dev/manual/nix/2.28/store/store-object/content-address)
- [Firejail usage and SUID model](https://firejail.wordpress.com/documentation-2/basic-usage/)
