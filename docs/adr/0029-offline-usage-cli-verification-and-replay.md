# Offline usage CLI verification, replay, and opt-in pinned public-source E2E

- Status: accepted
- Deciders: leitir usage-evidence-pipeline contributors
- Date: 2026-08-25
- Technical Story: issue #259 (blocked by #255-#258)

## Context and Problem Statement

`#255`-`#258` freeze a data contract, an admission/import-catalog gate, a
static resolver, and a deterministic evidence assembler, but none of them
are reachable from the command line, and nothing yet proves that a
previously-produced usage evidence report can be re-verified, fully
offline, byte-for-byte, against the real corpus bytes it describes -- which
is the entire point of the contract's `replay_report` function existing.
The final piece is exposing that as a `leitir` subcommand with strict
stdout/stderr discipline, wiring it to fail closed on tampered evidence,
proving determinism across `PYTHONHASHSEED`, and providing a place for a
real-network, pinned-identity end-to-end benchmark without ever requiring
that benchmark, or invented identities, to gate local completion.

## Decision Drivers

- `src/leitir/cli.py` has one shared dispatch convention (an `if
  args.command in {...}` cluster, `_write_cli_payload`/`_write_bts_error`)
  that every validate-style subcommand already follows; a new subcommand
  should not invent a second convention.
- Machine consumers of `--json` output must be able to pipe stdout straight
  into `json.loads` with zero risk of a stray log line corrupting the
  parse; all diagnostic/progress text belongs on stderr, unconditionally.
- A tampered bundle must fail closed: non-zero exit, a typed error on
  stderr, and -- critically -- no output on stdout at all, not even a
  partial or "looks valid" JSON document.
- MCP is out of scope for every issue in this chain; the CLI surface must
  not introduce the token anywhere, including help text.
- The issue records the public-source E2E identity/pin selection as an
  explicit **owner decision: UNKNOWN**. Local-fixture completion (AC-1,
  SP-1) is independent of that decision and must not be gated on it, and a
  missing owner selection must never be papered over by inventing pins or
  weakening the local proof.

## Considered Options

- A single `leitir usage <report.json>` command that always both verifies
  and replays (rejected -- collapses two genuinely different operations,
  a pure-validate stage that needs no corpus/requirements paths and a
  replay stage that does, into one confusing argument surface).
- Two entirely separate subcommands, `usage-verify` and `usage-replay`
  (rejected -- doubles the parser surface for no benefit; every other
  multi-mode subcommand in this CLI uses a positional mode argument, e.g.
  `exit-gate-validate`/`exit-gate-run` are the exception that proves the
  convention rather than the rule here, since those differ enough in
  required flags to earn separate parsers).
- One `usage` subcommand with a positional `action` (`verify` | `replay`)
  and mode-specific optional flags (`--corpus-root`, `--requirements`,
  `--times`), following the existing `_write_cli_payload`/
  `_write_bts_error` output convention exactly like `occupied-validate`
  (chosen).
- Implement the pinned public-source E2E against a hard-coded PyPI
  package/GitHub repo chosen unilaterally by this issue's implementation
  (rejected -- the issue explicitly records the pin selection as an owner
  decision; inventing one would be exactly the kind of unauthorized
  identity claim the usage evidence pipeline exists to prevent).

## Decision Outcome

Chosen option: a `usage` subcommand in `src/leitir/cli.py`, backed by
`src/leitir/usage/cli_support.py` (new; the frozen `contract.py`,
`_canonical.py`, `errors.py`, `admission.py`, `import_catalog.py`,
`resolver.py`, and `assemble.py` are untouched).

- **`leitir usage verify report.json [--json]`** reads `report.json`
  through `leitir.safeio.read_regular_file` (bounded, `no_follow=True`)
  and calls the frozen `report_from_dict`/`report_from_json_bytes`
  parse+self-consistency check. Success emits a summary payload (digest,
  identities, counts); a malformed, unsupported, or self-inconsistent
  (tampered `report_digest`) report raises the frozen typed error, which
  the shared `bts-compute`/.../`occupied-validate` dispatch cluster's
  `except Exception as exc: _write_bts_error(...); return CORPUS_FAILURE`
  catches -- `usage` joins that cluster's frozenset rather than getting a
  bespoke error path.
- **`leitir usage replay report.json --corpus-root DIR --requirements
  FILE [--times N] [--json]`** first performs the same verify step, then
  calls the frozen, fully offline `replay_report` `--times` (default 2)
  times against the real on-disk corpus/requirements bytes, and asserts
  the resulting canonical JSON bytes are identical across every pass
  before reporting `byte_identical: true`. Any replay-stage mismatch
  (tampered corpus/requirements bytes) raises `UsageTamperError`, caught
  by the same shared cluster -- never partially reported.
- **CLI-argument mistakes** (missing `--corpus-root`/`--requirements` for
  `replay`, or `--times < 1`) are checked before any file I/O and return
  `ExitCode.MALFORMED_USAGE` directly, distinct from a verification/replay
  *content* failure (`CORPUS_FAILURE`).
- **Stdout/stderr discipline**: `_write_cli_payload` is the only thing
  that ever writes to `out`; every diagnostic (`leitir: usage <action> ok
  report_digest=...`, and `_write_bts_error`'s error line) goes to `err`.
  `_write_bts_error` gained one more branch -- alongside its existing
  `BTSError` case -- so a `leitir.usage.UsageError` also renders its
  `.to_json()` on stderr in `--json` mode, rather than falling through to
  a bare `str(exc)`.
- **The opt-in, pinned public-source E2E** lives at
  `tests/e2e/test_usage_e2e.py`, carrying both `@pytest.mark.live` and a
  `skipif` gated on `LEITIR_ENABLE_LIVE_E2E` (the pairing
  `tests/test_live_marker_inventory.py` enforces). Its skip condition also
  checks a module-level `_PUBLIC_E2E_PINS: dict | None`, left `None`
  pending the recorded owner decision; the default run always passes by
  skipping and reports UNKNOWN rather than fabricating a pin, and the test
  body re-checks `_PUBLIC_E2E_PINS is None` a second time so a future edit
  that clears the module-level skip without wiring real fetch/pin logic
  still refuses to reach the network on invented identities.

### Positive Consequences

- Local-fixture verification and replay (AC-1) run in well under a second,
  fully offline, with no dependency on the owner's public-E2E decision.
- The tamper path (SP-1) is exercised against the same committed
  `tests/fixtures/usage/tamper` fixture #255 already established, so no
  new fixture bytes needed inventing or auditing.
- `usage` reuses every existing CLI convention (`_write_cli_payload`,
  `_write_bts_error`, the shared validate-cluster frozenset, `ExitCode`),
  so it does not add a second dispatch pattern for future readers to learn.

### Negative Consequences

- `leitir usage replay` requires the caller to separately supply
  `--corpus-root`/`--requirements` rather than inferring them from a
  fixture manifest, because the frozen contract has no manifest-discovery
  convention of its own (`tests/fixtures/usage/*/manifest.json` is a
  test-only convention, not part of `leitir.usage`'s public contract); a
  human or CI caller must know these paths.
- The pinned public-source E2E is deliberately inert until an owner
  supplies `_PUBLIC_E2E_PINS`; this ADR does not by itself unblock real
  public-source E2E coverage, only the local-fixture proof.

## Links

- `docs/adr/0025-usage-evidence-and-replay-contract.md` -- `replay_report`,
  `report_from_json_bytes`, and the typed `UsageError` hierarchy this CLI
  wraps.
- `docs/adr/0028-deterministic-usage-evidence-assembly.md` -- the
  assembler whose `AssembledEvidenceReport.report` is a normal,
  replay-compatible `UsageReport` this CLI can also verify/replay.
- Issue #259.
