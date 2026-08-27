# Deriving distribution import roots from materialized evidence, not from the name

- Status: accepted
- Deciders: leitir contributors
- Date: 2026-08-27
- Technical Story: issue #269 (follow-on to issue #266 task B3 / ADR-0030,
  and #256 / ADR-0026)

## Context and Problem Statement

ADR-0030 documented, as an accepted limitation, that `leitir check` decides
which import root to look for by normalizing the target distribution's
registry name (`guess_import_root`): lowercase, non-identifier characters
replaced with `_`. That is correct for the common case (`flask` -> `flask`,
`numpy` -> `numpy`) but wrong for a large and unexceptional slice of the
Python ecosystem: `pillow` imports as `PIL`, `beautifulsoup4` as `bs4`,
`pyyaml` as `yaml`, `python-dateutil` as `dateutil`, `scikit-learn` as
`sklearn`, `opencv-python` as `cv2`. When the guess is wrong, the resolver
(`leitir.usage.resolver.resolve_consumer`, keyed by exact top-level import
name) finds no reference to check at all -- `check` fails safe (zero sites
examined, `status="nothing_examined"`, exit 4 `NOTHING_INDEXED`, per
ADR-0030's own P1 correction) but it has verified nothing for exactly the
packages this table names. How should `check` determine a distribution's
real import root(s), without inventing a hardcoded distribution-name alias
table (which would itself become exactly the kind of stale, unverifiable
claim issue #266 spent considerable effort removing from leitir), and
without weakening the fail-safe contract ADR-0030 already established?

## Decision Drivers

- The import root is a property of the distribution's own packaging
  artifact or source tree, not of its registry name -- any fix must derive
  it from evidence the materialized distribution itself carries.
- No hardcoded distribution -> import-root alias table, ever. A fallback,
  if one is unavoidable, must be an *algorithm* applied to the evidence at
  hand (regenerable, re-derivable, auditable), never a hand-maintained list
  of package names.
- Reuse ADR-0026's conservative-admission / import-catalog machinery
  (`leitir.usage.import_catalog`, issue #256) rather than bolting a
  second, parallel lookup mechanism onto `check.py`. That machinery
  already has exactly the typed-unresolved (ambiguous / unsupported)
  vocabulary and the multi-root contract this problem needs.
- One-to-many is common, not exotic: a distribution can genuinely ship more
  than one top-level import root (e.g. `attrs` ships both `attr` and
  `attrs`). This must be a legitimate resolved outcome, not treated as an
  error.
- Fail safe when the evidence is absent or contradictory: an undeterminable
  root must still produce `nothing_examined` / exit 4, never a guessed
  `violation` and never a guessed `ok`. This is a strengthening of
  ADR-0030's existing "wrong guess -> zero sites examined" behavior, not a
  departure from it.
- `check` materializes a pinned *source* (typically a GitHub repository
  resolved from the registry's project URLs), not necessarily an installed
  wheel -- so classic wheel-only evidence (`RECORD`, an installed
  `*.dist-info/top_level.txt`) is frequently absent, and a real design has
  to work from a source tree's own conventions and static packaging
  metadata as well.

## Considered Options

- Keep `guess_import_root` as the sole source of truth for `check`, and
  simply broaden its normalization heuristics (extra suffix/prefix
  stripping rules). Rejected: still a name-based guess, still wrong for
  every listed case, and broadening it a little only shrinks the gap
  without closing it -- the underlying premise (name implies import root)
  remains false.
- Hardcode a distribution -> import-root alias table for the well-known
  renamed packages. Rejected explicitly by the issue and by AGENTS.md's
  standing discipline against unverifiable, unmaintainable claims: any
  such table is immediately stale for a distribution not yet added to it,
  silently wrong the moment upstream renames a root, and is exactly the
  class of defect issue #266 already spent effort removing.
- Require the full ADR-0026 admission pipeline (SHA-pinned consumer,
  exact-pin `requirements.txt` digest) before `check` can run at all.
  Rejected: `check` operates on one file against one pinned target with no
  admitted consumer repository in play; requiring out-of-band admission
  evidence `check` does not have (and structurally cannot have, since it
  is invoked directly against arbitrary local code) would make the command
  unusable for its actual purpose.
- **Derive `leitir.usage.import_catalog.DistributionRecord` evidence
  directly from the materialized target's own tree, in a precedence-
  ordered sequence of increasingly-structural evidence tiers, and feed it
  through the existing, unmodified `build_import_catalog` (chosen).**

## Decision Outcome

Chosen option: extend ADR-0026's import-catalog machinery with a new
evidence-derivation module, `leitir.usage.import_evidence`, that builds
`DistributionRecord`s from the materialized distribution's own tree and
hands them to the existing, unmodified `build_import_catalog`. `check.py`
now calls `leitir.usage.import_evidence.resolve_import_roots(materialized_root,
package_name)` in place of `guess_import_root`, and uses whatever set of
roots (zero, one, or many) that resolves to.

This was the only option that satisfies every driver simultaneously:
`build_import_catalog` already has the exact typed-unresolved vocabulary
(`AMBIGUOUS_BINDING` / `UNSUPPORTED_SYNTAX`) and multi-root contract this
problem needs, so no new resolution semantics had to be invented -- only a
new, local way to *produce* the `DistributionRecord` evidence it consumes,
derived from a materialized source tree rather than out-of-band admission
data.

### Evidence sources, in precedence order

Each tier is tried in order; the search stops at the first tier that finds
*any* evidence for the distribution (one or more candidate root sets --
including a disagreeing set, which the existing catalog logic already
types as ambiguous). A lower tier is therefore only ever consulted when a
higher-confidence tier found literally nothing, so a low-confidence
structural guess can never override real packaging metadata that is
actually present.

1. **`top-level-txt`** -- a real `top_level.txt` file found verbatim
   inside any `*.dist-info/` or `*.egg-info/` directory anywhere in the
   materialized tree. This is the same evidence `pip` itself trusts for an
   installed distribution; when a materialization happens to include one
   (e.g. a vendored `.egg-info`, or a build artifact left in the tree),
   it is the single most authoritative signal available and is preferred
   unconditionally over every other tier.
2. **`setup-cfg-static`** -- a static, never-executed parse (Python's
   stdlib `configparser`) of a top-level `setup.cfg`'s `[options] packages`
   (an *explicit* list only -- `find:`/`find_namespace:` is deliberately
   never trusted, because it requires actually running setuptools'
   discovery logic, which this module will not do) and/or `py_modules`.
3. **`pyproject-static`** -- a static, never-executed parse (stdlib
   `tomllib`) of a top-level `pyproject.toml`'s explicit
   `[tool.setuptools] packages`/`py-modules`, or Poetry's
   `[tool.poetry.packages]` `include=` entries.
4. **`materialized-tree-layout`** -- the lowest-confidence tier, and the
   one that recovers the `pillow`/`PIL` and `pyyaml`/`yaml` cases when (as
   is typical for a GitHub-sourced materialization) no wheel-only
   packaging metadata is present at all: a purely structural,
   *algorithmic* scan of the tree's own immediate layout for plausible
   top-level import roots. A `src/` layout is preferred when present
   (checked first; only falls back to the repository root if `src/` does
   not exist or yields no candidates). A candidate is either a top-level
   directory containing `__init__.py` or a top-level `.py` file, excluding
   a small, generic, cross-ecosystem set of non-package directory/file
   names every Python source distribution uses for its own tooling
   regardless of what it is named or imports as (`tests`, `docs`,
   `examples`, `benchmarks`, `scripts`, `build`, `.github`, `setup.py`,
   `conftest.py`, and similar). **This exclude set is not a distribution
   alias table** -- it names generic filesystem conventions, not any
   specific package's import root, and is the same fixed handful of names
   for every distribution checked. It is intentionally small and
   over-inclusive rather than precise: an extra false-positive candidate
   root (e.g. a `tools/` directory that happens to contain an
   `__init__.py` and was not excluded) is harmless, because a real
   consumer's code will simply never import it, and the resolver only
   examines roots a consumer file actually references.

If every tier finds nothing at all, `import_evidence.py` returns a single
zero-root `DistributionRecord` (source `"materialized-tree-layout"`),
which `build_import_catalog` already types as
`UnresolvedState.UNSUPPORTED_SYNTAX` ("no local evidence declares any
import root for this distribution") -- reusing ADR-0026's existing
fail-safe path for missing evidence verbatim, rather than inventing a
parallel one.

### Multi-root

A single, coherent evidence tier that declares more than one root (e.g.
`attr` and `attrs` both discovered by the tree-layout tier for a single
distribution) resolves to one `ImportMapping` naming every declared root --
this is ADR-0026's existing multi-root contract, reused completely
unmodified. `check.py` maps every resolved root to the same `--against`
target when building the resolver's `import_roots` dict, so a consumer
file using any (or all) of the declared roots is examined.

### Undeterminable root: still fail-safe

Two situations make `resolve_import_roots` return `None` (never a guess):

- **No evidence at all** -- every tier found nothing. Typed
  `UNSUPPORTED_SYNTAX` by `build_import_catalog`, as above.
- **Ambiguous evidence** -- the tier that found something produced more
  than one disagreeing candidate root set (e.g. two `top_level.txt` files
  under different `*.dist-info` directories that disagree), or the
  resolved root count exceeds the existing
  `MAX_IMPORT_ROOTS_PER_MAPPING` cap (ADR-0026/#255). Typed
  `AMBIGUOUS_BINDING` (or the cap-exceeded `UNSUPPORTED_SYNTAX` case),
  again reusing ADR-0026's existing logic unmodified.

`check.py` treats `None` exactly like ADR-0030's existing "wrong guess"
outcome: the resolver's `import_roots` dict is built with zero entries, so
`resolve_consumer` finds no reference to examine, `sites_examined` stays
`0`, `CheckReport.status` is `"nothing_examined"`, and the CLI exits `4`
(`NOTHING_INDEXED`). No code path in this change can produce a `violation`
or an `ok` site against a root that was not positively, non-ambiguously
resolved from evidence.

### New `CheckReport` fields for transparency

`CheckReport` (and its JSON payload) now also carries `import_roots` (the
resolved roots actually searched for, empty when undeterminable) and
`import_roots_determinable` (`False` only when no tier could resolve
anything at all). This lets a consumer of the JSON -- or a human reading
the CLI's `nothing_examined` message -- distinguish "the root was
determined, but this code just doesn't use it" from "the root could not be
determined at all," which ADR-0030's original message conflated (it always
named the same normalized-name guess regardless of which case applied).
The CLI's stderr message for a zero-site run now branches on this: it
either names the derived root(s) that were searched for, or explains that
no evidence tier could determine a root at all (and, only in that
diagnostic message, still shows what a name-based guess *would* have been,
clearly labeled as unused).

### `guess_import_root` is retained, but demoted

`leitir.check.guess_import_root` is no longer consulted to decide what
`run_check` looks for. It is kept only as a display/diagnostic helper (the
CLI's undeterminable-root message can still show what a naive name-based
guess would have produced, for a user's own troubleshooting) and its
docstring now says so explicitly.

### Bounds

Every filesystem walk `import_evidence.py` performs is bounded: the
`*.dist-info`/`*.egg-info` search caps the number of directory entries it
will visit (`MAX_WALK_DIR_ENTRIES`), and every file it reads goes through
the existing `leitir.safeio.read_regular_file` with a byte cap
(`MAX_EVIDENCE_FILE_BYTES`). The tree-layout tier only ever inspects the
*immediate* children of the repository root (and, if present, `src/`) --
it does not recurse -- so it is inherently `O(top-level entry count)`, not
`O(tree size)`. Hitting any bound never raises and never fabricates a
root: it simply means that tier found nothing, so the search falls through
to the next tier (or to the zero-root fail-safe) -- the same
under-detect-rather-than-guess direction ADR-0030's own corroboration-scan
cap already uses.

## Positive Consequences

- `pypi:pillow`, `pypi:pyyaml`, and a multi-root distribution like
  `pypi:attrs` now actually get checked: `leitir check ./code.py --against
  pypi:pillow@X` examines real `PIL` usage and reports real
  `ok`/`violation`/`unresolved` outcomes, closing the gap ADR-0030
  documented and accepted.
- No new resolution semantics were invented: ADR-0026's existing
  `build_import_catalog` ambiguity/unsupported-shape handling and
  multi-root contract are reused completely unmodified, so this change is
  additive to that machinery rather than a parallel implementation of it.
- No hardcoded distribution-name alias table exists anywhere in leitir
  after this change; every derived root is either read verbatim from an
  artifact the distribution itself shipped, or produced by a fixed,
  regenerable algorithm applied to the tree's own structure.
- The fail-safe contract is strictly strengthened, not weakened: every
  path that previously produced `nothing_examined` for a wrong name-based
  guess still does, plus additional cases (genuinely ambiguous evidence)
  that previously were not distinguishable from "evidence agreed, but the
  code doesn't use it" now are, via `import_roots_determinable`.

## Negative Consequences

- The tree-layout tier's exclude list, while generic and not
  distribution-specific, is still a finite, static set of directory/file
  names; an unusual project layout that names its real package something
  like `docs` (unlikely, but not impossible) would have that root excluded
  and fall through toward the undeterminable outcome -- the accepted,
  deliberate cost of the same false-positive-avoidance trade-off ADR-0030
  already made elsewhere (this module is over-inclusive on the *harmless*
  direction -- an extra false candidate is silently unused -- but
  conservative on the *exclusion* direction, which can under-detect a
  genuinely oddly-named real package).
- `setup.cfg`'s `find:`/`find_namespace:` directive and any dynamic
  `setup.py`-only packaging logic are never trusted, by design (running
  either would mean executing untrusted, materialized code) -- a
  distribution whose *only* packaging declaration uses one of those and
  that also fails every other tier (no `top_level.txt`, no recognizable
  tree layout) is still correctly reported as undeterminable rather than
  incorrectly guessed, but is real, accepted under-coverage.
- Evidence derivation only runs against whatever `check` already
  materializes (typically the pinned GitHub source, not necessarily an
  installed wheel) -- so the highest-confidence `top-level-txt` tier is
  the *least* commonly available in practice for this command's normal
  usage; the tree-layout tier carries most of the real-world weight,
  which is exactly why it is deliberately not exempt from bounds and
  disagreement handling.

## Links

- [ADR-0030](0030-check-command-conservative-symbol-existence-gate.md) --
  the `leitir check` command this fixes a documented limitation of.
- [ADR-0026](0026-conservative-admission-and-import-catalog.md) -- the
  import-catalog machinery this ADR extends, reused unmodified.
- Issue #269, issue #266 task B3, PR #267.
