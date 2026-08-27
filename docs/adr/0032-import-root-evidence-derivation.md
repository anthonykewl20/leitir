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
  through the existing `build_import_catalog` (chosen).**

## Decision Outcome

Chosen option: extend ADR-0026's import-catalog machinery with a new
evidence-derivation module, `leitir.usage.import_evidence`, that builds
`DistributionRecord`s from the materialized distribution's own tree and
hands them to the existing `build_import_catalog`. `check.py` now calls
`leitir.usage.import_evidence.resolve_import_roots(materialized_root,
package_name)` in place of `guess_import_root`, and uses whatever set of
roots (zero, one, or many) that resolves to.

**Precision, corrected after adversarial review (2026-08-27):** `build_import_catalog`'s
*resolution and ambiguity logic* was not touched -- every disagreement,
cap, and multi-root decision below is exactly its pre-existing behavior,
reused as-is. What *was* modified in `import_catalog.py` is the
`SUPPORTED_EVIDENCE_SOURCES` allow-list: this issue adds the three new
evidence-source kinds this module produces (`setup-cfg-static`,
`pyproject-static`, `materialized-tree-layout`) to it. Without that
addition, `build_import_catalog` would reject every `DistributionRecord`
this module builds as an unsupported packaging shape (its own, correct,
unmodified behavior for a `source` value it doesn't recognize). An
earlier version of this ADR and the originating PR description both
overstated this as "unmodified" without qualification; that was
inaccurate and is corrected here.

This was the closest option to satisfying every driver simultaneously:
`build_import_catalog` already had the exact typed-unresolved vocabulary
(`AMBIGUOUS_BINDING` / `UNSUPPORTED_SYNTAX`) and multi-root contract this
problem needs, so no new resolution semantics had to be invented -- only a
new, local way to *produce* the `DistributionRecord` evidence it consumes
(derived from a materialized source tree rather than out-of-band admission
data), plus the one-line allow-list extension needed for that evidence to
be accepted at all.

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
4. **`materialized-tree-layout` (retired as an authority -- see below)**
   -- an earlier version of this ADR described a fourth tier here: a
   purely structural, *algorithmic* scan of the tree's own immediate
   layout for plausible top-level import roots (`src/` preferred when
   present), the tier that recovered the `pillow`/`PIL` and `pyyaml`/
   `yaml` cases when no wheel-only packaging metadata was present. It has
   been removed as a *source* of resolved roots; see "Tier 4 was retired
   as an authority" immediately below for why, and "Negative Consequences"
   for the resulting, accepted coverage limitation. The evidence-source
   tag `"materialized-tree-layout"` still exists in code, but only as the
   fixed sentinel `source` value on the single zero-root
   `DistributionRecord` returned when tiers 1-3 all find nothing -- it no
   longer labels any tier that can *originate* a non-empty root set.

If every tier (1-3) finds nothing at all, `import_evidence.py` returns a
single zero-root `DistributionRecord` (source `"materialized-tree-layout"`,
the "no evidence" sentinel), which `build_import_catalog` already types as
`UnresolvedState.UNSUPPORTED_SYNTAX` ("no local evidence declares any
import root for this distribution") -- reusing ADR-0026's existing
fail-safe path for missing evidence verbatim, rather than inventing a
parallel one.

### Tier 4 was retired as an authority (P1 residual, second adversarial review, 2026-08-27)

The first round of adversarial review (below, "Corrected after adversarial
review (2026-08-27, P1)") found that tier 4 binding *every* surviving
candidate to `--against` let an unrelated, same-named local import in a
consumer's own code get misattributed to the pinned distribution -- a
false `violation` against code that is actually correct. The fix at that
time restricted tier 4 to resolving a root only when it found *exactly
one* candidate, treating more than one candidate as ambiguous.

That fix closed the *multi*-candidate collision shape but not a narrower
*single*-candidate one: reviewer-hy3's re-verification pass reproduced a
`src/`-layout donor tree where `src/` contains only a private/vendored
helper package (`src/buildutils/__init__.py`) while the tree's real,
public import root is a module living *outside* `src/`
(`reallib.py` at the repository root). `_tree_layout_records` preferred
`src/` unconditionally whenever it was non-empty, so `reallib.py` was
never even considered as a candidate -- `buildutils` was tier 4's *sole*
candidate, took the "exactly one, so resolve it" branch, and bound to
`--against` as if it were authoritative. A consumer's own, unrelated local
`buildutils.py` module then got misattributed to the pinned distribution
the same way as the original P1 finding: a false `violation` the moment
an accessed name wasn't in the target's index, against code that was
actually correct.

This is not a bug in the exact-one-candidate heuristic that a smarter
heuristic could patch away: there is no purely structural signal in the
tree's own layout that reliably distinguishes "the one candidate tier 4
found is the real public root" from "the one candidate tier 4 found
happens to be a vendored/internal helper, and the real root lives
somewhere tier 4's search doesn't look" -- without either executing
untrusted build logic (`setup.py`, `find:`/`find_namespace:` discovery,
explicitly out of scope by design) or hardcoding distribution-specific
knowledge (forbidden by issue #269). Tiers 1-3 are the distribution's own
declarations about itself, read verbatim from an artifact it shipped;
tier 4 was never more than a guess from directory shape, no matter how
many or how few candidates that guess produced. A guess must not bind a
gate whose defining property is "never flag correct code" -- occasionally
guessing right is not a substitute for that property, and a gate that
occasionally flags correct code gets disabled by its users and then
protects nothing.

**Decision: tier 4 is retired as an authority entirely**, not narrowed
further. `_EVIDENCE_TIERS` now contains only tiers 1-3
(`_top_level_txt_records`, `_setup_cfg_records`, `_pyproject_records`);
the tree-layout scan (`_tree_layout_records`, `_package_candidates`, and
their exclude-name sets) was deleted from `import_evidence.py` rather than
kept in a corroborating-only role, because a corroborating role still
requires tier 4 to be consulted and its output trusted for *something* --
and this module has no way to safely bound what "corroboration" means
here (confirming a root tiers 1-3 already named adds no information tier
4 could contradict without also being capable of contradicting it
wrongly). Retiring it outright is simpler, is strictly safe, and matches
issue #269's own explicitly accepted trade-off: "A distribution whose
import root genuinely cannot be determined still fails safe." When tiers
1-3 are all silent, `resolve_import_roots` returns `None`,
`check.py` reports `nothing_examined`, and the CLI exits `4`
(`NOTHING_INDEXED`) -- never a guessed `violation`, never a silent `ok`.

Both the residual reproduction above and the two original P1 shapes
(stray top-level helper module, vendored `src/`-layout subpackage) are
regression tests: `tests/test_usage_import_evidence.py::
test_src_layout_donor_with_only_a_vendored_src_package_is_undeterminable`
and `tests/test_check_import_root_evidence_e2e.py::
test_src_layout_vendored_helper_masking_real_root_never_produces_a_false_violation`
assert the safe outcome (`resolve_import_roots(...) is None`,
`status == "nothing_examined"`, `sites_violation == 0`,
`import_roots_determinable is False`) directly against
reviewer-hy3's exact scenario.

### Multi-root

A single, coherent, *authoritative* evidence tier (1-3: a real
`top_level.txt`, or an explicit `setup.cfg`/`pyproject.toml` packaging
declaration) that declares more than one root resolves to one
`ImportMapping` naming every declared root -- this is ADR-0026's existing
multi-root contract, reused unmodified. `check.py` maps every resolved
root to the same `--against` target when building the resolver's
`import_roots` dict, so a consumer file using any (or all) of the declared
roots is examined.

There is no tier 4 any more (see above), so a distribution that genuinely
ships more than one top-level import root (e.g. `attrs` shipping both
`attr` and `attrs`) is resolved as multi-root only when an authoritative
tier (1-3) actually declares the roots together in this materialization.
A source tree with no such packaging metadata at all cannot be resolved
as multi-root -- or as any root -- purely from its own directory shape any
more.

### Undeterminable root: still fail-safe

These situations make `resolve_import_roots` return `None` (never a guess):

- **No evidence at all** -- every tier (1-3) found nothing (including the
  now-common case of a GitHub-sourced materialization with no
  `top_level.txt`/`setup.cfg`/`pyproject.toml` packaging declaration at
  all, since tier 4's retirement -- see "Negative Consequences"). Typed
  `UNSUPPORTED_SYNTAX` by `build_import_catalog`, as above.
- **Ambiguous evidence** -- the tier that found something produced more
  than one disagreeing candidate root set (e.g. two `top_level.txt` files
  under different `*.dist-info` directories that disagree), or the
  resolved root count exceeds the existing `MAX_IMPORT_ROOTS_PER_MAPPING`
  cap (ADR-0026/#255). Typed `AMBIGUOUS_BINDING` (or the cap-exceeded
  `UNSUPPORTED_SYNTAX` case), again reusing ADR-0026's existing logic
  unmodified.
- **A malformed or adversarial evidence file** -- `setup.cfg`/
  `pyproject.toml` come from the materialized donor artifact, which is not
  trusted content. See "Fail-closed parsing" below.

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

### Fail-closed parsing (P2 correction, adversarial review)

`setup.cfg` and `pyproject.toml` are read out of the materialized donor
artifact, which this module's own docstring already frames as
attacker-influenceable, untrusted content -- the same threat model the
rest of leitir applies to any materialized tree. Two failures were found
where a malformed file could escape this module as a raw, untyped
exception instead of the documented "this tier found nothing usable"
outcome:

- `tomllib.loads` raises `RecursionError` (not `tomllib.TOMLDecodeError`)
  on a sufficiently deeply nested TOML structure. `_pyproject_records` now
  catches `(tomllib.TOMLDecodeError, RecursionError)` around the parse
  call.
- `configparser`'s interpolation (triggered by `.get()`, not by
  `read_string`) raises `configparser.InterpolationDepthError` on a
  self-referencing value (`a = %(a)s`) -- a subclass of
  `configparser.Error`, but one that was previously unguarded because only
  `read_string` was wrapped. `_setup_cfg_records` now wraps the whole
  parse-and-extract block (`read_string` plus every `.get()` call) in the
  same `except configparser.Error`.

Both failures previously reached a direct in-process caller of
`resolve_import_roots`/`derive_distribution_records` as a raw traceback;
only the CLI's own outer blanket `except Exception` (`cli.py`, pre-existing,
unrelated to this module) happened to mask them end-to-end. This module's
own boundary now upholds its documented contract without depending on that
incidental catch-all, matching AGENTS.md's "match existing error taxonomy"
and fail-closed conventions: a parse failure here is treated exactly like
an unparsable file (this tier found nothing), never a crash and never a
guess.

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
(`MAX_EVIDENCE_FILE_BYTES`). Hitting either bound never raises and never
fabricates a root: it simply means that tier found nothing, so the search
falls through to the next tier (or to the zero-root fail-safe) -- the same
under-detect-rather-than-guess direction ADR-0030's own corroboration-scan
cap already uses. (There is no tree-layout tier any more to note a
recursion bound for -- see "Tier 4 was retired as an authority" above.)

## Positive Consequences

- A distribution whose materialization carries real packaging metadata
  (a `top_level.txt`, a `setup.cfg` with an explicit `packages`/
  `py_modules` list, or a `pyproject.toml` with an explicit
  `[tool.setuptools]`/`[tool.poetry.packages]` declaration) now actually
  gets checked against its *real* import root instead of a normalized-name
  guess: `leitir check ./code.py --against pypi:pillow@X` examines real
  `PIL` usage when the materialization's own metadata says so, and a
  multi-root distribution like `pypi:attrs` (shipping both `attr` and
  `attrs`) is resolved correctly when a `top_level.txt` declares both
  roots together.
- No new resolution semantics were invented: ADR-0026's existing
  `build_import_catalog` ambiguity/unsupported-shape handling and
  multi-root *logic* are reused completely unmodified (only its
  `SUPPORTED_EVIDENCE_SOURCES` allow-list was extended, per the
  precision correction above), so this change is additive to that
  machinery rather than a parallel implementation of it.
- No hardcoded distribution-name alias table exists anywhere in leitir
  after this change; every derived root is either read verbatim from an
  artifact the distribution itself shipped, or -- now that tier 4 is
  retired -- not derived at all when tiers 1-3 are silent.
- The fail-safe contract is strictly strengthened, not weakened: every
  path that previously produced `nothing_examined` for a wrong name-based
  guess still does, plus additional cases (genuinely ambiguous evidence,
  and now every case tier 4 used to guess at) that previously were not
  distinguishable from "evidence agreed, but the code doesn't use it" now
  are, via `import_roots_determinable`. No code path anywhere in this
  module can bind a root to `--against` that was not read verbatim from
  the distribution's own tiers 1-3 packaging declarations.

## Negative Consequences

- **The tree-layout fallback (tier 4) is gone, not narrowed.** A
  distribution whose materialization carries no `top_level.txt`, no
  `setup.cfg` with an explicit `packages`/`py_modules` list, and no
  `pyproject.toml` with an explicit `[tool.setuptools]`/
  `[tool.poetry.packages]` declaration -- which, per this ADR's own
  Context section, is the *common* case for a `check` materialization
  (typically a pinned GitHub source tree, not an installed wheel) -- now
  always resolves to undeterminable (`nothing_examined`, exit 4), even
  when the tree's directory layout would make the real import root
  obvious to a human (a single top-level `PIL/` or `yaml/` directory with
  an `__init__.py`, no ambiguity in sight). This closes real coverage this
  PR originally set out to add for exactly the motivating cases
  (`pillow`/`PIL`, `pyyaml`/`yaml`, and similar renamed distributions),
  whenever the GitHub source tree carries no packaging metadata of its
  own. This is a deliberate, accepted trade: issue #269 explicitly accepts
  "a distribution whose import root genuinely cannot be determined still
  fails safe," and losing coverage on layout-only distributions is
  strictly preferable to a gate that can occasionally flag correct code --
  a gate with that flaw gets disabled by its users and then protects
  nothing, whereas under-coverage that fails safe merely limits what gets
  checked at all. A future, safer tree-layout tier is not ruled out, but
  it would need a way to positively corroborate a candidate against
  something more authoritative than the tree's own shape (e.g. actually
  installing the distribution and reading its real, installed
  `top_level.txt` -- a materially different, heavier design than a static
  scan) rather than a narrower version of the same directory-shape guess.
- `setup.cfg`'s `find:`/`find_namespace:` directive and any dynamic
  `setup.py`-only packaging logic are never trusted, by design (running
  either would mean executing untrusted, materialized code) -- a
  distribution whose *only* packaging declaration uses one of those is
  now, like the no-metadata-at-all case above, reported undeterminable
  rather than incorrectly guessed -- real, accepted under-coverage.
- Evidence derivation only runs against whatever `check` already
  materializes (typically the pinned GitHub source, not necessarily an
  installed wheel) -- so the highest-confidence `top-level-txt` tier
  (the only tier a wheel-based installation reliably provides) is the
  *least* commonly available in practice for this command's normal usage.
  With tier 4 retired, a GitHub-sourced materialization with no
  `setup.cfg`/`pyproject.toml` packaging declaration -- an ordinary,
  common shape, not a corner case -- has no path to a resolved root at
  all.

## Links

- [ADR-0030](0030-check-command-conservative-symbol-existence-gate.md) --
  the `leitir check` command this fixes a documented limitation of.
- [ADR-0026](0026-conservative-admission-and-import-catalog.md) -- the
  import-catalog machinery this ADR extends. Its resolution/ambiguity
  logic (`build_import_catalog`) is reused unmodified; its
  `SUPPORTED_EVIDENCE_SOURCES` allow-list is extended with the three new
  evidence-source kinds this ADR introduces.
- Issue #269, issue #266 task B3, PR #267.
