# `leitir check`: a conservative, three-way symbol-existence gate for written code

- Status: accepted
- Deciders: leitir contributors
- Date: 2026-08-26
- Technical Story: issue #266, tasks B3 (`leitir check`) and E1 (hallucination-rate counts)

## Context and Problem Statement

Every existing leitir verb is retrieval or provenance: `search`, `api`,
`examples`, `info`, `diff`, and the usage-evidence pipeline (#255-#259) all
tell an agent what a pinned source actually contains. None of them take code
an agent just *wrote* and check it against that truth. Retrieval that is
never checked against the output an agent produces is a suggestion, not a
gate. `leitir check <path> --against <spec>` closes that gap: it validates
that a Python file's calls/imports against one materialized, pinned source
are backed by symbols that actually exist in that source's version.

The premise had to be verified against the actual code before any design,
per this issue's standing instruction (two prior items in this epic were
withdrawn for false premises):

- `leitir.apisurface` (`_python_extractor`) walks only *direct* top-level
  statements (`for node in tree.body`), plus one level of methods on a
  top-level class. It never recurses into `if`/`try` blocks, so a
  conditionally defined symbol (a common real-world pattern: `try: from
  ujson import dumps except ImportError: def dumps(...): ...`) is invisible
  to it. It never indexes plain module-level assignments or constants
  (`__version__`, `codes`, re-assigned aliases like `Blueprint = _Blueprint`).
  It deliberately excludes any name starting with `_`. Its `signature`
  field is a formatted string (parameter names, defaults, type annotations)
  useful for a human diff, but not a structured arity model: default
  arguments, `*args`/`**kwargs`, and decorator-rewritten signatures all make
  "arity" ill-defined from a string alone, and a class's own recorded
  `signature` is its *base classes*, not its `__init__` parameters.
- `leitir.usage.resolver` (`resolve_consumer`, ADR-0027) resolves, per
  source line and with real scope-aware binding tracking, *which
  distribution* a name is bound to -- exactly the dependency-attribution
  problem it was built for. It does not extract *which symbol* was accessed
  at a usage site: a `CodeReference` carries only `distribution`, `span`,
  and a code digest, never an attribute or call target name. That is
  dependency-level evidence, not symbol-level evidence.

**Conclusion, stated plainly rather than assumed:** the API index supports
symbol-*existence* checking. It does not support reliable arity/signature
checking, and its existence coverage is itself an approximation with real,
identified blind spots (conditional definitions, constants, aliases,
private names). The usage resolver supports correct, conservative
*distribution* attribution and gives the closed unresolved-outcome
vocabulary for free, but not symbol-name recovery at a usage site.

## Decision Drivers

- False positives are fatal for a gate agents hit constantly: a gate that
  flags genuinely correct code gets disabled, and then it protects nothing.
  Python is dynamically typed and statically unresolvable in general.
- Never invent a capability (arity checking, a resolved re-export catalog)
  the underlying evidence does not actually support; report the limitation
  instead of faking it.
- Match ADR-0002's principle: unknown is neither zero nor pass. A
  three-outcome model, not two-way pass/fail.
- Fail closed on a missing, stale, or unverifiable API index -- but
  equally, never fail *code* because the truth surface was absent; that is
  a different, typed failure (of the tool, not of the code).
- Reuse `apisurface`, `usage.resolver`, and their existing error taxonomy
  (`MaterializationError`, `VerificationError`) rather than reimplementing
  AST walking or symbol extraction that already exists.
- Language scope must be honest: the static usage resolver is Python-only
  (ADR-0027). A non-Python input must reject clearly, never silently pass.
- E1: the same run must report enough counts to compute a hallucinated
  symbol rate without a model judge -- total sites examined, resolved,
  violations, unresolved.

## Considered Options

- Two-way pass/fail on exact `qualified_name` (`module.Class.method`) match
  against the API index.
- Three-way outcome using bare-name (not qualified-name) matching against
  the API index alone, treating any index miss as a violation.
- Three-way outcome using bare-name matching against the API index,
  corroborated by a raw full-text scan of the pinned source before ever
  declaring a violation (original decision, amended below).
- Attempt arity/signature checking using the index's formatted `signature`
  string.

## Decision Outcome

Amended decision (2026-09-05, #315): **three outcomes (`ok` / `violation` /
`unresolved`), with `ok` requiring an exact qualified definition or an explicit
module-level reexport**. A raw text scan of pinned source still corroborates
absence before a violation is declared. A bare-name collision cannot prove
that the consumer's qualified access exists.

### Qualified binding evidence (amended 2026-09-05, issue #315)

Consumer imports and complete attribute chains identify the accessed provider
name. The gate maps module paths to the distribution's evidence-backed import
roots, accepts exact indexed definitions, and follows explicit module-level
reexports such as `requests.get` to `requests.api.get`. Ambiguous module layouts,
conditional/star exports and dynamic bindings without exact proof remain
`unresolved`. A bare-name match in another module cannot establish `ok`.

The original bare-name design accepted `requests.parse_header_links` because
`requests.utils.parse_header_links` existed. Actual Requests rejects the first
access. The qualified gate preserves the valid `requests.utils` access and
ordinary public reexports while refusing the false `ok`.

### Why a text-scan corroboration gate, not the index alone

The extractor's blind spots (conditional definitions, module constants,
aliases, private names) are real and were confirmed by construction, not
guessed: `tests/test_check_cli_e2e.py::test_conditionally_defined_symbol_is_unresolved_not_a_violation`
materializes a package whose only symbol is defined inside a top-level
`if True:` block; the naive index-only design would report a violation for
genuinely correct, present code. Before declaring `violation`, `check.py`
therefore also raw-scans the pinned source's own text (word-boundary
match) for the candidate symbol name. Absence from *both* the curated
index *and* the raw source text is the strongest static absence signal
available without executing anything, and is what earns a `violation`. A
name outside the index but present in the raw text is downgraded to
`unresolved` (real, but the index's def/class-only shape could not place
it -- likely a constant, alias, or conditional definition) rather than
guessed either way. If the raw-text scan itself hits its byte/file budget
before finishing, the whole scan is marked `capped` and no violation may
be declared from it at all for the remainder of that run (an absence found
under a capped scan is not proven absence) -- this is surfaced in the JSON
payload as `target_corroboration_capped` so a consumer of the report knows
whether violation detection was able to run to completion.

### Why existence-only, not arity

The index's `signature` field cannot safely support a "wrong arity"
verdict: defaults, `*args`/`**kwargs`, decorators that rewrite a callable's
effective signature, and (for classes) the fact that the recorded
`signature` is the base-class list rather than `__init__`'s parameters all
make a structural arity comparison unreliable enough that a false positive
is a real, not theoretical, risk. This first version does not attempt it.
A future version could add arity checking only if the API index itself is
extended to carry a structured, decorator-aware parameter model -- that is
out of this issue's scope.

### The scope-recovery limitation, and why it is safe

`resolve_consumer` gives certain, scope-correct *distribution* attribution
for a reference, but not the symbol name accessed there. `check.py` adds a
small, local, top-level-only import table (`_ImportTable`) to recover which
symbol a reference names: `import demo` bindings resolve a candidate via
the enclosing `ast.Attribute`, `from demo import X [as Y]` bindings resolve
the candidate directly to `X`. This recovery pass is intentionally not
scope-aware beyond the module's own top level; anything it cannot resolve
(a deeper-scope import, an unusual rebind, dynamic dispatch via `getattr`,
an alias handed to a function, a module value passed around and called
elsewhere) falls back to `unresolved`, never a guessed symbol name and
never a guessed `ok` or `violation`. The effect of a missed recovery is
under-checking (fewer `ok`/`violation` sites, more `unresolved` ones,
`sites_examined` unchanged), which is the safe direction.

**Correction (2026-08-26, P1 rejection fix):** the first version of this
module classified every site where the accessed symbol name could not be
statically recovered as `ok` (reasoning: "it's at least a legitimate
reference to the target distribution, so let it through"). That was wrong,
and an adversarial review caught it live: a file whose *only* usage of a
target package was dynamic dispatch (`getattr(pkg, name)()`, an
alias-then-call, a module handed into a function and called there)
reported `sites_ok=3, sites_violation=0, sites_unresolved=0` -- 100% "ok"
for a file that never demonstrated a single concretely-resolved symbol.
`ok` must mean "resolved and present"; a site whose symbol could not be
recovered was never resolved, full stop, regardless of how confidently its
*distribution* was attributed. Both of the recovery-failure reasons
(`_candidate_for_reference`'s "symbol site not statically located" and
"no attribute access") are now classified `unresolved`, carrying their
original reason string, and never fail the gate. They are also never
promoted to `violation` -- that would just be a differently-flavored guess.
There is no silently-reclassified "genuinely fine" case buried in this
fix: `resolve_consumer` only emits a `CodeReference` at an actual
Name-load usage site (`visit_Name` in `usage/resolver.py`), so a bare
`import x` with no subsequent usage never reaches `_candidate_for_reference`
at all -- every site this fix moved was already a real, examined,
irreducibly-undecidable usage, not an unused import being penalized.
`CheckReport.__post_init__` now enforces this as a structural invariant:
no site in `ok_sites` may carry a placeholder symbol (`"<module>"` /
`"<file>"`) or an empty symbol name.

### Why `guess_import_root` was a documented, accepted limitation

**Superseded (2026-08-27, issue #269, [ADR-0032](0032-import-root-evidence-derivation.md)):**
`check.py` no longer decides which import root to look for by normalizing
the distribution's registry name. It now derives the import root(s) from
the materialized distribution's own evidence -- a real `top_level.txt`,
static `setup.cfg`/`pyproject.toml` packaging metadata, or (lowest
confidence, and the tier that actually recovers the cases named below) the
materialized tree's own layout -- via `leitir.usage.import_evidence`,
extending ADR-0026's import-catalog machinery rather than adding a second
lookup mechanism. `guess_import_root` itself still exists, but only as a
diagnostic display helper; it is no longer consulted to build the
resolver's `import_roots`. `pypi:pillow`, `pypi:pyyaml`, and multi-root
distributions are now actually examined; an import root that still cannot
be determined from any evidence tier (or whose evidence disagrees) still
fails safe exactly as this section originally described -- `nothing_examined`,
exit 4, never a guessed `violation` or a guessed `ok`. The original
limitation text is kept below for history.

There is no local, static, network-free distribution-name-to-import-root
catalog available to this command without the full admitted-consumer
pipeline of ADR-0026 (which requires out-of-band admission evidence --
pinned consumer refs, exact-pin `requirements.txt` digests -- this command
does not have and should not require just to check one file). `check.py`
assumes the import root equals the normalized distribution name. This is
correct for the common case (`flask` -> `flask`, `numpy` -> `numpy`) but
wrong for any renamed distribution, and renamed distributions are common,
not exotic: `pillow` imports as `PIL`, `beautifulsoup4` imports as `bs4`,
`pyyaml` imports as `yaml`, `python-dateutil` imports as `dateutil`, and
`scikit-learn` imports as `sklearn`. When the guess is wrong, the resolver
simply finds no reference to check under the wrong (guessed) name -- zero
sites examined, never a false `ok` or a false `violation` for any
individual site.

**Correction (2026-08-26, P1 rejection fix):** the first version of this
module let a zero-examined-sites run fall straight through to
`sites_ok=0, sites_violation=0, sites_unresolved=0, exit 0` -- which reads,
and was confirmed live to read, exactly like "checked your file, it's
clean," when in truth nothing was checked at all (`pillow` is the
concrete, confirmed repro: `import PIL` against `--against pypi:pillow@...`
examines zero sites because `guess_import_root("pillow")` returns
`"pillow"`, which never matches the consumer's `PIL` import root). A check
that examined zero sites has verified nothing and must never present as a
clean pass. `CheckReport` now exposes a `status` field
(`"nothing_examined"` / `"violations_found"` / `"clean"`) precisely so a
consumer of the JSON never has to separately remember to cross-check
`sites_examined` before trusting `sites_violation == 0`. The CLI also
prints an explicit stderr line naming the import root it looked for when
`sites_examined == 0`, and exits `4` (`ExitCode.NOTHING_INDEXED`) instead
of `0` -- reusing the exact "completed cleanly, but verified nothing, so
neither success nor failure" tier the `index` command already established
for its own all-skipped case, rather than inventing a parallel code for
the same shape of outcome. This does not fix the underlying guesser (that
needs ADR-0026's admission pipeline, and remains explicitly out of scope
for this command); it only makes the guesser's known failure mode loud
instead of silent.

### Fail-closed on the truth surface

If the extracted API index has no Python modules at all (empty source, a
materialization of the wrong ecosystem, or an unverifiable manifest),
`check.py` raises `CheckIndexError` -- a subclass of the existing
`VerificationError` taxonomy -- before evaluating a single site. `check`
never reports `ok` sites against an index that was not actually
established, matching the same fail-closed discipline the rest of leitir
already applies to a missing or tampered manifest.

### Language scope

`discover_python_files` rejects (`UnsupportedLanguageError`) a non-`.py`
file, or a directory with no `.py` files at all, before any network or
materialization work -- fast, offline, and honest, rather than silently
reporting a vacuous `ok`. The target (`--against`) side is always extracted
Python-only (`extract_check_index` always passes `"python"` as the
language hint to `extract_api_surface`, regardless of the pinned source's
declared ecosystem), because the consumer side this command checks is
Python-only in this version; a polyglot pinned repository's non-Python
symbols are simply not part of the checked surface.

### E1: counts

Every `CheckReport` carries `sites_examined`, `sites_ok`,
`sites_violation`, and `sites_unresolved`, with the invariant
`sites_examined == sites_ok + sites_violation + sites_unresolved` enforced
in `CheckReport.__post_init__`. This is sufficient to compute a
hallucinated-symbol rate (`sites_violation / (sites_ok +
sites_violation)`, excluding the honestly-uncertain `unresolved` bucket
from the denominator) without any model judge -- issue #266's most
legible number. The exit code is `CORPUS_FAILURE` (1) if and only if
`sites_violation > 0`; `unresolved` alone never fails the gate. A run with
`sites_examined == 0` is a distinct case (see the `guess_import_root`
correction above): it exits `NOTHING_INDEXED` (4), neither success nor
failure, because zero examined sites means the hallucination-rate
denominator itself is zero -- there is no rate to report, and no verdict
to trust.

### What this version explicitly does NOT check

- Arity, parameter names, keyword-only/positional-only shape, or return
  type -- the index does not support it reliably (see above).
- Anything not reachable through a real top-level or scope-tracked
  `import`/`from ... import` (dynamic imports, star imports, ambiguous
  multi-branch bindings, deep re-export chains) -- these are `unresolved`,
  by the same closed vocabulary ADR-0027 already established.
- Non-Python consumer code, or non-Python symbols in a polyglot pinned
  repository.
- Distribution-to-import-root mapping beyond what
  `leitir.usage.import_evidence` can derive from the materialized tree's
  own evidence (ADR-0032) -- no out-of-band ADR-0026 *admission* evidence
  (a pinned consumer repository, an exact-pin `requirements.txt`) is
  invoked or required; only the already-materialized target's own tree is
  consulted.
- Instance/attribute chains past the first resolved symbol (`flask.Flask`
  is checked; `app.route` on an instance `app = Flask(__name__)` is not --
  that requires runtime type information no static tool has).

## Positive Consequences

- The gate is safe to run unattended and often: its false-positive risk is
  bounded by independent conservative mechanisms (qualified binding evidence,
  text-scan corroboration) rather than one.
- E1's hallucination-rate counts fall out of the same implementation with
  no separate instrumentation.
- Reuses `apisurface` and `usage.resolver` as directed; no AST walking or
  binding-resolution logic already solved elsewhere was reimplemented.

## Negative Consequences

- Real violations can be missed: a genuinely removed symbol whose name
  happens to collide with an unrelated symbol elsewhere in the pinned tree,
  or that still appears in a comment/docstring/dead code path within the
  budget-scanned text, will be reported `unresolved` or `ok` rather than
  `violation`. This under-detection is the accepted, deliberate cost of
  avoiding false positives.
- No arity checking means a call with the right symbol name but wrong
  argument count is not caught by this version.
- The import-root guess is wrong for any renamed distribution (`pillow`/
  `PIL`, `beautifulsoup4`/`bs4`, `pyyaml`/`yaml`, `python-dateutil`/
  `dateutil`, `scikit-learn`/`sklearn`), reducing coverage to zero sites
  for that package rather than checking it -- now surfaced loudly
  (`status: "nothing_examined"`, an explicit stderr line naming the
  guessed root, exit code `NOTHING_INDEXED`) rather than silently, but the
  underlying guess itself is not fixed by this ADR; that remains
  ADR-0026's scope.

## Links

- [ADR-0026](0026-conservative-admission-and-import-catalog.md) -- the
  admission/import-catalog pipeline this command deliberately does not
  invoke (out of scope; see "Why `guess_import_root`").
- [ADR-0027](0027-static-python-usage-resolver.md) -- the static resolver
  this command's distribution attribution is built on.
- `src/leitir/apisurface.py`, `src/leitir/usage/resolver.py`,
  `src/leitir/check.py`.
- `tests/test_check_cli_e2e.py`.
- Issue #266, tasks B3 and E1.

2026-09-05 amendment: Qualified API checking (#315): qualified imports and full attribute chains must reach the exact indexed definition or an explicit module-level reexport. Bare-name collisions in other modules cannot yield ok. Unproven dynamic, conditional or star exports remain unresolved.
