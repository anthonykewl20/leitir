# Static, execution-free resolution of Python consumer usage

- Status: accepted
- Deciders: leitir usage-evidence-pipeline contributors
- Date: 2026-08-25
- Technical Story: issue #257 (blocked by #2, blocks #258)

## Context and Problem Statement

Once a consumer is admitted and its distribution-to-import-root catalog is
known (#256), leitir needs to know *which lines of the consumer's own source*
actually use a given provider distribution, so #258 can assemble that into
signed `CodeReference`/`CoverageSummary` evidence. The consumer is untrusted,
local, third-party source: leitir must never import, exec, eval, or otherwise
run any byte of it to find out.

## Decision Drivers

- Never execute untrusted consumer code, under any circumstance.
- Aliasing, attribute/call usage, and local shadowing must resolve
  correctly, including across several Python scope flavors (function,
  class, comprehension, `global`/`nonlocal`).
- Anything statically unknowable (dynamic import, star import, an
  ambiguous multi-branch binding, a name that flows through another local
  module's re-export, unparsable source, or a declared cap) must come back
  as one of the closed `UnresolvedState` members -- never a guess reported
  as resolved.
- Output must be deterministic: byte-stable across runs and independent of
  `PYTHONHASHSEED`, input file ordering, and `import_roots` dict ordering.

## Considered Options

- Import the consumer module and introspect `sys.modules` / `__dict__`.
- Use a full third-party static-analysis library (e.g. a type-checker's
  internals) for name resolution.
- Hand-roll a `ast`-only, scope-aware binding-table walk (chosen).

## Decision Outcome

Chosen option: a stdlib-only `ast.NodeVisitor` (`src/leitir/usage/resolver.py`,
`resolve_consumer`) that builds a per-scope name-binding table while walking
the AST, and classifies every `Name` load against that table:

- A name currently bound to a tracked provider import root emits a
  `CodeReference` at that exact usage site (never at the import line itself,
  which is a binding event, not a usage).
- A name rebound locally after having been a provider import (function
  param, assignment, `for`/`with`/`except ... as`, nested `def`/`class`,
  `global`/`nonlocal` redirection) is typed `re-export` from that point --
  chosen over inventing a new "shadowed" state, since the closed
  `UnresolvedState` enum is frozen (issue #255) and re-export ("a name that
  flows through an intermediate binding") is the closest true meaning:
  the resolver can no longer vouch for what the name now refers to.
- A name bound to two *different* provider distributions across
  disagreeing branches of the same `if`/`try` (conditional imports,
  `try`/`except ImportError` fallbacks) is `ambiguous-binding`. Branches are
  visited from a common snapshot and only genuinely *changed* values are
  compared across branches, so an untouched name copied unchanged into
  every branch is never mistaken for a disagreement.
- `from <local-module> import <name>` is resolved one hop across files (a
  lightweight, non-scope-aware, module-top-level-only index built ahead of
  the main per-file pass) so a local package `__init__.py` that forwards a
  provider import is recognized -- but the crossing is still always typed
  `re-export`, never `resolved`, matching the acceptance intent that
  re-export flows stay typed-unresolved regardless of whether the resolver
  could technically trace them.
- Comprehensions get their own scope (matching Python 3 semantics); `for`
  loops and `with`/`except ... as` do not, matching Python's own scoping.
- A `from x import *` poisons the *entire file's* evidence (`star-import`,
  zero references emitted for that file) rather than trying to model
  partial poisoning -- a wildcard genuinely makes every subsequent binding
  in that file statically unknowable.
- `__import__(...)` and `importlib.import_module(...)` calls are detected
  structurally (never executed) and flagged `dynamic-import`; the call's
  own name is not treated as a usage site.
- Every cap (file count, bytes per file, AST nodes per file, references per
  run) is a module-level constant with an overridable keyword parameter;
  exceeding one always yields a typed `cap-exceeded` coverage record (or an
  explicit `exclusions` entry for files never examined at all) and the run
  continues rather than aborting.
- All output ordering (references, coverage records, exclusions) is
  produced via explicit sorts, never left to set/dict iteration order, so
  output is stable across `PYTHONHASHSEED` values and input orderings.

### Positive Consequences

- Zero execution risk: the entire resolver is `ast.parse` plus pure data
  structure manipulation.
- The scope model is reusable as-is for #258's evidence assembly.
- Deterministic, cap-bounded behavior gives #259's CLI/replay layer a
  predictable contract to build retries/reporting on.

### Negative Consequences

- Cross-file re-export resolution is intentionally shallow (one hop,
  module-top-level only): a re-export chained through two or more local
  proxy modules falls back to untracked (`shadow`), not `re-export`. This
  is a conservative under-approximation (never a false `resolved`), not a
  correctness bug, but a deeper resolver could recover more evidence.
  Documented for #258/#259; not required by the AC-1/SP-1 acceptance
  criteria for this issue.
- The `if`/`try` branch model does not track finer control flow (e.g. loops
  executing zero or many times); this is acceptable because leitir only
  ever needs a conservative, execution-free classification, not a flow
  analysis.

## Links

- `docs/adr/0025-usage-evidence-and-replay-contract.md` -- the frozen
  contract this resolver produces evidence against.
- `docs/adr/0026-conservative-admission-and-import-catalog.md` -- upstream
  admission/import-root catalog this resolver consumes.
- Issue #257.
