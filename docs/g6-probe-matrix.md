# Committed probe matrix for issue #49 (G6) — legacy GET /search/code ground truth

This is the committed probe matrix for issue #49 / G6. It was captured live
against `https://api.github.com/search/code` on 2026-08-06
(token-authenticated, legacy endpoint — the endpoint `leitir`'s
`GitHubCodeSearchTransport` actually calls). All probes use `per_page=1`;
`total_count` is the API's reported match count. Control term: `urlencode`.

The verdicts are stable behavioral ground truth; absolute counts drift with the live index.

## Honored syntax (results are meaningful)

| Syntax | Query used | total_count | Verdict |
|---|---|---|---|
| bare term | `urlencode` | 12,222,464 | control (identifier/token lossless) |
| AND (implicit) | `urlencode doseq` | 162,816 | honored (narrowing) |
| NOT | `urlencode -doseq` | 12,189,696 | honored (narrowing) |
| `path:` | `path:urllib` | 413 | honored (path restriction) |
| `filename:` | `filename:parse.py` | 8,720 | honored (file name restriction) |
| `language:` | `urlencode language:python` | 1,691,648 | honored |
| `org:` | `urlencode org:python` | 100 | honored |
| `repo:` | `urlencode repo:python/cpython` | 15 | honored |
| `in:path` | `urllib in:path` | 2,273,280 | honored (path scope) |
| `in:file` | `urlencode in:file` | 12,222,464 | honored (default scope; no change) |

## Not honored (silently degraded to literal text)

| Syntax | Query used | total_count | Verdict |
|---|---|---|---|
| slash regex | `/urlencode/` | 2,384 | literal `/urlencode/` text, NOT regex |
| regex lookahead | `/urlencode(?=x)/` | 0 | degraded to nothing (no error) |
| regex lookbehind | `/(?<=a)urlencode/` | 0 | degraded to nothing (no error) |
| regex backref | `/(urlencode)\1/` | 0 | degraded to nothing (no error) |
| regex char class | `/url[ae]/` | 0 | degraded to nothing (no error) |
| regex quantifier | `/urlencode{2}/` | 0 | degraded to nothing (no error) |
| bare lookahead | `urlencode(?=x)` | 0 | degraded to nothing (no error) |
| `regex:` qualifier | `regex:urlencode` | 1 | literal (no such qualifier) |
| `symbol:` | `symbol:urlencode` | 33 | literal (no such qualifier) |
| `symbol:` + regex | `symbol:/^urlencode$/` | 0 | literal / no match |
| `filename:` + slash | `filename:/urlencode/` | 440 | slashes treated literally in filename |
| quoted string | `"urlencode"` | 12,222,464 | quotes are NOT a special operator |

## Rejected (HTTP error)

| Syntax | Query used | HTTP error | Verdict |
|---|---|---|---|
| `in:comments` | `urlencode in:comments` | 422 | invalid qualifier on legacy endpoint |
| `in:body` | `urlencode in:body` | 422 | invalid qualifier on legacy endpoint |

## Spec conclusions for G6 / issue #49

1. **REGEX is wholly unexpressible** on the legacy endpoint. Every regex form
   (slash-delimited, `regex:` qualifier, bare, filename-scoped) silently
   degrades — either to literal text or to zero results. No form raises a
   syntax error. The honest behavior is to **reject** a `REGEX` predicate with
   a typed failure (`REJECT_SEMANTIC_DEGRADATION`), never compile it.
2. **SYMBOL_DEFINITION / SYMBOL_REFERENCE / SIGNATURE / CALL / IMPORT** have no
   honoring qualifier (`symbol:` is literally ignored). They must be rejected,
   or compiled to literal text WITH a machine-readable degradation note. The
   probe shows `symbol:` returns plausible-looking non-zero literal results,
   which is the worst form of silent degradation.
3. **EXACT_TEXT / IDENTIFIER / TOKEN_SEQUENCE** compile losslessly to bare
   terms. Caveat: quotes are not honored, so EXACT_TEXT cannot request
   exact-substring semantics — it is token search.
4. **PATH** compiles to `path:` which is honored (qualifier semantics).
5. The report needs a `query_translation` record: per-predicate
   `(kind -> emitted syntax | rejected-reason)` so no predicate kind is
   silently flattened.

## Methodology

- Probes run with token auth (search rate limit 30/min). 403s during collection
  were rate-limit resets, not syntax rejections; re-probed after reset.
- `in:file` equal to control is expected: `in:file` is the default scope.
- Values are live totals; they drift with the index. The VERDICT column is the
  stable ground truth, not the absolute counts.
