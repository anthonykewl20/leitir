# ADR-0012 Open Question 3 — Measured tree-sitter parser and query limits

Evidence base for `docs/adr/0012-polyglot-graph-via-tree-sitter.md` Open Question 3.
All numbers below come from runs executed on 2026-08-14 with the certified tuple
(tree-sitter 0.25.2; grammars js 0.25.0 / ts 0.23.2 / rust 0.24.2 / go 0.25.0) on
CPython 3.12.3 in `/tmp/opencode/tsint-venv`. The leitir repository was read, never written.

## 1. Corpus provenance

Real, previously materialized leitir shelves on local disk (no network fetches were needed; verified
flags come from each shelf root's `sources.json`):

| Language | Repo | Commit (HEAD of shelf) | Files | Bytes | `node_modules`/`vendor` dirs excluded |
|---|---|---|---|---|---|
| javascript | mermaid-js/mermaid | `7ecca0cd7f1658ef74f4e7e91f925724ef403bbf` | 276 | 25,179,565 | 0 |
| javascript | panva/node-oidc-provider | `96e1583ab112d48bed90729653e382527c78625c` | 427 | 2,182,004 | 0 |
| javascript | pinojs/pino | `eff2b30ea52cb73ec683541972ae57b331626bdf` | 138 | 429,611 | 1 |
| javascript | wix/Detox | `d80a57405142839dfe47ae95de6a191c42c3a7be` | 764 | 5,156,540 | 0 |
| javascript | uuidjs/uuid | `ea83515d6a4de13a8f9d253fe772752c9dd7bbbe` | 39 | 32,853 | 0 |
| typescript | nestjs/nest | `4e3b42d9280b50c928c85915686b43257703cd24` | 1677 | 3,385,824 | 0 |
| typescript | openapi-ts/openapi-typescript | `0cc7ee77d28359c7901d9cd3b5733b70a050ea49` | 134 | 50,816,002 | 0 |
| typescript | kysely-org/kysely | `f24018c789c3cf7ad03ccc672ada63a1ded87f88` | 458 | 2,653,547 | 0 |
| rust | meilisearch/meilisearch | `be181e115792eae868b1b7c0934a2a29b9d2fde7` | 707 | 9,539,089 | 0 |
| rust | pnpm/pnpm | `1c7ad8167b8afaa4aa663db17f05315896d0fb24` | 1281 | 17,484,265 | 25 |
| go | golang/text | `6c97a165dd661335ff7bce6104a008558123c353` | 488 | 40,499,001 | 0 |
| go | lxc/incus | `5910ff48a6f5e1fa15ee3363b4f26076d6e35dda` | 1343 | 11,538,430 | 0 |
| go | gorilla/websocket | `ac0789be11725ab2285233e9a3800c2312cff4fc` | 35 | 187,707 | 1 |
| go | sirupsen/logrus | `d40e25cd45ed9c6b2b66e6b97573a0413e4c23bd` | 46 | 149,526 | 0 |

- **javascript**: 1644 files selected, 32,980,573 bytes total.

- **typescript**: 2000 files selected (capped deterministically from 2269 sorted paths), 5,957,018 bytes total.

- **rust**: 1988 files selected, 27,023,354 bytes total.

- **go**: 1912 files selected, 52,374,664 bytes total.

Total measured: 7544 files. Corpus-wide selection: all `.go`; `.js/.mjs/.cjs/.jsx`; `.ts`
(TSX deliberately excluded — the policy tuple pins `language_typescript` only); `.rs`. `node_modules`,
`vendor`, `.git` pruned everywhere. Local shelves hold more polyglot trees than used (e.g. nodejs/node,
aws-sdk-js-v3, vercel/next.js, backstage); the measured sample keeps every language ≤ 2000 files.

## 2. Per-language parse and size percentiles

### javascript (1644 files, 3 parsed with `root.has_error`)

| Metric | n | p50 | p95 | p99 | max | sum |
|---|---|---|---|---|---|---|
| bytes/file (KiB) | 1644 | 1.5 | 42.2 | 218.1 | 8023.4 | 32207.6 |
| nodes/file (all, incl. unnamed) | 1644 | 447 | 17741 | 94383 | 2281466 | 12626761 |
| tree depth (nodes) | 1644 | 17 | 38 | 49 | 430 | 32939 |
| nodes per byte | 1644 | 0.312 | 0.551 | 0.706 | 1.000 | 536.832 |
| parse wall-time (ms) | 1644 | 0.17 | 5.38 | 27.70 | 863.85 | 4342.65 |
| query matches() (ms) | 1644 | 0.07 | 2.65 | 14.35 | 356.20 | 1931.86 |
| query captures() (ms) | 1644 | 0.08 | 2.90 | 14.85 | 387.71 | 2237.21 |
| query matches/file | 1644 | 12 | 263 | 1300 | 37565 | 219616 |
| captures/file (production count) | 1644 | 12 | 263 | 1300 | 37565 | 219616 |
| definition captures/file | 1644 | 1 | 32 | 146 | 6554 | 34230 |
| call/new captures/file | 1644 | 8 | 204 | 1141 | 31924 | 178772 |

### typescript (2000 files, 16 parsed with `root.has_error`)

| Metric | n | p50 | p95 | p99 | max | sum |
|---|---|---|---|---|---|---|
| bytes/file (KiB) | 2000 | 0.9 | 12.1 | 33.2 | 143.7 | 5817.4 |
| nodes/file (all, incl. unnamed) | 2000 | 235 | 3276 | 8305 | 33944 | 1533347 |
| tree depth (nodes) | 2000 | 14 | 34 | 44 | 106 | 33999 |
| nodes per byte | 2000 | 0.294 | 0.398 | 0.450 | 0.608 | 567.587 |
| parse wall-time (ms) | 2000 | 0.10 | 1.14 | 2.86 | 10.56 | 562.41 |
| query matches() (ms) | 2000 | 0.04 | 0.43 | 1.13 | 4.55 | 222.12 |
| query captures() (ms) | 2000 | 0.04 | 0.47 | 1.30 | 5.06 | 235.98 |
| query matches/file | 2000 | 10 | 90 | 208 | 476 | 45477 |
| captures/file (production count) | 2000 | 10 | 90 | 208 | 476 | 45477 |
| definition captures/file | 2000 | 2 | 15 | 37 | 253 | 8520 |
| call/new captures/file | 2000 | 2 | 53 | 160 | 469 | 25183 |

### rust (1988 files, 3 parsed with `root.has_error`)

| Metric | n | p50 | p95 | p99 | max | sum |
|---|---|---|---|---|---|---|
| bytes/file (KiB) | 1988 | 7.0 | 46.1 | 96.7 | 411.6 | 26390.0 |
| nodes/file (all, incl. unnamed) | 1988 | 1795 | 10740 | 21043 | 93473 | 6445811 |
| tree depth (nodes) | 1988 | 18 | 31 | 39 | 57 | 37417 |
| nodes per byte | 1988 | 0.253 | 0.363 | 0.419 | 0.525 | 506.242 |
| parse wall-time (ms) | 1988 | 0.66 | 3.91 | 8.09 | 34.10 | 2375.10 |
| query matches() (ms) | 1988 | 0.28 | 1.87 | 3.99 | 15.39 | 1066.70 |
| query captures() (ms) | 1988 | 0.33 | 2.02 | 4.23 | 15.07 | 1198.65 |
| query matches/file | 1988 | 32 | 210 | 440 | 1093 | 120325 |
| captures/file (production count) | 1988 | 32 | 210 | 440 | 1093 | 120325 |
| definition captures/file | 1988 | 9 | 48 | 90 | 302 | 29401 |
| call/new captures/file | 1988 | 18 | 165 | 370 | 932 | 84001 |

### go (1912 files, 0 parsed with `root.has_error`)

| Metric | n | p50 | p95 | p99 | max | sum |
|---|---|---|---|---|---|---|
| bytes/file (KiB) | 1912 | 3.1 | 54.3 | 374.3 | 5320.3 | 51147.1 |
| nodes/file (all, incl. unnamed) | 1912 | 844 | 15815 | 170440 | 1592106 | 16732618 |
| tree depth (nodes) | 1912 | 17 | 31 | 234 | 948 | 42390 |
| nodes per byte | 1912 | 0.285 | 0.455 | 0.564 | 0.712 | 534.050 |
| parse wall-time (ms) | 1912 | 0.33 | 6.61 | 63.48 | 583.38 | 5846.38 |
| query matches() (ms) | 1912 | 0.12 | 2.23 | 29.49 | 599.00 | 3041.33 |
| query captures() (ms) | 1912 | 0.14 | 2.95 | 35.65 | 590.51 | 3363.65 |
| query matches/file | 1912 | 14 | 103 | 245 | 7608 | 100732 |
| captures/file (production count) | 1912 | 14 | 103 | 245 | 7608 | 100732 |
| definition captures/file | 1912 | 4 | 33 | 67 | 175 | 15711 |
| call/new captures/file | 1912 | 4 | 62 | 155 | 7604 | 72864 |

Largest files: mermaid `dist/mermaid.js` 8,215,977 B / 2,281,466 nodes / parse 0.9–1.6 s;
golang/text `collate/tables.go` 5,447,983 B / 1,419,017 nodes; pnpm `install/tests.rs` 421,466 B / 93,473 nodes.

### Query-pattern fan-out (matches/file per pattern)

| Language | Pattern | p50 | p95 | p99 | max | sum |
|---|---|---|---|---|---|---|
| javascript | def.function | 0 | 12 | 116 | 3895 | 19242 |
| javascript | def.class | 0 | 1 | 4 | 20 | 468 |
| javascript | def.method | 0 | 17 | 53 | 2656 | 14520 |
| javascript | import.specifier | 0 | 20 | 42 | 120 | 5639 |
| javascript | inherit.base | 0 | 1 | 4 | 216 | 975 |
| javascript | call.callee | 6 | 186 | 1126 | 29613 | 162851 |
| javascript | raise.constructor | 0 | 17 | 79 | 3155 | 15921 |
| typescript | def.function | 0 | 1 | 6 | 27 | 632 |
| typescript | def.class | 1 | 2 | 8 | 30 | 1624 |
| typescript | def.method | 0 | 10 | 29 | 127 | 4594 |
| typescript | import.specifier | 4 | 17 | 38 | 116 | 11287 |
| typescript | inherit.base | 0 | 1 | 1 | 21 | 244 |
| typescript | inherit.iface | 0 | 1 | 2 | 6 | 243 |
| typescript | call.callee | 2 | 45 | 157 | 430 | 21779 |
| typescript | raise.constructor | 0 | 9 | 28 | 182 | 3404 |
| typescript | def.interface | 0 | 1 | 4 | 247 | 877 |
| typescript | def.type | 0 | 2 | 7 | 79 | 793 |
| rust | def.function | 7 | 41 | 76 | 212 | 24177 |
| rust | def.struct | 0 | 6 | 13 | 41 | 3012 |
| rust | def.enum | 0 | 2 | 6 | 29 | 1012 |
| rust | def.trait | 0 | 0 | 2 | 9 | 132 |
| rust | impl.trait | 0 | 3 | 9 | 72 | 1068 |
| rust | import.specifier | 2 | 11 | 20 | 33 | 6918 |
| rust | import.specifier | 0 | 0 | 0 | 2 | 5 |
| rust | call.callee | 9 | 91 | 224 | 596 | 45987 |
| rust | call.macro | 4 | 89 | 208 | 923 | 38014 |
| go | def.function | 1 | 12 | 25 | 80 | 5419 |
| go | def.method | 0 | 20 | 50 | 165 | 7591 |
| go | def.type | 1 | 6 | 13 | 40 | 2701 |
| go | import.path | 4 | 21 | 35 | 87 | 12157 |
| go | call.callee | 4 | 62 | 155 | 7604 | 72864 |

## 3. Adversarial nesting (synthetic)

Isolated subprocess per case, 30 s wall budget, CPython 3.12.3. Depths 100/1k/10k/100k.
**Every case completed — zero timeouts, zero crashes, zero ERROR nodes at any depth.**

| Language | Construct | Depth | Nodes | Tree depth | Parse ms | Walk ms | Peak RSS MiB |
|---|---|---|---|---|---|---|---|
| javascript | arrays | 100 | 308 | 104 | 0.2 | 0.2 | 16 |
| javascript | arrays | 1,000 | 3,008 | 1,004 | 0.7 | 1.2 | 17 |
| javascript | arrays | 10,000 | 30,008 | 10,004 | 6.8 | 11.4 | 23 |
| javascript | arrays | 100,000 | 300,008 | 100,004 | 74.4 | 184.7 | 89 |
| javascript | parens | 100 | 308 | 104 | 0.1 | 0.1 | 16 |
| javascript | parens | 1,000 | 3,008 | 1,004 | 1.1 | 1.0 | 17 |
| javascript | parens | 10,000 | 30,008 | 10,004 | 8.3 | 10.8 | 23 |
| javascript | parens | 100,000 | 300,008 | 100,004 | 77.7 | 184.2 | 89 |
| javascript | blocks | 100 | 310 | 104 | 0.2 | 0.2 | 16 |
| javascript | blocks | 1,000 | 3,010 | 1,004 | 0.7 | 1.2 | 16 |
| javascript | blocks | 10,000 | 30,010 | 10,004 | 7.3 | 11.4 | 23 |
| javascript | blocks | 100,000 | 300,010 | 100,004 | 79.2 | 179.8 | 87 |
| typescript | arrays | 100 | 308 | 104 | 0.1 | 0.1 | 17 |
| typescript | arrays | 1,000 | 3,008 | 1,004 | 0.9 | 1.4 | 17 |
| typescript | arrays | 10,000 | 30,008 | 10,004 | 7.5 | 12.8 | 24 |
| typescript | arrays | 100,000 | 300,008 | 100,004 | 79.0 | 199.4 | 89 |
| typescript | parens | 100 | 308 | 104 | 0.1 | 0.1 | 16 |
| typescript | parens | 1,000 | 3,008 | 1,004 | 0.7 | 0.9 | 17 |
| typescript | parens | 10,000 | 30,008 | 10,004 | 7.3 | 11.3 | 23 |
| typescript | parens | 100,000 | 300,008 | 100,004 | 75.4 | 197.9 | 90 |
| typescript | blocks | 100 | 310 | 104 | 0.1 | 0.1 | 17 |
| typescript | blocks | 1,000 | 3,010 | 1,004 | 0.7 | 1.0 | 17 |
| typescript | blocks | 10,000 | 30,010 | 10,004 | 7.3 | 12.9 | 23 |
| typescript | blocks | 100,000 | 300,010 | 100,004 | 77.0 | 163.2 | 88 |
| typescript | generics | 100 | 507 | 203 | 0.2 | 0.2 | 17 |
| typescript | generics | 1,000 | 5,007 | 2,003 | 1.2 | 1.6 | 18 |
| typescript | generics | 10,000 | 50,007 | 20,003 | 9.9 | 20.2 | 28 |
| typescript | generics | 100,000 | 500,007 | 200,003 | 108.7 | 380.9 | 129 |
| rust | arrays | 100 | 316 | 105 | 0.1 | 0.1 | 17 |
| rust | arrays | 1,000 | 3,016 | 1,005 | 0.7 | 0.9 | 17 |
| rust | arrays | 10,000 | 30,016 | 10,005 | 7.6 | 12.1 | 24 |
| rust | arrays | 100,000 | 300,016 | 100,005 | 85.2 | 195.9 | 89 |
| rust | parens | 100 | 316 | 105 | 0.1 | 0.2 | 17 |
| rust | parens | 1,000 | 3,016 | 1,005 | 0.7 | 1.1 | 17 |
| rust | parens | 10,000 | 30,016 | 10,005 | 10.1 | 12.2 | 23 |
| rust | parens | 100,000 | 300,016 | 100,005 | 73.2 | 175.8 | 90 |
| rust | blocks | 100 | 410 | 204 | 0.2 | 0.2 | 17 |
| rust | blocks | 1,000 | 4,010 | 2,004 | 1.5 | 2.3 | 17 |
| rust | blocks | 10,000 | 40,010 | 20,004 | 8.3 | 14.9 | 26 |
| rust | blocks | 100,000 | 400,010 | 200,004 | 91.3 | 281.8 | 113 |
| rust | macro | 100 | 316 | 106 | 0.2 | 0.2 | 16 |
| rust | macro | 1,000 | 3,016 | 1,006 | 1.3 | 1.7 | 17 |
| rust | macro | 10,000 | 30,016 | 10,006 | 7.2 | 11.7 | 24 |
| rust | macro | 100,000 | 300,016 | 100,006 | 70.3 | 181.1 | 90 |
| go | parens | 100 | 319 | 107 | 0.1 | 0.1 | 16 |
| go | parens | 1,000 | 3,019 | 1,007 | 0.6 | 1.1 | 16 |
| go | parens | 10,000 | 30,019 | 10,007 | 6.1 | 10.0 | 22 |
| go | parens | 100,000 | 300,019 | 100,007 | 58.0 | 168.8 | 80 |
| go | composite | 100 | 912 | 305 | 0.4 | 0.5 | 16 |
| go | composite | 1,000 | 9,012 | 3,005 | 1.8 | 3.2 | 18 |
| go | composite | 10,000 | 90,012 | 30,005 | 19.2 | 63.0 | 34 |
| go | composite | 100,000 | 900,012 | 300,005 | 216.0 | 1058.5 | 198 |
| go | blocks | 100 | 413 | 204 | 0.1 | 0.1 | 16 |
| go | blocks | 1,000 | 4,013 | 2,004 | 0.6 | 1.3 | 16 |
| go | blocks | 10,000 | 40,013 | 20,004 | 6.2 | 15.7 | 24 |
| go | blocks | 100,000 | 400,013 | 200,004 | 72.4 | 261.5 | 103 |

Growth is strictly linear in depth: ~3 nodes/level (arrays/parens/blocks), ~4/level (rust blocks,
go blocks), ~5/level (ts generics), ~9/level (go `[]any{}` composite literals). Parse cost stays
0.6–2.4 µs per nesting level; the worst case (go composite, depth 100k) needed 216 ms parse,
1.06 s full traversal, 198 MiB peak RSS. Depth itself is therefore not a crash vector in the
certified tuple up to 100k; the DoS exposure scales with **bytes** (≈ depth × 2–7 bytes/level),
which `max_file_bytes` already bounds.

## 4. Error-recovery stress (seeded delimiter deletion)

Five largest files per language; one deterministic delimiter (`()[]{}'"`,;`) deleted per selected
line at 1%/10%/50% line density (seed = sha256 of `oq3|<lang>|<file>|<density>`, first 16 hex).

| Language | File | Bytes | Clean: ms→nodes (err) | 1%: ms→nodes (err) | 10%: ms→nodes (err) | 50%: ms→nodes (err) |
|---|---|---|---|---|---|---|
| javascript | mermaid.js | 8,215,977 | 1578ms→2,281,466n (0E) | 2189ms→2,243,787n (10,341E) | 1712ms→1,832,138n (23,276E) | 2478ms→1,329,640n (44,677E) |
| javascript | mermaid.min.js | 3,566,058 | 726ms→2,127,360n (0E) | 821ms→2,086,663n (471E) | 790ms→1,990,329n (1,195E) | 745ms→1,755,212n (2,741E) |
| javascript | yarn-4.12.0.cjs | 2,992,863 | 506ms→1,540,718n (0E) | 467ms→1,395,265n (242E) | 575ms→1,502,142n (296E) | 437ms→1,047,925n (1,127E) |
| javascript | chunk-A7G5T7E5.mjs | 1,341,135 | 121ms→331,488n (0E) | 207ms→259,849n (2,951E) | 206ms→252,120n (3,482E) | 374ms→211,346n (7,912E) |
| javascript | chunk-EMKVYAI2.mjs | 1,015,304 | 106ms→342,194n (0E) | 139ms→341,362n (970E) | 254ms→336,135n (3,557E) | 498ms→314,785n (10,717E) |
| typescript | huge-db.test-d.ts | 147,161 | 9ms→25,285n (0E) | 9ms→25,268n (3E) | 11ms→25,139n (54E) | 16ms→24,523n (166E) |
| typescript | schema.test.ts | 146,306 | 10ms→33,944n (0E) | 18ms→26,687n (219E) | 32ms→27,677n (496E) | 57ms→21,662n (1,086E) |
| typescript | select-query-builder.ts | 79,591 | 6ms→10,904n (2E) | 10ms→10,544n (92E) | 14ms→10,577n (261E) | 12ms→7,814n (278E) |
| typescript | merge.test.ts | 54,107 | 3ms→11,174n (0E) | 6ms→11,146n (17E) | 12ms→9,896n (160E) | 4ms→1,325n (63E) |
| typescript | operation-node-transformer.ts | 48,933 | 4ms→12,621n (0E) | 20ms→12,265n (318E) | 20ms→12,147n (392E) | 15ms→9,356n (178E) |
| rust | tests.rs | 421,466 | 30ms→93,473n (0E) | 31ms→55,279n (45E) | 36ms→42,981n (149E) | 37ms→32,326n (312E) |
| rust | proxy.rs | 267,396 | 20ms→54,363n (0E) | 25ms→45,434n (20E) | 31ms→43,921n (157E) | 38ms→40,918n (363E) |
| rust | mod.rs | 208,952 | 13ms→29,906n (0E) | 16ms→29,055n (10E) | 26ms→32,159n (96E) | 28ms→30,618n (221E) |
| rust | server.rs | 187,106 | 14ms→39,901n (0E) | 15ms→39,892n (45E) | 33ms→26,269n (514E) | 27ms→21,383n (281E) |
| rust | server.rs | 156,477 | 16ms→47,454n (0E) | 23ms→37,849n (22E) | 24ms→30,598n (141E) | 19ms→18,493n (173E) |
| go | tables.go | 5,447,983 | 552ms→1,419,017n (0E) | 576ms→1,401,056n (813E) | 832ms→1,396,656n (7,663E) | 1118ms→1,495,364n (34,062E) |
| go | tables.go | 4,950,165 | 554ms→1,592,106n (0E) | 579ms→1,590,224n (701E) | 691ms→1,559,032n (6,704E) | 1564ms→941,197n (3,961E) |
| go | tables.go | 3,891,830 | 284ms→799,968n (0E) | 329ms→795,844n (2,121E) | 388ms→712,403n (4,905E) | 636ms→671,840n (13,453E) |
| go | tables15.0.0.go | 1,288,180 | 70ms→184,122n (0E) | 86ms→184,580n (248E) | 155ms→187,940n (2,402E) | 433ms→202,500n (10,537E) |
| go | tables13.0.0.go | 1,244,128 | 68ms→177,969n (0E) | 80ms→178,433n (246E) | 143ms→182,159n (2,352E) | 404ms→194,569n (9,944E) |

No hangs or crashes at any density. Parse time grows at most ~6× (go `tables13.0.0.go`,
68ms→433ms at 50%); node counts never explode (they usually shrink — deleted delimiters remove
structure). `root.has_error` was True for every corrupted parse and every ERROR node was counted
by the same traversal the kernel uses, so fail-closed error detection holds under stress.

## 5. Peak memory (isolated subprocess, `getrusage` ru_maxrss)

| Case | Bytes | Nodes | Parse ms | Query ms | RSS baseline | After parse | Peak (after walk+query) |
|---|---|---|---|---|---|---|---|
| javascript/mermaid-js/mermaid@7ecca0cd/dist/mermaid.js | 8,215,977 | 2,281,466 | 853 | 334 | 28 MiB | 244 MiB | 545 MiB |
| typescript/kysely-org/kysely@f24018c7/test/node/src/schema.test.ts | 146,306 | 33,944 | 15 | 5 | 25 MiB | 28 MiB | 33 MiB |
| typescript/kysely-org/kysely@f24018c7/test/typings/test-d/huge-db.test- | 147,161 | 25,285 | 11 | 4 | 25 MiB | 28 MiB | 31 MiB |
| rust/pnpm/pnpm@1c7ad816/pnpm/crates/package-manager/src/install/t | 421,466 | 93,473 | 34 | 16 | 22 MiB | 31 MiB | 43 MiB |
| go/golang/text@6c97a165/collate/tables.go | 4,950,165 | 1,592,106 | 510 | 306 | 24 MiB | 179 MiB | 393 MiB |
| javascript/parens,100000 | 200,012 | 300,008 | 75 | 33 | 17 MiB | 45 MiB | 89 MiB |
| typescript/generics,100000 | 300,011 | 500,007 | 107 | 52 | 20 MiB | 63 MiB | 129 MiB |
| rust/blocks,100000 | 200,011 | 400,010 | 88 | 46 | 19 MiB | 55 MiB | 112 MiB |
| go/composite,100000 | 700,019 | 900,012 | 183 | 88 | 17 MiB | 83 MiB | 199 MiB |

Peak RSS is dominated by full-tree traversal from Python (~230–250 B/node): the 2.28M-node
mermaid bundle peaks at 545 MiB vs a 245 MiB parse-only footprint. Traversal cost, not parsing,
is the memory multiplier the node budget must bound.

## 6. Candidate-limit coverage against the corpus

Rejected share over all 7,544 measured files (legitimate-content rejection risk):

| `max_file_bytes` | files rejected | share |
|---|---|---|
| 262,144 (0 MiB) | 59 | 0.78% |
| 524,288 (0 MiB) | 20 | 0.27% |
| 1,048,576 (1 MiB) | 13 | 0.17% |
| 2,097,152 (2 MiB) | 6 | 0.08% |
| 4,194,304 (4 MiB) | 3 | 0.04% |
| 8,388,608 (8 MiB) | 0 | 0.00% |
| 16,777,216 (16 MiB) | 0 | 0.00% |

| `max_tree_nodes_per_file` | files rejected | share |
|---|---|---|
| 50,000 | 89 | 1.18% |
| 100,000 | 54 | 0.72% |
| 250,000 | 22 | 0.29% |
| 500,000 | 6 | 0.08% |
| 1,000,000 | 5 | 0.07% |
| 2,500,000 | 0 | 0.00% |

## 7. Recommended limits (derivation and comparison)

Cross-language worst observed values (the binding column for each derivation):
bytes p95 = 55,585 (go), bytes p99 = 383,270 (go); nodes p95 = 17,741 (js), nodes p99 = 170,440 (go);
depth p95 = 38, p99 = 234, max = 948 (all go); matches p95 = 263/file (js); def captures p95 = 48/file (rust);
call/new captures p95 = 204/file (js). Largest single-repo per-language scope observed = 1,677 files (nestjs/nest).
Full-corpus per-language totals (a whole-repo request is the realistic request shape): matches/captures
js 219,616 · go 100,732 · rust 120,325 · ts 45,477; def captures js 34,230 · rust 29,401 · go 15,711 · ts 8,520;
call captures js 178,772 · rust 84,001 · go 72,864 · ts 25,183.

Derivation rules: per-file caps use ceil(p99 × 1.5) so the cap clears the whole tail band of *generated*
Unicode-table/bundle files that sit between p95 and max; request-wide caps use ceil(max_files × p95 × 2)
(p95 not mean, because a request can deliberately select the largest files of a repo; ×2 because request
scope composition is attacker-influenced within a legitimate repo). Safety factors are calibrated so that
(i) no measured hand-written file is rejected and (ii) every measured rejection is a machine-generated file
(verified above: all files >100k nodes or >2 MiB are `tables*.go`, `data*_test.go`, `*.mjs` build chunks,
or minified bundles).

| Limit | Recommended | Derivation | Provisional in repo (historical; superseded 2026-08-14 by ratified kernel defaults) | Verdict on provisional |
|---|---|---|---|---|
| `max_files` | **2,000** | ceil(1,677 observed scope p95 × 1.2); covers every measured single-repo language scope | none (test fixture 10; BTS candidates budget uses 1,000) | fixture value is a toy; BTS 1,000 would under-cover nest (1,677)/incus (1,343). AWS-scale repos (aws-sdk-js-v3: 35,779 `.ts` on shelf) must split requests — deliberate |
| `max_file_bytes` | **2,097,152 (2 MiB)** | ≈ p99 383,270 × 5.5; rejects 6/7,544 files (0.08%), all generated (mermaid/yarn bundles, `collate/tables.go`) | none (test fixture 1,024) | fixture value is a toy; 2 MiB bounds adversarial parse to ~4.2 M nodes (measured ≤2.0 nodes/byte) |
| `max_tree_nodes_per_file` | **250,000** | ceil(170,440 p99 × 1.47); rejects 22/7,544 (0.29%), all generated; ≈60 MiB traversal peak (measured ~240 B/node) | **100,000** (ts_kernel.py:23) | **slightly too low**: sits exactly at hand-written p99 (94,383) and rejects 32 generated-but-ordinary files (`tables9–15.go` ≤184k) that a margin cap admits; still fail-closed-safe |
| `max_query_matches` | **1,100,000** | ceil(2,000 × 263 × 2) = 1,052,000 → round to 1.1 M | **100,000** (ts_kernel.py:24) | **too low for real requests**: a whole-corpus go request already totals 100,732; js totals 219,616 (2.2× over) — legitimate mid-size repos breach the provisional cap |
| `max_symbols` | **200,000** | ceil(2,000 × 48 × 2) = 192,000 → round | **100,000** (ts_kernel.py:25) | marginal: measured real totals ≤34,230 pass, but p95-composed requests approach 96k; raise for margin |
| `max_edges` | **900,000** | ceil(2,000 × 204 × 2) = 816,000 → round | **100,000** (ts_kernel.py:26) | **too low for real requests**: js call captures alone total 178,772 over 1,644 files (1.8× over) before resolution filtering |
| `max_work_units` | **10,000** (keep) | must be ≥ `max_files`; 5× headroom while units stay per-file | **10,000** (ts_kernel.py:27) | adequate **only** while `add_file` counts 1/file; if units ever count queries/nodes it must be re-derived |
| `max_tree_depth_per_file` (new, optional) | **10,000** | corpus max 948, p99 234 → 10.6× max; rejects nothing measured; cheap check inside the existing walk | absent | defense-in-depth only: 100k depth already parses in ≤216 ms with no crash |

Adversarial cross-checks on the recommended set: a 2 MiB `f();`-spam file yields ≈524k captures —
below the 1.1 M request cap as a single file, and the third such file breaches it, so request-wide
spam is bounded; a 2 MiB nesting bomb yields ≤4.2 M nodes and is rejected by the 250k node cap.
Native backstop available: `QueryCursor.match_limit` defaults to 4,294,967,295 (measured) — the
kernel may set it to `max_query_matches` so the C engine itself truncates at the policy bound.

**Enforcement-shape finding (memory):** `BudgetCounters.add_file` (ts_kernel.py:148-151) calls
`walk_nodes(root)` which *materializes the entire node tuple before counting*. Measured traversal
cost is ~240 B/node, so a max-file-bytes-compliant adversarial file can transiently allocate
~1 GiB before the node budget rejects it. Recommend counting with an early-abort streaming walk
(count without retaining nodes, abort at limit+1) — same failure identity, bounded transient memory.

## 8. Methodology

- Environment: CPython 3.12.3, `/tmp/opencode/tsint-venv`, tree-sitter 0.25.2 + grammars
  js 0.25.0 / ts 0.23.2 / rust 0.24.2 / go 0.25.0 (ABI 15, except ts ABI 14). 16-core Linux host.
- Scripts (all under `/tmp/opencode/oq3/scripts/`, outputs under `results/`):
  `manifest.py` (deterministic corpus selection, `node_modules`/`vendor`/`.git` pruned, sorted paths,
  2,000-file cap applied to typescript only); `measure.py` (per file: one timed `parser.parse`,
  iterative all-node traversal for count/depth/ERROR nodes, `QueryCursor.matches` for per-pattern
  fan-out and timed `QueryCursor.captures` mirroring the production counting in javascript.py:88-89);
  `adversarial.py` (fresh subprocess per case, 30 s wall budget); `error_stress.py` (sha256-seeded
  delimiter deletion); `memory.py` (`getrusage` ru_maxrss staged around parse/walk/query);
  `report.py` (nearest-rank percentiles). All runs with `PYTHONHASHSEED=0`.
- JS query text is VERBATIM the stage-2 producer's `QUERY_TEXT` (javascript.py:23-30). TS/Rust/Go
  queries were written for this measurement (no stage-2 producer exists yet). Grammar probes rejected
  three naive patterns — TS `class_declaration name:(identifier)`, TS `class_heritage (identifier)`,
  Go `import_spec name:(identifier)` — replaced by `type_identifier` names, `extends_clause`/
  `implements_clause`, and `import_spec path:(interpreted_string_literal)`. Evidence that query
  portability across the JS/TS grammars cannot be assumed.
- Error-stress seeds: `sha256("oq3|<lang>|<file>|<density>")[:16]` → `random.Random`; densities
  0.01/0.10/0.50; one delimiter (`()[]{}'"`,;`) deleted per selected line.
- Clean corpus files that still parse with `root.has_error`: 3 js, 16 ts, 3 rust, 0 go (real upstream
  content — extraction blockers, not measurement errors).
- Language processes ran sequentially per language; go/typescript/rust measurement processes ran
  concurrently on an idle 16-core host (count metrics are deterministic; parse wall-times may carry
  minor scheduling noise).
- Failures/timeouts: none. All 48 adversarial cases, all 60 error-stress parses, all 9 memory cases
  completed within budget.
- UNVERIFIED: CPython 3.14 behavior (venv is 3.12-only); musllinux-aarch64 (fail-closed per
  requirements-tree-sitter.lock, not executable here); TSX (no `language_tsx` factory is pinned by
  the policy); nesting beyond 100k depth; effects of `set_max_start_depth`/`timeout_micros` cursor
  knobs (available in 0.25.2, unused by the producer).
- The leitir working tree was only read (it carries an uncommitted stage-2 diff; `ts_kernel.py` and
  `javascript.py` quoted from it are dated 2026-08-14).
