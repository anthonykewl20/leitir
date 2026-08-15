# BTS v1 gold review record

This record reviews the six real task gold annotations against the pinned donor
bytes and their upstream documentation/tests. It is content-addressed by
`tasks/RECEIPTS.json`; the task receipt is SHA-256 of this file's bytes, a
newline, task ID, a newline, and the manifest task digest.

| Task | Grade-2 correctness evidence | Distractor review |
| --- | --- | --- |
| `async-retry-backoff` | `litl/backoff` README “Jitter”, lines 194-211, calls `full_jitter` the default AWS Full Jitter implementation; `_jitter.py:18-28` samples the complete `[0, value]` range. | Cognee and Omi calculate delay shapes, not the selected full-jitter operation. |
| `url-normalization-compare` | `normalize_fragment.py:8-27` documents RFC 3986 fragment-safe encoding and implements quote-after-unquote; the upstream README describes percent encoding and RFC compliance. | w3lib file URI conversion and urltools default-port removal normalize different URL components. |
| `lru-ttl-decisions` | `values_with_ttl.py:4-13` stores `(result, deadline)`, makes a strict deadline decision, and retrieves the result; README lines 98-117 describes TTL and capacity semantics. | The two adjacent triad functions and gazu's expiry predicate are component evidence, not the selected value-construction seed. |
| `binary-wire-decode` | `electrumx/lib/tx.py:143-145` returns an unpacked little-endian uint32 and cursor plus four; its contract test composes uint16 then uint32. README declares MIT. | Other width readers and vlen/zigzag/CRC are real wire primitives but do not provide the selected uint32 cursor step. |
| `worker-shutdown-predicate` | `mypy/build_worker/worker.py:140-147` returns true only for an empty SCC request and asserts an expected alternative tag; module protocol documentation lines 4-15 says empty SCC input prompts cleanup/shutdown. | No separate grade-1 candidate was found; round-2 report documents the rejected event/class-method implementations. |
| `three-repo-combine` | `luhn.py:3-11` computes the documented checksum; its contract test validates known values. The two grade-1 helpers are independently pinned MIT component operations from the async and URL tasks. | Neither helper computes the checksum entry point, so neither is an interchangeable task seed. |

Review result: every task has exactly one grade-2 candidate, every seed identity
is a commit/path/blob/symbol/line tuple, and no missing-gold metric is left
applicable. The source evidence was checked from the pinned donor checkouts
described in `/tmp/opencode/donors/{candidates.json,REPORT.md}` and
`/tmp/opencode/donors2/{candidates2.json,REPORT2.md}`. This is a provenance and
gold-correctness review record, not a claim that live S2 execution has occurred.
