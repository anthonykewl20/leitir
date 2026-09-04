# Leitir calibration report

Run `20260904T120617Z-0002` at 2026-09-04T12:06:17Z on `c7c73eb08a78`. Probes: mutation.

## Convergence

| run | sha | blind-spot index | new | fixed | regressed |
|---|---|---|---|---|---|
| 20260904T115118Z-0001 | c7c73eb0 | 1402 | 467 | 0 | 0 |
| 20260904T120617Z-0002 | c7c73eb0 | 1456 | 23 | 0 | 0 |

Open findings by severity: critical 0, high 3, medium 473, low 13, info 1. Blind-spot index **1456** (target 0).

## Measurements

| probe | result |
|---|---|
| mutation | kill rate 77.9% (95% CI 69.0% to 84.8%) over 105 of 18775 enumerated mutants; 23 survived; selection=contexts |

### Mutation by operator

| operator | killed | survived | kill % |
|---|---|---|---|
| arith-swap | 3 | 0 | 100% |
| bool-flip | 2 | 1 | 67% |
| boolop-swap | 7 | 4 | 64% |
| cmp-swap | 16 | 7 | 70% |
| if-negate | 5 | 0 | 100% |
| int-shift | 6 | 9 | 40% |
| not-drop | 10 | 0 | 100% |
| raise-drop | 21 | 1 | 95% |
| return-none | 11 | 1 | 92% |

## Open findings (top 40)

- **high** `bd8100993bedd150` [fuzz/fuzz-crash] crash in trust: TypeError: unhashable type: 'dict' — `trust:TypeError@trust.py:_license` (seen 1x, status open)
  - repro: `python tools/calibrate.py fuzz-repro --target trust --seed 1 --index 13`
- **high** `8735063ec4b0c090` [fuzz/fuzz-crash] crash in trust: TypeError: unhashable type: 'dict' — `trust:TypeError@trust.py:_parity` (seen 1x, status open)
  - repro: `python tools/calibrate.py fuzz-repro --target trust --seed 1 --index 3`
- **high** `228b07e529c2910d` [mutation/surviving-mutant] tests blind to raise-drop: `raise ResolutionError( f"npm registry lookup failed for {nam` -> `pass` — `src/leitir/resolver.py:2545` (seen 1x, status open)
  - repro: `python tools/calibrate.py mutant ab58a3fced513e86 --path src/leitir/resolver.py`
- **medium** `4a06716ac342cc41` [coverage/uncovered-raise] fail-closed path never executed by any test: raise ValueError(f"invalid shelved source path: {entry['path']!r}") — `src/leitir/corpus.py:192` (seen 1x, status open)
  - repro: `sed -n 187,194p src/leitir/corpus.py`
- **medium** `f01a759b419bbf02` [coverage/uncovered-raise] fail-closed path never executed by any test: raise ValueError(f"source has no valid manifest (run 'leitir upgrade-cache' to migrate legacy shelves): {e — `src/leitir/corpus.py:213` (seen 1x, status open)
  - repro: `sed -n 208,215p src/leitir/corpus.py`
- **medium** `5cea6960e585f953` [coverage/uncovered-raise] fail-closed path never executed by any test: raise ValueError(f'source changed during trust verification: {spec}') — `src/leitir/corpus.py:414` (seen 1x, status open)
  - repro: `sed -n 409,416p src/leitir/corpus.py`
- **medium** `74cc0cbf9c5ba274` [coverage/uncovered-raise] fail-closed path never executed by any test: raise ValueError(f'invalid API cache {label}: {value!r}') — `src/leitir/corpus.py:445` (seen 1x, status open)
  - repro: `sed -n 440,447p src/leitir/corpus.py`
- **medium** `1506fa9e0de2dbb6` [coverage/uncovered-raise] fail-closed path never executed by any test: raise ValueError(f'invalid examples cache {label}: {value!r}') — `src/leitir/corpus.py:500` (seen 1x, status open)
  - repro: `sed -n 495,502p src/leitir/corpus.py`
- **medium** `d8841b2eb5879ae9` [coverage/uncovered-raise] fail-closed path never executed by any test: raise ValueError(f'snapshot is missing {pointers_name}') — `src/leitir/corpus.py:571` (seen 1x, status open)
  - repro: `sed -n 566,573p src/leitir/corpus.py`
- **medium** `cac98ec27c3a90dc` [coverage/uncovered-raise] fail-closed path never executed by any test: raise FileExistsError(f'destination corpus is not an ordinary directory: {corpus_root}') — `src/leitir/corpus.py:595` (seen 1x, status open)
  - repro: `sed -n 590,597p src/leitir/corpus.py`
- **medium** `ed84e72bda26f968` [coverage/uncovered-raise] fail-closed path never executed by any test: raise FileExistsError(f'destination corpus is not empty: {corpus_root}') — `src/leitir/corpus.py:599` (seen 1x, status open)
  - repro: `sed -n 594,601p src/leitir/corpus.py`
- **medium** `589a3d8e64c79afb` [coverage/uncovered-raise] fail-closed path never executed by any test: raise TypeError('resolved must be a RepoScope or ResolvedPackage') — `src/leitir/corpus.py:706` (seen 1x, status open)
  - repro: `sed -n 701,708p src/leitir/corpus.py`
- **medium** `6032c0b43a2d7f0a` [coverage/uncovered-raise] fail-closed path never executed by any test: raise MaterializationError(f'registry-only resolution of {spec} has no checksum-verified artifact') — `src/leitir/corpus.py:729` (seen 1x, status open)
  - repro: `sed -n 724,731p src/leitir/corpus.py`
- **medium** `b3d5634d65978e65` [coverage/uncovered-raise] fail-closed path never executed by any test: raise RuntimeError('Go module zip resolution has no proxy URL') — `src/leitir/corpus.py:736` (seen 1x, status open)
  - repro: `sed -n 731,738p src/leitir/corpus.py`
- **medium** `54fcf0c1ee1d36af` [coverage/uncovered-raise] fail-closed path never executed by any test: raise RuntimeError('materializer returned a source without a valid manifest') — `src/leitir/corpus.py:816` (seen 1x, status open)
  - repro: `sed -n 811,818p src/leitir/corpus.py`
- **medium** `f1b602f7fff8797b` [coverage/uncovered-raise] fail-closed path never executed by any test: raise ValueError('source manifest must be an object') — `src/leitir/corpus.py:980` (seen 1x, status open)
  - repro: `sed -n 975,982p src/leitir/corpus.py`
- **medium** `5ca2598e6bc536dd` [coverage/uncovered-raise] fail-closed path never executed by any test: raise ValueError('unsupported authentication scheme') — `src/leitir/credentials.py:32` (seen 1x, status open)
  - repro: `sed -n 27,34p src/leitir/credentials.py`
- **medium** `9e97138fd04223ff` [coverage/uncovered-raise] fail-closed path never executed by any test: raise OSError('scratch source is not a directory') — `src/leitir/exec_sandbox.py:1013` (seen 1x, status open)
  - repro: `sed -n 1008,1015p src/leitir/exec_sandbox.py`
- **medium** `12d6bcc6cba86cd3` [coverage/uncovered-raise] fail-closed path never executed by any test: raise OSError('scratch source contains a special file') — `src/leitir/exec_sandbox.py:1033` (seen 1x, status open)
  - repro: `sed -n 1028,1035p src/leitir/exec_sandbox.py`
- **medium** `a83b3e95e9d603ed` [coverage/uncovered-raise] fail-closed path never executed by any test: raise _reject('writable scratch source quota cannot be measured', 'scratch_quota_unverifiable') — `src/leitir/exec_sandbox.py:1038` (seen 1x, status open)
  - repro: `sed -n 1033,1040p src/leitir/exec_sandbox.py`
- **medium** `2bf68d9d3de624bf` [coverage/uncovered-raise] fail-closed path never executed by any test: raise _reject('execution gate changed while preparing containment', 'execution_gate_mismatch') — `src/leitir/exec_sandbox.py:1066` (seen 1x, status open)
  - repro: `sed -n 1061,1068p src/leitir/exec_sandbox.py`
- **medium** `bd2ecb75e93348d9` [coverage/uncovered-raise] fail-closed path never executed by any test: raise _reject('host architecture does not match the pinned policy', 'architecture_mismatch') — `src/leitir/exec_sandbox.py:1069` (seen 1x, status open)
  - repro: `sed -n 1064,1071p src/leitir/exec_sandbox.py`
- **medium** `9246dca1e9847840` [coverage/uncovered-raise] fail-closed path never executed by any test: raise _reject('generated nsjail configuration exceeds its bound', 'config_too_large') — `src/leitir/exec_sandbox.py:1073` (seen 1x, status open)
  - repro: `sed -n 1068,1075p src/leitir/exec_sandbox.py`
- **medium** `345cf9a947d34bbe` [coverage/uncovered-raise] fail-closed path never executed by any test: raise ValueError('startup procfs receipt is malformed') — `src/leitir/exec_sandbox.py:1181` (seen 1x, status open)
  - repro: `sed -n 1176,1183p src/leitir/exec_sandbox.py`
- **medium** `dfea7f736dccf94c` [coverage/uncovered-raise] fail-closed path never executed by any test: raise _reject('nsjail release/build identity does not match policy', 'nsjail_identity_mismatch') — `src/leitir/exec_sandbox.py:370` (seen 1x, status open)
  - repro: `sed -n 365,372p src/leitir/exec_sandbox.py`
- **medium** `7d9042c17e403bb2` [coverage/uncovered-raise] fail-closed path never executed by any test: raise _reject('nsjail release/build identity does not match policy', 'nsjail_identity_mismatch') — `src/leitir/exec_sandbox.py:372` (seen 1x, status open)
  - repro: `sed -n 367,374p src/leitir/exec_sandbox.py`
- **medium** `05ff137e4f396b2c` [coverage/uncovered-raise] fail-closed path never executed by any test: raise _reject("Leitir's canonical seccomp policy is invalid", 'invalid_seccomp_policy') — `src/leitir/exec_sandbox.py:496` (seen 1x, status open)
  - repro: `sed -n 491,498p src/leitir/exec_sandbox.py`
- **medium** `dfefa60ac19a5a5e` [coverage/uncovered-raise] fail-closed path never executed by any test: raise _reject('mount entry is malformed', 'invalid_mount_entry') — `src/leitir/exec_sandbox.py:519` (seen 1x, status open)
  - repro: `sed -n 514,521p src/leitir/exec_sandbox.py`
- **medium** `2594ae29da1edcb2` [coverage/uncovered-raise] fail-closed path never executed by any test: raise _reject('mount plan digest does not match its inputs', 'mount_plan_digest_mismatch') — `src/leitir/exec_sandbox.py:530` (seen 1x, status open)
  - repro: `sed -n 525,532p src/leitir/exec_sandbox.py`
- **medium** `c61a93550da5ee29` [coverage/uncovered-raise] fail-closed path never executed by any test: raise OSError('nsjail probe has no output pipe') — `src/leitir/exec_sandbox.py:708` (seen 1x, status open)
  - repro: `sed -n 703,710p src/leitir/exec_sandbox.py`
- **medium** `f821dcb22cd1494a` [coverage/uncovered-raise] fail-closed path never executed by any test: raise OSError('mount source is not a regular file or directory') — `src/leitir/exec_sandbox.py:847` (seen 1x, status open)
  - repro: `sed -n 842,849p src/leitir/exec_sandbox.py`
- **medium** `e3a18d724f6e6e4a` [coverage/uncovered-raise] fail-closed path never executed by any test: raise OSError('mount source contains a symlink or special file') — `src/leitir/exec_sandbox.py:878` (seen 1x, status open)
  - repro: `sed -n 873,880p src/leitir/exec_sandbox.py`
- **medium** `107b1a9ff3d09a0d` [coverage/uncovered-raise] fail-closed path never executed by any test: raise TypeError('path must be a Path') — `src/leitir/exit_corpus.py:374` (seen 1x, status open)
  - repro: `sed -n 369,376p src/leitir/exit_corpus.py`
- **medium** `b3433590457b441d` [coverage/uncovered-raise] fail-closed path never executed by any test: raise BTSError(BTSRejectReason.REJECT_PROVENANCE_MISMATCH, 'exit corpus manifest is not valid JSON', detai — `src/leitir/exit_corpus.py:382` (seen 1x, status open)
  - repro: `sed -n 377,384p src/leitir/exit_corpus.py`
- **medium** `34fd2030f29a06d7` [coverage/uncovered-raise] fail-closed path never executed by any test: raise TypeError('manifest_dict and runnable must be mappings') — `src/leitir/exit_corpus.py:488` (seen 1x, status open)
  - repro: `sed -n 483,490p src/leitir/exit_corpus.py`
- **medium** `1de5d199aa18caf8` [coverage/uncovered-raise] fail-closed path never executed by any test: raise BTSError(BTSRejectReason.REJECT_PROVENANCE_MISMATCH, 'manifest cannot be encoded as canonical JSON', — `src/leitir/exit_corpus.py:87` (seen 1x, status open)
  - repro: `sed -n 82,89p src/leitir/exit_corpus.py`
- **medium** `380aaf6e1aee20e1` [coverage/coverage-regression] src/leitir/graph/go.py coverage 7.19% is below the recorded baseline 87.87% — `src/leitir/graph/go.py` (seen 1x, status open)
  - repro: `python -m coverage report`
- **medium** `ac458687a40d0e29` [coverage/coverage-regression] src/leitir/graph/javascript.py coverage 7.49% is below the recorded baseline 91.49% — `src/leitir/graph/javascript.py` (seen 1x, status open)
  - repro: `python -m coverage report`
- **medium** `3972a90e043a5c85` [coverage/coverage-regression] src/leitir/graph/rust.py coverage 6.74% is below the recorded baseline 85.50% — `src/leitir/graph/rust.py` (seen 1x, status open)
  - repro: `python -m coverage report`
- **medium** `a27c21a239233844` [coverage/coverage-regression] src/leitir/graph/ts_kernel.py coverage 35.69% is below the recorded baseline 88.32% — `src/leitir/graph/ts_kernel.py` (seen 1x, status open)
  - repro: `python -m coverage report`

## Probe notes


Generated by `tools/calibrate.py`; see `docs/calibration.md` for how to read and act on this.
