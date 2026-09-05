# macOS worker scheduling evidence — 2026-09-05

The full hosted suite reproduced a long final worker queue. With the default
`load` scheduler, all 13 differential tests ran on `gw2`. Five individual tests
took approximately 118 seconds and the determinism test took 94 seconds. Other
workers had completed their work around 91–92%, while this queue continued to
drain. The complete suite passed in 768.21 seconds.

On the same source and test trees, `worksteal` distributed those 13 tests across
`gw0`, `gw1`, and `gw2`. Individual long tests still took approximately 120
seconds; the complete suite passed in 445.24 seconds, 42% less elapsed time.
Both runs collected the same tests and reported 3682 passed / 218 skipped.
The comparison changes scheduling, not assertions or skip gates.

- [Default scheduler run 33957602315](https://github.com/anthonykewl20/leitir/actions/runs/33957602315)
- [Work stealing run 33958241644](https://github.com/anthonykewl20/leitir/actions/runs/33958241644)
- [Exact heads, source/test tree identities, log hashes and worker assignments](comparison.json)
- [Default worker completion timestamps](baseline-workers.txt)
- [Work stealing completion timestamps](worksteal-workers.txt)
- [Actual faulthandler worker stack](worker-stack.txt)

The captured long-running worker is in `subprocess.communicate`, reached through
`benchmarks/differential/check_bridge.py:86` and the real differential harness.
It subsequently completes. This evidence identifies scheduling imbalance and
bounded subprocess waits, not a lock deadlock. The earlier cancelled runs did
not capture stacks, so their exact internal state cannot be reconstructed.

The correction selects `--dist worksteal` for macOS only. The normal 15-minute
job timeout, worker count, test collection and assertions remain intact.
The diagnostic branch additionally enabled verbose output, durations and
faulthandler; those diagnostic workflow changes are not included in this fix.

[pytest-xdist's distribution documentation](https://pytest-xdist.readthedocs.io/en/stable/distribution.html)
describes how work stealing reassigns queued tests from busy workers and suits
uneven test durations. Here its benefit is verified by actual full hosted runs.
