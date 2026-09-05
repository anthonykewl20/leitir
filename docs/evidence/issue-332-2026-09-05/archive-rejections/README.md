# Independent review of real CI distribution rejection paths

Input: unchanged wheel/sdist downloaded from real CI run33962193988, from source `cc134194e6528c34dd364d8a1dae15939093ed16`. Original artifact identities are in `identities.json`; originals at `../ci-33962193988-dist` were preserved. Every negative input is a copy of those actual archives with the recorded mutation. No mock archive/provider or unit fixture substitutes for the released package source.

## Findings before correction

1. A one-byte mutation in the wheel's compressed `leitir/__init__.py` payload caused an independently confirmed `BadZipFile: Bad CRC-32` when reading that member, but production release verification returned0. Actual cached Twine also passed, while actual isolated pip installation failed on that CRC (exit2). Evidence: `additional-results.json`, `corrupt-runtime-validation.json`, case directory `wheel_corrupt_payload`.
2. Truncating the actual gzip archive raised an uncaught EOFError. A syntactically valid sdist pyproject with `project` set to a list or string raised uncaught AttributeError. Reserved deflate block bits in actual wheel METADATA raised uncaught zlib.error. These failed closed by exit status but violated the clean rejection diagnostic. Evidence: `results.json` cases `corrupt_sdist`, `sdist_project_list`, `sdist_project_string`, and `zlib-result.json`.
3. A ZIP METADATA member marked as a symlink was accepted. This is recorded as a structural limit, not a demonstrated exploit: the prior ADR explicitly prohibited artifact symlinks but did not specify ZIP member types. Root deliberately tightened the regular metadata invariant for consistency. Case `wheel_symlink_metadata`.
4. Gzip trailer-only CRC corruption and omission of the trailer were both accepted by the exact old production tool, even though the gzip stream was invalid. The correction consumes the full stream and rejects both. `trailer-before-results.json` ran an exact Git-extracted copy of the original verifier (hash checked against the original tool); `trailer-results.json` ran the corrected production verifier against the same mutated bytes.

5. Root found that appending a valid duplicate `leitir/__init__.py` shadows the corrupt first entry during name-based `ZipFile.testzip()` reads. Independent inspection of the unchanged real duplicate archive confirmed the first ZipInfo raises bad CRC, the second reads successfully, and name-based testzip returns no error. The final duplicate-path guard rejects it. See `duplicate-payload-before.json`, `duplicate-independent-validation.json`, and `final-results.json`.

## Corrected production results

Final independent rerun: **38 unchanged actual archive cases: 36 clean rejections, 2 valid acceptances, zero tracebacks**. This includes all35 original cases, both gzip trailer cases, and root’s duplicate-payload case. Artifact hashes were checked before each run; no negative input was regenerated or substituted. See `final-results.json`, `final-identities.json`, `duplicate-independent-validation.json`, and `rerun_final.py`. Earlier before/after records remain unchanged for audit. Final verifier SHA-256: `4818d3d7ec4b8450cc0f7357e2e322800644607656ec8614fa792f37b74c7059`.

The two valid acceptances are the unchanged actual distributions and an initial compressed-bit perturbation whose payload independently still decoded with a valid CRC. That first perturbation (`wheel_bad_crc`, a provisional case name) was explicitly excluded from corruption findings; `wheel_corrupt_payload` is the separate mutation with a proven bad CRC. Likewise, initial `sdist_missing_project_table` removed the actual member due to its case dispatch; the independently added `sdist_project_table_absent` preserves a TOML file without a project table and correctly rejects. These distinctions remain visible in the preserved mutation code and results.

Covered: duplicate/missing wheel METADATA and sdist PKG-INFO/pyproject members; wrong/multiple Name/Version headers; oversized metadata; artifact symlink; wheel metadata symlink; sdist metadata symlink/hardlink; wrong, missing, malformed and non-UTF8 project metadata; list/string project shape; truncated ZIP/gzip; bad member CRC; invalid deflate encoding; gzip trailer CRC and truncation. Rejection uses production `tools/verify_release.py --tag v0.2.000 --dist CASE --project pyproject.toml`.

Corrected source was root's uncommitted verifier fix atop the recorded head. `final-identities.json` records the exact final tool SHA-256. This bounded independent review reports no remaining finding in these paths; it is not a claim of exhaustive proof for all possible archive mutations. No project file, PR, GitHub issue, tag or release was edited by this reviewer.

The committed archive retains the exact original CI distributions, the actual
mutated archives demonstrating the CRC, trailer, project-shape, decompression
and duplicate-payload findings, and original scripts/results. Other matrix
mutations remain reproducible from the scripts; all original case directories
and their recorded hashes are retained in the session evidence directory.
