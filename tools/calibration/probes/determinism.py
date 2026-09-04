"""Environment determinism: the same inputs under different hash seeds, time zones, and locales."""

from __future__ import annotations

import json
import os
import subprocess
import sys

from ..fuzz import TARGETS
from ..ledger import Finding
from . import ProbeContext, ProbeResult

ENVIRONMENTS = (
    {"PYTHONHASHSEED": "0", "TZ": "UTC", "LC_ALL": "C.UTF-8", "LANG": "C.UTF-8"},
    {"PYTHONHASHSEED": "4242", "TZ": "Pacific/Kiritimati", "LC_ALL": "C.UTF-8", "LANG": "C.UTF-8"},
    {"PYTHONHASHSEED": "random", "TZ": "America/Los_Angeles", "LC_ALL": "C", "LANG": "C"},
)


def _worker(context: ProbeContext, args: list[str], variant: dict[str, str]) -> tuple[int, str]:
    env = {key: value for key, value in os.environ.items() if key not in {"PYTHONHASHSEED", "TZ", "LC_ALL", "LANG", "LANGUAGE"} and not key.startswith("LEITIR_ENABLE_")}
    env.update(variant)
    env["PYTHONPATH"] = str(context.repo_root / "src")
    completed = subprocess.run([sys.executable, str(context.repo_root / "tools" / "calibrate.py"), *args], cwd=context.repo_root, env=env, capture_output=True, check=False, timeout=1800)
    return completed.returncode, completed.stdout.decode("utf-8", errors="replace")


def probe(context: ProbeContext) -> ProbeResult:
    result = ProbeResult("determinism", "ok")
    seed = int(context.option("seed", 0))
    count = int(context.option("determinism_count", 120))
    wanted = context.option("fuzz_targets")
    compared = 0
    mismatches = 0
    for name in TARGETS:
        if wanted and name not in wanted:
            continue
        digest_lists: list[list[str]] = []
        for variant in ENVIRONMENTS:
            code, output = _worker(context, ["fuzz-worker", "--target", name, "--seed", str(seed), "--count", str(count)], variant)
            if code != 0 or not output.strip():
                result.notes.append(f"{name}: worker failed under {variant} (exit {code})")
                digest_lists = []
                break
            digest_lists.append(json.loads(output)["digests"])
        if not digest_lists:
            continue
        reference = digest_lists[0]
        compared += len(reference)
        for index in range(len(reference)):
            values = [lst[index] if index < len(lst) else None for lst in digest_lists]
            if len(set(values)) > 1:
                mismatches += 1
                result.findings.append(
                    Finding(
                        "determinism",
                        "env-nondeterminism",
                        "high",
                        f"{name} output depends on hash seed / TZ / locale",
                        f"{name}#{index}",
                        {"identity": f"{name}:{seed}:{index}", "digests": values, "environments": ENVIRONMENTS},
                        f"python tools/calibrate.py fuzz-repro --target {name} --seed {seed} --index {index}",
                    )
                )
    # CLI help text is user-visible output and must be byte-stable too.
    helps = []
    for variant in ENVIRONMENTS:
        env = dict(os.environ)
        env.update(variant)
        env["PYTHONPATH"] = str(context.repo_root / "src")
        completed = subprocess.run([sys.executable, "-c", "import sys; sys.argv = ['leitir', '--help']; from leitir.cli import _process_main; sys.exit(_process_main())"], cwd=context.repo_root, env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, check=False)
        helps.append(completed.stdout)
    if len(set(helps)) > 1:
        result.findings.append(Finding("determinism", "env-nondeterminism", "medium", "`leitir --help` output varies with environment", "cli:--help", {"identity": "cli-help"}, "PYTHONHASHSEED=4242 python -m leitir --help"))
    result.metrics = {"inputs_compared": compared, "mismatches": mismatches, "environments": len(ENVIRONMENTS)}
    return result
