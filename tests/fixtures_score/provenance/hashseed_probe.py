"""Emit one S2 assessment produced from hash-seed-sensitive input iteration."""

from __future__ import annotations

import hashlib
import json

from tools.score_engine import (
    POLICY_SCHEMA_VERSION,
    CheckMode,
    CheckPolicy,
    CheckResult,
    CheckStatus,
    CommandExecution,
    Criterion,
    DimensionPolicy,
    EvidenceArtifact,
    Policy,
    Producer,
    Profile,
    SourceSpan,
    Subject,
    evaluate,
)


dimensions = (
    "engine_correctness",
    "output_effectiveness",
    "code_health",
    "test_adequacy",
    "process_supply_chain",
    "performance_operability",
)
check_dimensions = {
    "engine.seed": "engine_correctness",
    "output.seed": "output_effectiveness",
    "code.seed": "code_health",
    "test.seed": "test_adequacy",
    "process.seed": "process_supply_chain",
    "performance.seed": "performance_operability",
}
checks_by_id = {
    check_id: CheckPolicy(
        id=check_id,
        dimension=dimension,
        weight=1,
        score_eligible=True,
        criterion=Criterion(op="eq", value=10000),
        offline_mode=CheckMode.REQUIRED,
        release_mode=CheckMode.REQUIRED,
    )
    for check_id, dimension in check_dimensions.items()
}
results_by_id = {
    check_id: CheckResult(
        id=check_id,
        status=CheckStatus.PASS,
        score_bps=10000,
        reason_code="CHECK_PASSED",
        exclusions=tuple({("IGNORED_B", 2), ("IGNORED_A", 1)}),
        evidence=tuple(
            dict(items)
            for items in {
                (("kind", "source"), ("value", "z.py")),
                (("value", "fixture.a"), ("kind", "artifact")),
            }
        ),
    )
    for check_id in check_dimensions
}
payloads = {
    "fixture.z": b"z evidence\n",
    "fixture.a": b"a evidence\n",
}
artifacts_by_id = {
    artifact_id: EvidenceArtifact(
        id=artifact_id,
        path=f"evidence/{artifact_id}.txt",
        sha256=hashlib.sha256(content).hexdigest(),
        content=content,
        command=CommandExecution(
            argv=("python", "-m", "fixture_collector", artifact_id),
            process_exit=0,
            collector_reason_code="COLLECTOR_COMPLETE",
        ),
        sources=tuple(
            {
                SourceSpan("src/z.py", "a" * 40, 5, 7),
                SourceSpan("src/a.py", "b" * 40, 1, 2),
            }
        ),
    )
    for artifact_id, content in payloads.items()
}
policy = Policy(
    schema_version=POLICY_SCHEMA_VERSION,
    id="hashseed-policy-v1",
    dimensions=tuple(DimensionPolicy(id=item, weight=1) for item in dimensions),
    checks=tuple(checks_by_id[item] for item in set(checks_by_id)),
)
assessment = evaluate(
    policy,
    tuple(results_by_id[item] for item in set(results_by_id)),
    profile=Profile.OFFLINE,
    subject=Subject(
        repository="https://example.invalid/leitir",
        commit_sha="1" * 40,
        worktree="clean",
    ),
    producer=Producer(
        name="leitir-score-engine",
        version="2",
        commit_sha="2" * 40,
    ),
    evidence=tuple(artifacts_by_id[item] for item in set(artifacts_by_id)),
)
print(
    json.dumps(
        {
            "bytes_hex": assessment.to_bytes().hex(),
            "sha256": assessment.digest(),
        },
        sort_keys=True,
    )
)
