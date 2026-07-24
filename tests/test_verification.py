"""Offline rubric tests for Step 5 verification and bounded repair."""

from __future__ import annotations

from collections import deque
from pathlib import Path

import pytest

from leitir import (
    ArtifactId,
    Config,
    EvidenceAccounting,
    EvidenceCitation,
    EvidenceTier,
    FailureClassification,
    InfrastructureStatus,
    PythonCandidate,
    PythonVerificationTask,
    SandboxExecution,
    SandboxPolicyError,
    Step5Controller,
    SynthesisMode,
    TerminalDisposition,
    TestOutcome as VerificationTestOutcome,
    TraceRecorder,
    VerificationRoute,
)
from leitir.synthesis import ChunkProvenance
from leitir.verification import (
    BASE_DOCKERFILE,
    BASE_IMAGE_TAG,
    PYTEST_ARGUMENTS,
    DockerSandbox,
    EvidenceState,
)


def candidate(number: int = 1, code: str = "answer = 1\n") -> PythonCandidate:
    chunk_id = ArtifactId("chunk")
    provenance = ChunkProvenance(
        chunk_id=chunk_id,
        evidence_id=ArtifactId("evidence"),
        tier=EvidenceTier.TIER_1,
        source_uri="https://docs.example.test/api",
        ordinal=1,
        repository=None,
        file_path=None,
        revision="v1",
    )
    return PythonCandidate(
        artifact_id=ArtifactId(f"candidate-{number}"),
        code=code,
        citation_ids=(chunk_id,),
        provenance=(EvidenceCitation(chunk_id, (provenance,)),),
        evidence_accounting=EvidenceAccounting(1, (chunk_id,), 1, (chunk_id,)),
        attempt_number=number,
        mode=SynthesisMode.INITIAL if number == 1 else SynthesisMode.REPAIR,
    )


def execution(
    *,
    passed: bool = False,
    category: str | None = "logic",
    timed_out: bool = False,
    infrastructure: InfrastructureStatus = InfrastructureStatus.VALID,
) -> SandboxExecution:
    return SandboxExecution(
        exit_code=0 if passed else (None if timed_out else 1),
        stdout="1 failed\n" if not passed else "1 passed\n",
        stderr="SyntaxError: invalid syntax\n" if category == "syntax" else "",
        test_outcome=(
            VerificationTestOutcome.PASSED
            if passed
            else VerificationTestOutcome.FAILED
        ),
        timed_out=timed_out,
        infrastructure_status=infrastructure,
        error_category=category,
        output_limit_exceeded=False,
        duration_ms=10,
    )


class FakeSandbox:
    def __init__(self, *results: SandboxExecution):
        self.results = deque(results)
        self.calls = []

    def execute(self, task, *, hidden_tests=None):
        self.calls.append((task, hidden_tests))
        return self.results.popleft()


class FakeSynthesizer:
    def __init__(self, *candidates: PythonCandidate):
        self.candidates = deque(candidates)
        self.calls = []

    def repair(self, request, evidence, context, *, attempt_number):
        self.calls.append((request, tuple(evidence), context, attempt_number))
        return self.candidates.popleft()


class FakeImages:
    def __init__(self):
        self.build_calls = []
        self.removed = []

    def get(self, tag):
        return object()

    def build(self, **kwargs):
        self.build_calls.append(kwargs)
        return object(), ()

    def remove(self, tag, force):
        self.removed.append((tag, force))


class FakeContainer:
    def __init__(
        self,
        *,
        wait_result=None,
        wait_error=None,
        stdout=b"1 passed\n",
        stderr=b"",
    ):
        self.wait_result = wait_result or {"StatusCode": 0}
        self.wait_error = wait_error
        self.stdout = stdout
        self.stderr = stderr
        self.started = False
        self.killed = False
        self.removed = False

    def start(self):
        self.started = True

    def wait(self, timeout):
        if self.wait_error:
            raise self.wait_error
        return self.wait_result

    def logs(self, *, stdout, stderr):
        return self.stdout if stdout else self.stderr

    def kill(self):
        self.killed = True

    def remove(self, *, force):
        self.removed = True


class FakeContainers:
    def __init__(self, container):
        self.container = container
        self.calls = []

    def create(self, image, **kwargs):
        self.calls.append((image, kwargs))
        return self.container


class FakeDocker:
    def __init__(self, container):
        self.images = FakeImages()
        self.containers = FakeContainers(container)


def task(**overrides) -> PythonVerificationTask:
    values = {
        "candidate": candidate(),
        "public_tests": {"test_candidate.py": "def test_ok(): assert True\n"},
        "dependencies": (),
    }
    values.update(overrides)
    return PythonVerificationTask(**values)


def test_base_and_runtime_policy_are_fixed_and_not_model_controlled(tmp_path):
    assert BASE_DOCKERFILE.startswith("FROM python:3.11-slim\n")
    assert "pytest==9.0.2" in BASE_DOCKERFILE
    assert PYTEST_ARGUMENTS == (
        "-q",
        "--tb=no",
        "--no-header",
        "-p",
        "no:cacheprovider",
        "-p",
        "leitir_pytest_plugin",
        "/workspace/tests",
    )

    container = FakeContainer()
    docker = FakeDocker(container)
    config = Config(
        sandbox_timeout_seconds=7,
        sandbox_memory_mb=128,
        sandbox_cpu_count=2,
        sandbox_process_limit=17,
        sandbox_max_output_bytes=4096,
        sandbox_tmpfs_mb=8,
    )
    result = DockerSandbox(config, docker_client=docker).execute(task())

    assert result.test_outcome is VerificationTestOutcome.PASSED
    image, policy = docker.containers.calls[0]
    assert image == BASE_IMAGE_TAG
    assert policy["command"] == PYTEST_ARGUMENTS
    assert policy["network_mode"] == "none"
    assert policy["network_disabled"] is True
    assert policy["privileged"] is False
    assert policy["read_only"] is True
    assert policy["cap_drop"] == ["ALL"]
    assert policy["security_opt"] == ["no-new-privileges:true"]
    assert policy["user"] == "65532:65532"
    assert policy["mem_limit"] == "128m"
    assert policy["memswap_limit"] == "128m"
    assert policy["nano_cpus"] == 2_000_000_000
    assert policy["pids_limit"] == 17
    assert policy["tmpfs"]["/tmp"].startswith("rw,noexec,nosuid,nodev,size=8m")
    assert policy["shm_size"] == "8m"
    assert policy["environment"] == {
        "HOME": "/tmp",
        "PYTHONDONTWRITEBYTECODE": "1",
        "PYTHONPATH": "/workspace",
    }
    assert len(policy["volumes"]) == 1
    assert all(source != "/var/run/docker.sock" for source in policy["volumes"])
    assert all(value["mode"] == "ro" for value in policy["volumes"].values())
    assert container.removed
    workspace = next(iter(policy["volumes"]))
    assert not Path(workspace).exists()


@pytest.mark.parametrize(
    "dependency",
    [
        "-r requirements.txt",
        "git+https://example.test/repo.git",
        "https://example.test/pkg.whl",
        "../local-package",
        "apt:curl",
        "pytest==8.0.0",
        "name; python_version>'3.11'",
    ],
)
def test_dependency_policy_rejects_options_urls_paths_system_and_pytest(dependency):
    with pytest.raises(SandboxPolicyError):
        PythonVerificationTask(
            candidate=candidate(),
            public_tests={"test_x.py": "def test_x(): pass\n"},
            dependencies=(dependency,),
        )


def test_only_declared_dependencies_enter_an_ephemeral_build_context():
    container = FakeContainer()
    docker = FakeDocker(container)
    sandbox = DockerSandbox(docker_client=docker)
    sandbox.execute(task(dependencies=("six==1.17.0",)))
    assert len(docker.images.build_calls) == 1
    call = docker.images.build_calls[0]
    assert call["custom_context"] is True
    assert call["network_mode"] == "default"
    assert call["quiet"] is True
    assert call["use_config_proxy"] is False
    assert call["timeout"] == Config().sandbox_timeout_seconds
    assert docker.images.removed and docker.images.removed[0][1] is True


def test_hidden_tests_are_only_a_read_only_verification_mount(tmp_path):
    hidden = tmp_path / "hidden"
    hidden.mkdir()
    (hidden / "test_secret.py").write_text("SECRET_SOURCE_SENTINEL = 42\n")
    docker = FakeDocker(FakeContainer())
    DockerSandbox(docker_client=docker).execute(task(), hidden_tests=hidden)
    _, policy = docker.containers.calls[0]
    assert policy["command"] == (*PYTEST_ARGUMENTS, "/hidden-tests")
    assert policy["volumes"][str(hidden.resolve())] == {
        "bind": "/hidden-tests",
        "mode": "ro",
    }


def test_timeout_is_distinct_and_container_is_killed_and_removed():
    container = FakeContainer(wait_error=TimeoutError())
    docker = FakeDocker(container)
    result = DockerSandbox(
        Config(sandbox_timeout_seconds=1), docker_client=docker
    ).execute(task())
    assert result.timed_out
    assert result.infrastructure_status is InfrastructureStatus.VALID
    assert result.error_category == "timeout"
    assert container.killed and container.removed


def test_interrupt_still_removes_container_and_workspace():
    container = FakeContainer(wait_error=KeyboardInterrupt())
    docker = FakeDocker(container)
    with pytest.raises(KeyboardInterrupt):
        DockerSandbox(docker_client=docker).execute(task())
    assert container.removed
    _, policy = docker.containers.calls[0]
    assert not Path(next(iter(policy["volumes"]))).exists()


def test_output_is_bounded_and_invalid_pytest_exit_is_infrastructure():
    output_container = FakeContainer(stdout=b"x" * 100, stderr=b"y" * 100)
    output = DockerSandbox(
        Config(sandbox_max_output_bytes=32), docker_client=FakeDocker(output_container)
    ).execute(task())
    assert output.infrastructure_status is InfrastructureStatus.INVALID
    assert output.output_limit_exceeded
    assert len((output.stdout + output.stderr).encode()) <= 32

    exit_container = FakeContainer(wait_result={"StatusCode": 3})
    invalid = DockerSandbox(docker_client=FakeDocker(exit_container)).execute(task())
    assert invalid.infrastructure_status is InfrastructureStatus.INVALID
    assert invalid.error_category == "pytest_exit_3"


def test_pass_accepts_without_model_call_and_records_span():
    sandbox = FakeSandbox(execution(passed=True, category=None))
    synth = FakeSynthesizer()
    recorder = TraceRecorder("trace-step5-pass", "verification")
    result = Step5Controller(
        sandbox, synth, trace_recorder=recorder
    ).verify(task(), request=object(), evidence=())
    assert result.disposition is TerminalDisposition.ACCEPTED
    assert result.route is VerificationRoute.ACCEPT
    assert len(result.attempts) == 1
    assert synth.calls == []
    assert recorder._spans[-1].sandbox.test_passed is True
    assert recorder._spans[-1].sandbox.repair_used is False


def test_syntax_failure_maps_code_and_routes_repair_with_bounded_safe_context():
    hidden = Path("/tmp/hidden-do-not-read")
    sandbox = FakeSandbox(
        execution(category="syntax"),
        execution(passed=True, category=None),
    )
    synth = FakeSynthesizer(candidate(2, "answer = 2\n"))
    recorder = TraceRecorder("trace-step5-syntax", "verification")
    config = Config(repair_max_diagnostics_characters=30)
    result = Step5Controller(
        sandbox, synth, config=config, trace_recorder=recorder
    ).verify(task(), request=object(), evidence=(), hidden_tests=hidden)
    assert result.disposition is TerminalDisposition.ACCEPTED
    assert result.attempts[0].classification is FailureClassification.SYNTAX
    assert recorder._spans[0].error_code.value == "ERR_SYNTAX_COMPILATION_FAIL"
    assert recorder._spans[0].sandbox.repair_used is True
    context = synth.calls[0][2]
    assert len(context.diagnostics) <= 30
    assert "hidden-do-not-read" not in context.diagnostics
    assert synth.calls[0][3] == 2
    assert len(recorder._diffs) == 1


def test_hidden_output_and_source_sentinel_never_enter_repair_context():
    leaked = execution()
    leaked = SandboxExecution(
        exit_code=leaked.exit_code,
        stdout="SECRET_HIDDEN_SOURCE_SENTINEL",
        stderr="assert hidden_implementation_detail",
        test_outcome=leaked.test_outcome,
        timed_out=False,
        infrastructure_status=leaked.infrastructure_status,
        error_category=leaked.error_category,
        output_limit_exceeded=False,
        duration_ms=1,
    )
    synth = FakeSynthesizer(candidate(2, "answer = 2\n"))
    controller = Step5Controller(
        FakeSandbox(leaked, execution(passed=True, category=None)),
        synth,
    )
    controller.verify(
        task(),
        request=object(),
        evidence=(),
        hidden_tests=Path("/tmp/harness-hidden-tests"),
    )
    prompt_diagnostics = synth.calls[0][2].diagnostics
    assert "SECRET_HIDDEN_SOURCE_SENTINEL" not in prompt_diagnostics
    assert "hidden_implementation_detail" not in prompt_diagnostics
    assert "hidden evaluation output omitted" in prompt_diagnostics


def test_missing_or_stale_evidence_routes_step1_without_repair():
    for state, expected in (
        (EvidenceState.MISSING, FailureClassification.MISSING_EVIDENCE),
        (EvidenceState.STALE, FailureClassification.STALE_EVIDENCE),
    ):
        sandbox = FakeSandbox(execution())
        synth = FakeSynthesizer()
        result = Step5Controller(sandbox, synth).verify(
            task(), request=object(), evidence=(), evidence_state=state
        )
        assert result.route is VerificationRoute.STEP_1_REFRESH
        assert result.attempts[0].classification is expected
        assert synth.calls == []


def test_timeout_and_infrastructure_are_terminal_and_distinct():
    timed_out = Step5Controller(
        FakeSandbox(execution(timed_out=True, category="timeout")),
        FakeSynthesizer(),
    ).verify(task(), request=object(), evidence=())
    assert timed_out.disposition is TerminalDisposition.FAILED
    assert timed_out.attempts[0].classification is FailureClassification.TIMEOUT
    assert timed_out.attempts[0].error_code.value == "ERR_VERIFICATION_TIMEOUT"

    invalid = Step5Controller(
        FakeSandbox(
            execution(
                category="docker_error",
                infrastructure=InfrastructureStatus.INVALID,
            )
        ),
        FakeSynthesizer(),
    ).verify(task(), request=object(), evidence=())
    assert invalid.disposition is TerminalDisposition.INFRASTRUCTURE_ERROR
    assert (
        invalid.attempts[0].classification
        is FailureClassification.INFRASTRUCTURE
    )
    assert invalid.attempts[0].valid_execution is False


def test_exactly_three_repairs_is_the_hard_cap_and_a_fourth_is_impossible():
    sandbox = FakeSandbox(*(execution() for _ in range(4)))
    synth = FakeSynthesizer(
        candidate(2, "answer = 2\n"),
        candidate(3, "answer = 3\n"),
        candidate(4, "answer = 4\n"),
        candidate(5, "answer = 5\n"),
    )
    recorder = TraceRecorder("trace-step5-cap", "verification")
    result = Step5Controller(
        sandbox, synth, trace_recorder=recorder
    ).verify(task(), request=object(), evidence=())
    assert result.disposition is TerminalDisposition.REPAIR_EXHAUSTED
    assert len(sandbox.calls) == 4
    assert len(synth.calls) == 3
    assert [call[3] for call in synth.calls] == [2, 3, 4]
    assert len(synth.candidates) == 1  # a fourth repair was never reachable
    assert len(recorder._diffs) == 3
    assert recorder._spans[-1].sandbox.repair_used is False
