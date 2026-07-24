"""Docker-capable-host integration tests for the Step 5 sandbox."""

from __future__ import annotations

import uuid

from leitir import (
    ArtifactId,
    Config,
    EvidenceAccounting,
    EvidenceCitation,
    EvidenceTier,
    InfrastructureStatus,
    PythonCandidate,
    PythonVerificationTask,
    SynthesisMode,
    TestOutcome as VerificationTestOutcome,
)
from leitir.synthesis import ChunkProvenance
from leitir.verification import DockerSandbox


def candidate(code: str) -> PythonCandidate:
    chunk = ArtifactId("docker-chunk")
    source = ChunkProvenance(
        chunk,
        ArtifactId("docker-evidence"),
        EvidenceTier.TIER_1,
        "https://docs.example.test",
        1,
        None,
        None,
        "v1",
    )
    return PythonCandidate(
        ArtifactId(f"docker-candidate-{uuid.uuid4().hex}"),
        code,
        (chunk,),
        (EvidenceCitation(chunk, (source,)),),
        EvidenceAccounting(1, (chunk,), 1, (chunk,)),
        1,
        SynthesisMode.INITIAL,
    )


def test_docker_executes_pytest_with_isolation_and_hidden_tests(tmp_path):
    hidden = tmp_path / "hidden"
    hidden.mkdir()
    (hidden / "test_hidden.py").write_text(
        "import candidate\n"
        "def test_hidden_answer(): assert candidate.answer == 42\n",
        encoding="utf-8",
    )
    source = (
        "import os, pathlib, socket\n"
        "answer = 42\n"
        "def isolation():\n"
        "    network_blocked = False\n"
        "    try:\n"
        "        socket.create_connection(('1.1.1.1', 53), timeout=.2)\n"
        "    except OSError:\n"
        "        network_blocked = True\n"
        "    return {\n"
        "      'uid': os.getuid(),\n"
        "      'network_blocked': network_blocked,\n"
        "      'docker_socket': pathlib.Path('/var/run/docker.sock').exists(),\n"
        "      'openrouter_env': any('OPENROUTER' in k for k in os.environ),\n"
        "    }\n"
    )
    public = (
        "import candidate\n"
        "def test_isolation():\n"
        "    facts = candidate.isolation()\n"
        "    assert facts == {'uid': 65532, 'network_blocked': True, "
        "'docker_socket': False, 'openrouter_env': False}\n"
    )
    result = DockerSandbox(Config(sandbox_timeout_seconds=30)).execute(
        PythonVerificationTask(
            candidate(source),
            {"test_isolation.py": public},
            (),
        ),
        hidden_tests=hidden,
    )
    assert result.infrastructure_status is InfrastructureStatus.VALID
    assert result.test_outcome is VerificationTestOutcome.PASSED, (
        result.stdout,
        result.stderr,
    )


def test_docker_installs_declared_dependency_only_and_cleans_task_image():
    result = DockerSandbox(Config(sandbox_timeout_seconds=30)).execute(
        PythonVerificationTask(
            candidate("import six\nanswer = six.ensure_str(b'ok')\n"),
            {
                "test_dependency.py": (
                    "import candidate\n"
                    "def test_dependency(): assert candidate.answer == 'ok'\n"
                )
            },
            ("six==1.17.0",),
        )
    )
    assert result.infrastructure_status is InfrastructureStatus.VALID
    assert result.test_outcome is VerificationTestOutcome.PASSED, (
        result.stdout,
        result.stderr,
    )


def test_docker_parse_failure_is_a_valid_syntax_failure():
    result = DockerSandbox(Config(sandbox_timeout_seconds=30)).execute(
        PythonVerificationTask(
            candidate('compile("x =", "<generated>", "exec")\n'),
            {},
            (),
        )
    )
    assert result.infrastructure_status is InfrastructureStatus.VALID
    assert result.test_outcome is VerificationTestOutcome.FAILED
    assert result.error_category == "syntax"
    assert result.exit_code == 2


def test_docker_timeout_is_killed_and_ephemeral_container_is_removed():
    label = uuid.uuid4().hex
    sandbox = DockerSandbox(
        Config(sandbox_timeout_seconds=1),
        run_label=label,
    )
    result = sandbox.execute(
        PythonVerificationTask(
            candidate("import time\ndef hang(): time.sleep(60)\n"),
            {
                "test_timeout.py": (
                    "import candidate\n"
                    "def test_timeout(): candidate.hang()\n"
                )
            },
            (),
        )
    )
    assert result.timed_out
    assert result.infrastructure_status is InfrastructureStatus.VALID

    import docker

    client = docker.from_env()
    try:
        leftovers = client.containers.list(
            all=True, filters={"label": f"org.leitir.run={label}"}
        )
        assert leftovers == []
    finally:
        client.close()
