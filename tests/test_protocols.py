"""External-effect boundaries support dependency substitution."""

from __future__ import annotations

from leitir.contracts import Artifact, StepResult, WorkflowRequest
from leitir.protocols import (
    CredentialProvider,
    ExtractionProvider,
    ModelTransport,
    SandboxExecutor,
    SearchProvider,
    TraceSink,
)


class FakeDependencies:
    def send(self, request: WorkflowRequest):
        return {"request_id": request.request_id}

    def search(self, query: str):
        return ()

    def extract(self, artifact: Artifact):
        return artifact

    def get_openrouter_key(self):
        return "synthetic"

    def execute(self, source: str) -> StepResult:
        raise AssertionError("not called by a contract test")

    def emit(self, result: StepResult):
        return None


def test_structural_test_double_substitutes_for_each_dependency():
    fake = FakeDependencies()
    assert isinstance(fake, ModelTransport)
    assert isinstance(fake, SearchProvider)
    assert isinstance(fake, ExtractionProvider)
    assert isinstance(fake, CredentialProvider)
    assert isinstance(fake, SandboxExecutor)
    assert isinstance(fake, TraceSink)

