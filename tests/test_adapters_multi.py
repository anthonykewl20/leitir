"""Unit tests for Rust and Go language adapters (ADR-001 P4)."""

from __future__ import annotations

import pytest

from leitir.adapters import GoAdapter, PythonAdapter, RustAdapter
from leitir.discovery_search import _line_count
from leitir.search import Predicate, PredicateKind

RUST_SAMPLE = """\
use std::collections::HashMap;
use serde::{Serialize, Deserialize};

#[derive(Serialize, Deserialize)]
pub struct Config {
    pub name: String,
    pub retries: u32,
}

impl Config {
    pub fn new(name: &str) -> Self {
        Config {
            name: name.to_string(),
            retries: 3,
        }
    }
}

pub async fn load_config(path: &str) -> Result<Config, io::Error> {
    let data = std::fs::read_to_string(path)?;
    let config: Config = serde_json::from_str(&data)?;
    Ok(config)
}

fn main() {
    let cfg = Config::new("test");
    println!("{}", cfg.name);
}
"""

GO_SAMPLE = """\
package main

import (
	"fmt"
	"net/http"
)

type Server struct {
	Addr string
	Handler http.Handler
}

func NewServer(addr string) *Server {
	return &Server{Addr: addr}
}

func (s *Server) ListenAndServe() error {
	return http.ListenAndServe(s.Addr, s.Handler)
}

func main() {
	srv := NewServer(":8080")
	fmt.Println(srv.Addr)
}
"""


class TestRustAdapter:
    def setup_method(self):
        self.adapter = RustAdapter()

    def test_language(self):
        assert self.adapter.language == "rust"

    def test_eligible(self):
        assert self.adapter.eligible("src/main.rs")
        assert self.adapter.eligible("lib.rs")
        assert not self.adapter.eligible("main.go")
        assert not self.adapter.eligible("main.py")

    def test_identifier(self):
        preds = (Predicate(PredicateKind.IDENTIFIER, "Config"),)
        matches = self.adapter.find_matches(RUST_SAMPLE, preds)
        lines = {m.start_line for m in matches}
        assert 5 in lines
        assert 10 in lines

    def test_symbol_definition_fn(self):
        preds = (Predicate(PredicateKind.SYMBOL_DEFINITION, "load_config"),)
        matches = self.adapter.find_matches(RUST_SAMPLE, preds)
        assert len(matches) == 1
        assert matches[0].start_line == 19

    def test_symbol_definition_struct(self):
        preds = (Predicate(PredicateKind.SYMBOL_DEFINITION, "Config"),)
        matches = self.adapter.find_matches(RUST_SAMPLE, preds)
        lines = {m.start_line for m in matches}
        assert 5 in lines
        assert 10 in lines

    def test_symbol_reference(self):
        preds = (Predicate(PredicateKind.SYMBOL_REFERENCE, "Config"),)
        matches = self.adapter.find_matches(RUST_SAMPLE, preds)
        lines = {m.start_line for m in matches}
        assert 12 in lines
        assert 5 not in lines

    def test_import(self):
        preds = (Predicate(PredicateKind.IMPORT, "serde"),)
        matches = self.adapter.find_matches(RUST_SAMPLE, preds)
        assert len(matches) == 1
        assert matches[0].start_line == 2

    def test_call(self):
        preds = (Predicate(PredicateKind.CALL, "from_str"),)
        matches = self.adapter.find_matches(RUST_SAMPLE, preds)
        assert any(m.start_line == 21 for m in matches)

    def test_exact_text(self):
        preds = (Predicate(PredicateKind.EXACT_TEXT, "retries: 3"),)
        matches = self.adapter.find_matches(RUST_SAMPLE, preds)
        assert len(matches) == 1
        assert matches[0].start_line == 14

    def test_regex(self):
        preds = (Predicate(PredicateKind.REGEX, r"pub\s+async\s+fn"),)
        matches = self.adapter.find_matches(RUST_SAMPLE, preds)
        assert len(matches) == 1
        assert matches[0].start_line == 19

    def test_signature(self):
        preds = (Predicate(PredicateKind.SIGNATURE, r"load_config.*Result"),)
        matches = self.adapter.find_matches(RUST_SAMPLE, preds)
        assert len(matches) == 1
        assert matches[0].start_line == 19

    def test_no_match(self):
        preds = (Predicate(PredicateKind.IDENTIFIER, "nonexistent"),)
        matches = self.adapter.find_matches(RUST_SAMPLE, preds)
        assert len(matches) == 0


class TestGoAdapter:
    def setup_method(self):
        self.adapter = GoAdapter()

    def test_language(self):
        assert self.adapter.language == "go"

    def test_eligible(self):
        assert self.adapter.eligible("main.go")
        assert self.adapter.eligible("pkg/server/handler.go")
        assert not self.adapter.eligible("main.rs")
        assert not self.adapter.eligible("main.py")

    def test_identifier(self):
        preds = (Predicate(PredicateKind.IDENTIFIER, "Server"),)
        matches = self.adapter.find_matches(GO_SAMPLE, preds)
        lines = {m.start_line for m in matches}
        assert 8 in lines
        assert 13 in lines

    def test_symbol_definition_func(self):
        preds = (Predicate(PredicateKind.SYMBOL_DEFINITION, "NewServer"),)
        matches = self.adapter.find_matches(GO_SAMPLE, preds)
        assert len(matches) == 1
        assert matches[0].start_line == 13

    def test_symbol_definition_type(self):
        preds = (Predicate(PredicateKind.SYMBOL_DEFINITION, "Server"),)
        matches = self.adapter.find_matches(GO_SAMPLE, preds)
        assert len(matches) == 1
        assert matches[0].start_line == 8

    def test_symbol_reference(self):
        preds = (Predicate(PredicateKind.SYMBOL_REFERENCE, "Server"),)
        matches = self.adapter.find_matches(GO_SAMPLE, preds)
        lines = {m.start_line for m in matches}
        assert 13 in lines or 14 in lines
        assert 8 not in lines

    def test_import(self):
        preds = (Predicate(PredicateKind.IMPORT, "net/http"),)
        matches = self.adapter.find_matches(GO_SAMPLE, preds)
        assert len(matches) == 1
        assert matches[0].start_line == 5

    def test_call(self):
        preds = (Predicate(PredicateKind.CALL, "NewServer"),)
        matches = self.adapter.find_matches(GO_SAMPLE, preds)
        assert any(m.start_line == 22 for m in matches)

    def test_exact_text(self):
        preds = (Predicate(PredicateKind.EXACT_TEXT, ":8080"),)
        matches = self.adapter.find_matches(GO_SAMPLE, preds)
        assert len(matches) == 1
        assert matches[0].start_line == 22

    def test_regex(self):
        preds = (Predicate(PredicateKind.REGEX, r"func\s+\(s\s+\*Server\)"),)
        matches = self.adapter.find_matches(GO_SAMPLE, preds)
        assert len(matches) == 1
        assert matches[0].start_line == 17

    def test_signature(self):
        preds = (Predicate(PredicateKind.SIGNATURE, r"ListenAndServe.*error"),)
        matches = self.adapter.find_matches(GO_SAMPLE, preds)
        assert len(matches) == 1
        assert matches[0].start_line == 17

    def test_no_match(self):
        preds = (Predicate(PredicateKind.IDENTIFIER, "nonexistent"),)
        matches = self.adapter.find_matches(GO_SAMPLE, preds)
        assert len(matches) == 0


class TestMultiAdapterEngine:
    def test_engine_dispatches_to_correct_adapter(self):
        import hashlib

        from leitir.engine import ScopedSearcher
        from leitir.search import (
            RepoScope,
            SearchMode,
            SearchSpec,
        )
        from leitir.tree import BlobEntry

        rust_code = "pub fn main() {}\n"
        go_code = "func main() {}\n"
        rust_sha = hashlib.sha1(
            b"blob %d\x00" % len(rust_code) + rust_code.encode()
        ).hexdigest()
        go_sha = hashlib.sha1(
            b"blob %d\x00" % len(go_code) + go_code.encode()
        ).hexdigest()

        class FakeTree:
            def list_blobs(self, slug, commit_sha):
                return (
                    BlobEntry("src/main.rs", rust_sha, len(rust_code)),
                    BlobEntry("cmd/main.go", go_sha, len(go_code)),
                )

            def list_blobs_ex(self, slug, commit_sha):
                return self.list_blobs(slug, commit_sha), False

            def read_blob(self, slug, blob_sha):
                if blob_sha == rust_sha:
                    return rust_code.encode()
                return go_code.encode()

        searcher = ScopedSearcher(
            tree_source=FakeTree(),
            adapters=(RustAdapter(), GoAdapter()),
        )
        spec = SearchSpec(
            mode=SearchMode.SCOPED_EXHAUSTIVE,
            must=(Predicate(PredicateKind.IDENTIFIER, "main"),),
            scopes=(RepoScope("test/repo", "a" * 40),),
        )
        report = searcher.search(spec)
        paths = {m.source.path for m in report.matches}
        assert "src/main.rs" in paths
        assert "cmd/main.go" in paths
        assert report.coverage.files_eligible == 2


def test_adapter_never_emits_phantom_line_and_preserves_real_lines():
    cases = [
        (PythonAdapter(), "def foo():\n    pass\n", 2),
        (RustAdapter(), "pub fn foo() {}\nimpl Foo for Bar {}\n", 2),
        (GoAdapter(), "func foo() {}\nfunc bar() {}\n", 2),
    ]
    for adapter, content, real_lines in cases:
        star = adapter.find_matches(
            content, (Predicate(PredicateKind.REGEX, r".*"),)
        )
        assert {s.end_line for s in star} == set(range(1, real_lines + 1))
        empty_anchor = adapter.find_matches(
            content, (Predicate(PredicateKind.REGEX, r"^$"),)
        )
        assert all(s.end_line <= real_lines for s in empty_anchor)

    for adapter in (PythonAdapter(), RustAdapter(), GoAdapter()):
        assert adapter.find_matches(
            "", (Predicate(PredicateKind.REGEX, r".*"),)
        ) == ()
        assert adapter.find_matches(
            "", (Predicate(PredicateKind.REGEX, r"^$"),)
        ) == ()

    for adapter, content, real_lines in [
        (PythonAdapter(), "def foo():\n    pass", 2),
        (RustAdapter(), "pub fn foo() {}\nimpl Foo for Bar {}", 2),
        (GoAdapter(), "func foo() {}\nfunc bar() {}", 2),
    ]:
        star = adapter.find_matches(
            content, (Predicate(PredicateKind.REGEX, r".*"),)
        )
        assert {s.end_line for s in star} == set(range(1, real_lines + 1))

    for adapter in (PythonAdapter(), RustAdapter(), GoAdapter()):
        spans = adapter.find_matches(
            "a\n\n\n", (Predicate(PredicateKind.REGEX, r"^$"),)
        )
        assert {s.end_line for s in spans} == {2, 3}


def test_adapter_max_end_line_matches_validator_line_count():
    for adapter in (PythonAdapter(), RustAdapter(), GoAdapter()):
        for content in ("a\n", "a\nb\n", "a\nb", "x\n\n\n", "only"):
            spans = adapter.find_matches(
                content, (Predicate(PredicateKind.REGEX, r".*"),)
            )
            if spans:
                assert max(s.end_line for s in spans) == _line_count(content)
            else:
                assert _line_count(content) == 0


@pytest.mark.parametrize(
    ("adapter", "definition", "call"),
    (
        (PythonAdapter(), "def build():", "run()"),
        (RustAdapter(), "fn build() {}", "run();"),
        (GoAdapter(), "func build() {}", "run()"),
    ),
)
def test_adapter_whole_file_matches_required_evidence_on_different_lines(
    adapter, definition, call
):
    content = "\n".join((definition, *("" for _ in range(48)), call))
    predicates = (
        Predicate(PredicateKind.SYMBOL_DEFINITION, "build"),
        Predicate(PredicateKind.CALL, "run"),
    )

    assert adapter.find_matches(content, predicates) == ()
    matches = adapter.find_matches(content, predicates, whole_file=True)
    assert tuple(
        (match.start_line, match.end_line, match.matched_kinds) for match in matches
    ) == (
        (1, 1, (PredicateKind.SYMBOL_DEFINITION,)),
        (50, 50, (PredicateKind.CALL,)),
    )


@pytest.mark.parametrize("adapter", (PythonAdapter(), RustAdapter(), GoAdapter()))
def test_adapter_whole_file_rejects_missing_required_and_is_keyword_only(adapter):
    predicates = (
        Predicate(PredicateKind.IDENTIFIER, "present"),
        Predicate(PredicateKind.IDENTIFIER, "missing"),
    )
    assert adapter.find_matches("present\n", predicates, whole_file=True) == ()
    with pytest.raises(TypeError):
        adapter.find_matches("present\n", predicates, True)


@pytest.mark.parametrize(
    ("adapter", "content"),
    (
        (PythonAdapter(), "def build(): run()\nrun()\n"),
        (RustAdapter(), "fn build() { run(); }\nrun();\n"),
        (GoAdapter(), "func build() { run() }\nrun()\n"),
    ),
)
def test_adapter_whole_file_deduplicates_evidence_in_stable_order(adapter, content):
    matches = adapter.find_matches(
        content,
        (
            Predicate(PredicateKind.SYMBOL_DEFINITION, "build"),
            Predicate(PredicateKind.CALL, "run"),
            Predicate(PredicateKind.CALL, "run"),
        ),
        whole_file=True,
    )
    assert tuple((match.start_line, match.matched_kinds) for match in matches) == (
        (1, (PredicateKind.CALL, PredicateKind.SYMBOL_DEFINITION)),
        (2, (PredicateKind.CALL,)),
    )


@pytest.mark.parametrize("adapter", (PythonAdapter(), RustAdapter(), GoAdapter()))
def test_adapter_regex_predicate_over_length_cap_is_incomplete_not_hung(adapter):
    """ReDoS regression (BUG2): a regex predicate whose shape evades the compile-time check
    must not hang when matched against a long, repetitive line -- the adapter must instead
    report the file's evidence as incomplete via ``parser_unavailable``.
    """
    long_line = "a" * 5000
    content = f"first line\n{long_line}\nlast line\n"
    predicate = Predicate(PredicateKind.REGEX, r"^(a|a)*b")
    result = adapter.find_matches_ex(content, (predicate,))
    assert result.spans == ()
    assert result.parser_unavailable is True


@pytest.mark.parametrize("adapter", (PythonAdapter(), RustAdapter(), GoAdapter()))
def test_adapter_regex_predicate_under_cap_is_unaffected(adapter):
    content = "needle here\nno match on this line\n"
    predicate = Predicate(PredicateKind.REGEX, r"needle")
    result = adapter.find_matches_ex(content, (predicate,))
    assert result.parser_unavailable is False
    assert [span.start_line for span in result.spans] == [1]
