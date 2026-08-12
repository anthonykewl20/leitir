"""Real, iterative retry tests against a live local HTTP server (ADR-003).

These are NOT mocks. ``GitHubCodeSearchTransport`` talks to a real
``http.server.ThreadingHTTPServer`` over real sockets; ``urllib`` raises
genuine ``HTTPError`` objects carrying genuine response headers. Each scenario
is parametrized over many iterations to prove determinism and catch any state
leakage between retries — simulating sustained real usage.
"""

from __future__ import annotations

import base64
import hashlib

import _http_server as hs
import pytest

from leitir.adapters import PythonAdapter
from leitir.discovery_search import (
    CodeSearchError,
    GitHubCodeSearchTransport,
    GlobalSearcher,
)
from leitir.search import (
    CoverageStatus,
    Predicate,
    PredicateKind,
    SearchMode,
    SearchSpec,
)
from leitir.tree import GitHubTreeSource, TreeReadError

SHA = "a" * 40
BLOB_CONTENT = b'def urlencode(query, doseq=False):\n    return query\n'
BLOB = hashlib.sha1(
    b"blob " + str(len(BLOB_CONTENT)).encode("ascii") + b"\x00" + BLOB_CONTENT
).hexdigest()

SEARCH_OK = {
    "total_count": 1,
    "incomplete_results": False,
    "items": [
        {
            "repository": {"full_name": "python/cpython"},
            "path": "Lib/urllib/parse.py",
            "sha": BLOB,
            "url": f"https://api.github.com/repositories/1/contents/Lib/urllib/parse.py?ref={SHA}",
            "html_url": f"https://github.com/python/cpython/blob/{SHA}/Lib/urllib/parse.py",
        }
    ],
}
COMMITS_OK = [{"sha": SHA}]

ITERATIONS = 12


def _transport(base_url, *, sleeper=None, max_delay=60.0):
    return GitHubCodeSearchTransport(
        base_url=base_url,
        raw_base_url=base_url,
        sleeper=sleeper,
        base_delay=1.0,
        max_delay=max_delay,
    )


class TestTransportRetryReal:
    """Drive GitHubCodeSearchTransport against a real local HTTP server."""

    @pytest.mark.parametrize("iteration", range(ITERATIONS))
    def test_502_then_200_retries_and_succeeds(self, iteration):
        sleeps = []
        with hs.scripted_server([
            (502, {}, b""),
            (502, {}, b""),
            (200, {"Content-Type": "application/json"}, hs.json_body(SEARCH_OK)),
        ]) as h:
            t = _transport(h.base_url, sleeper=sleeps.append)
            page = t.search("urlencode")
        assert page.total_count == 1
        assert len(page.hits) == 1
        assert page.hits[0].slug == "python/cpython"
        # two transient failures -> two exponential backoff sleeps
        assert sleeps == [1.0, 2.0]
        assert h.state.served_count == 3

    @pytest.mark.parametrize("iteration", range(ITERATIONS))
    def test_429_honors_real_retry_after_header(self, iteration):
        sleeps = []
        with hs.scripted_server([
            (429, {"Retry-After": "7"}, b""),
            (200, {"Content-Type": "application/json"}, hs.json_body(SEARCH_OK)),
        ]) as h:
            t = _transport(h.base_url, sleeper=sleeps.append)
            page = t.search("urlencode")
        assert page.total_count == 1
        assert sleeps == [7.0]
        assert h.state.served_count == 2

    @pytest.mark.parametrize("iteration", range(ITERATIONS))
    def test_403_rate_limited_honors_reset_header(self, iteration):
        import time
        now = time.time()
        sleeps = []
        with hs.scripted_server([
            (403, {
                "X-RateLimit-Remaining": "0",
                "X-RateLimit-Reset": str(int(now) + 5),
            }, b""),
            (200, {"Content-Type": "application/json"}, hs.json_body(SEARCH_OK)),
        ]) as h:
            t = _transport(h.base_url, sleeper=sleeps.append, max_delay=60.0)
            page = t.search("urlencode")
        assert page.total_count == 1
        assert 0.0 < sleeps[0] <= 5.0 + 1.0
        assert h.state.served_count == 2

    @pytest.mark.parametrize("iteration", range(ITERATIONS))
    def test_404_is_fatal_no_retry(self, iteration):
        sleeps = []
        with hs.scripted_server([(404, {}, b"")]) as h:
            t = _transport(h.base_url, sleeper=sleeps.append)
            with pytest.raises(CodeSearchError, match="HTTP 404"):
                t.search("urlencode")
        assert sleeps == []
        assert h.state.served_count == 1

    @pytest.mark.parametrize("iteration", range(ITERATIONS))
    def test_401_is_fatal_no_retry(self, iteration):
        sleeps = []
        with hs.scripted_server([(401, {}, b"")]) as h:
            t = _transport(h.base_url, sleeper=sleeps.append)
            with pytest.raises(CodeSearchError, match="HTTP 401"):
                t.search("urlencode")
        assert sleeps == []
        assert h.state.served_count == 1

    @pytest.mark.parametrize("iteration", range(ITERATIONS))
    def test_500_retried_then_succeeds(self, iteration):
        sleeps = []
        with hs.scripted_server([
            (500, {}, b""),
            (200, {"Content-Type": "application/json"}, hs.json_body(SEARCH_OK)),
        ]) as h:
            t = _transport(h.base_url, sleeper=sleeps.append)
            page = t.search("urlencode")
        assert page.total_count == 1
        assert sleeps == [1.0]

    @pytest.mark.parametrize("iteration", range(ITERATIONS))
    def test_exhaustion_raises_code_search_error(self, iteration):
        sleeps = []
        with hs.scripted_server([
            (503, {}, b""), (503, {}, b""), (503, {}, b""), (503, {}, b""),
        ]) as h:
            t = _transport(h.base_url, sleeper=sleeps.append)
            with pytest.raises(CodeSearchError, match="HTTP 503"):
                t.search("urlencode")
        assert sleeps == [1.0, 2.0, 4.0]
        assert h.state.served_count == 4

    def test_connection_refused_urlerror_retried(self):
        # Port 1 is privileged and refuses connections on Linux -> real URLError.
        sleeps = []
        t = GitHubCodeSearchTransport(
            base_url="http://127.0.0.1:1",
            raw_base_url="http://127.0.0.1:1",
            sleeper=sleeps.append,
            max_attempts=2,
            base_delay=0.1,
        )
        with pytest.raises(CodeSearchError):
            t.search("urlencode")
        assert len(sleeps) == 1

    @pytest.mark.parametrize("iteration", range(ITERATIONS))
    def test_resolve_head_sha_retries_502(self, iteration):
        sleeps = []
        with hs.scripted_server([
            (502, {}, b""),
            (200, {"Content-Type": "application/json"}, hs.json_body(COMMITS_OK)),
        ]) as h:
            t = _transport(h.base_url, sleeper=sleeps.append)
            assert t.resolve_head_sha("python/cpython") == SHA
        assert sleeps == [1.0]

    @pytest.mark.parametrize("iteration", range(ITERATIONS))
    def test_read_blob_retries_502(self, iteration):
        sleeps = []
        with hs.scripted_server([
            (502, {}, b""),
            (200, {"Content-Type": "text/plain"}, BLOB_CONTENT),
        ]) as h:
            t = _transport(h.base_url, sleeper=sleeps.append)
            data = t.read_blob_by_path("python/cpython", SHA, "Lib/urllib/parse.py")
        assert data == BLOB_CONTENT
        assert sleeps == [1.0]


class TestGlobalSearcherUserLevel:
    """Full user-level path: transport -> GlobalSearcher -> SearchReport.

    Mirrors how ``cli.py`` wires production: a single transport serves code
    search, HEAD resolution, and blob reads. Proves a real user flow survives
    transient failures mid-search.
    """

    @pytest.mark.parametrize("iteration", range(ITERATIONS))
    def test_search_survives_transient_502_end_to_end(self, iteration):
        sleeps = []
        # Sequence served across all transport calls:
        # 1. code search -> 502 (transient)
        # 2. code search -> 200 with one hit
        # 3. read blob at the indexed commit -> 200 with python source
        with hs.scripted_server([
            (502, {}, b""),
            (200, {"Content-Type": "application/json"}, hs.json_body(SEARCH_OK)),
            (200, {"Content-Type": "text/plain"}, BLOB_CONTENT),
        ]) as h:
            transport = _transport(h.base_url, sleeper=sleeps.append)
            searcher = GlobalSearcher(
                code_search=transport,
                tree_source=_NullTree(),
                adapters=(PythonAdapter(),),
                blob_reader=transport.read_blob_by_path,
            )
            spec = SearchSpec(
                mode=SearchMode.GLOBAL_DISCOVERY,
                must=(Predicate(PredicateKind.IDENTIFIER, "urlencode", "python"),),
            )
            report = searcher.search(spec)

        assert report.coverage.status is CoverageStatus.INDETERMINATE_GLOBAL
        assert len(report.matches) >= 1
        match = report.matches[0]
        assert match.source.slug == "python/cpython"
        assert match.source.commit_sha == SHA
        assert match.source.blob_sha == BLOB
        assert match.source.path == "Lib/urllib/parse.py"
        # the single 502 produced exactly one backoff sleep
        assert sleeps == [1.0]
        assert h.state.served_count == 3

    @pytest.mark.parametrize("iteration", range(6))
    def test_repeated_user_sessions_are_deterministic(self, iteration):
        """Loop a full session; every iteration must yield identical provenance."""
        with hs.scripted_server([
            (200, {"Content-Type": "application/json"}, hs.json_body(SEARCH_OK)),
            (200, {"Content-Type": "text/plain"}, BLOB_CONTENT),
        ]) as h:
            transport = _transport(h.base_url, sleeper=lambda _: None)
            searcher = GlobalSearcher(
                code_search=transport,
                tree_source=_NullTree(),
                adapters=(PythonAdapter(),),
                blob_reader=transport.read_blob_by_path,
            )
            spec = SearchSpec(
                mode=SearchMode.GLOBAL_DISCOVERY,
                must=(Predicate(PredicateKind.IDENTIFIER, "urlencode", "python"),),
            )
            report = searcher.search(spec)

        assert len(report.matches) == 1
        m = report.matches[0]
        assert (m.source.slug, m.source.commit_sha, m.source.path) == (
            "python/cpython", SHA, "Lib/urllib/parse.py",
        )


class _NullTree:
    """TreeSource stub that is never reached (blob_reader is injected)."""

    def list_blobs(self, slug, commit_sha):
        return ()

    def read_blob(self, slug, blob_sha) -> bytes:
        return b""


class TestReviewDrivenDefects:
    """Regression tests for defects found in the independent code review.

    Each maps 1:1 to a verified finding: H1 (TimeoutError escape), M3 (shared
    Request redirect-state mutation), and __cause__ chaining (ADR-003 §5).
    """

    def test_socket_timeout_is_wrapped_not_leaked(self):
        """H1: a read timeout raises a bare TimeoutError from urllib; the call
        site must catch OSError and wrap it into CodeSearchError. Both attempts
        time out so the retry exhausts and the wrapping is exercised."""
        sleeps = []
        with hs.scripted_server([
            (200, {"Content-Type": "application/json"}, hs.json_body(SEARCH_OK), 2.0),
            (200, {"Content-Type": "application/json"}, hs.json_body(SEARCH_OK), 2.0),
        ]) as h:
            t = GitHubCodeSearchTransport(
                base_url=h.base_url, raw_base_url=h.base_url,
                sleeper=sleeps.append, timeout=0.5, max_attempts=2, base_delay=0.1,
            )
            with pytest.raises(CodeSearchError) as exc_info:
                t.search("urlencode")
        assert isinstance(exc_info.value.__cause__, OSError)
        assert sleeps == [0.1]

    def test_socket_timeout_is_retried_then_recovers(self):
        """A transient timeout on attempt 1 is retried (not fatal); attempt 2
        succeeds, proving timeouts are classified TRANSIENT."""
        sleeps = []
        with hs.scripted_server([
            (200, {"Content-Type": "application/json"}, hs.json_body(SEARCH_OK), 2.0),
            (200, {"Content-Type": "application/json"}, hs.json_body(SEARCH_OK)),
        ]) as h:
            t = GitHubCodeSearchTransport(
                base_url=h.base_url, raw_base_url=h.base_url,
                sleeper=sleeps.append, timeout=0.5, max_attempts=3, base_delay=0.1,
            )
            page = t.search("urlencode")
        assert page.total_count == 1
        assert sleeps == [0.1]

    @pytest.mark.parametrize("iteration", range(4))
    def test_redirect_chain_survives_retry(self, iteration):
        """M3: urllib mutates the Request's redirect_dict when following a
        redirect. Reusing one Request across retry attempts accumulates state
        and eventually synthesises a spurious 301. Constructing the Request
        inside the retried closure keeps each attempt fresh, so the real 503
        (not a synthetic 301) surfaces after exhaustion."""
        routes = {
            "/search/code": (
                301, {"Location": "/target"}, b"",
            ),
            "/target": (
                503, {}, b"",
            ),
        }
        sleeps = []
        with hs.routed_server(routes) as h:
            t = GitHubCodeSearchTransport(
                base_url=h.base_url, raw_base_url=h.base_url,
                sleeper=sleeps.append, max_attempts=6, base_delay=0.1,
            )
            with pytest.raises(CodeSearchError) as exc_info:
                t.search("x")
        # The real failure was 503; a spurious 301 (from accumulated
        # redirect_dict when reusing one Request across >=5 attempts) would be
        # a regression. max_attempts=6 is past urllib's max_repeats=4 threshold.
        assert "503" in str(exc_info.value)
        assert "301" not in str(exc_info.value)
        assert len(sleeps) >= 1

    def test_domain_error_preserves_cause_chain(self):
        """ADR-003 §5: the domain error must chain the original OSError via
        ``raise ... from exc`` so the real failure is inspectable."""
        with hs.scripted_server([(404, {}, b"")]) as h:
            t = GitHubCodeSearchTransport(base_url=h.base_url, raw_base_url=h.base_url)
            with pytest.raises(CodeSearchError) as exc_info:
                t.resolve_head_sha("o/r")
        cause = exc_info.value.__cause__
        assert cause is not None
        assert getattr(cause, "code", None) == 404

    def test_truncated_body_incomplete_read_is_wrapped(self):
        """M2: a server that hangs up mid-body raises http.client.IncompleteRead
        (an HTTPException, NOT an OSError). It must be retried as transient and,
        on exhaustion, wrapped into CodeSearchError rather than leaking raw."""
        import http.server
        import socketserver

        class _LyingHandler(http.server.BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def do_GET(self):  # noqa: N802
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", "1000")  # lies: sends 5 bytes
                self.end_headers()
                self.wfile.write(b'{"x"')  # truncated mid-body

            def log_message(self, *a):
                pass

        sleeps = []
        httpd = socketserver.ThreadingTCPServer(("127.0.0.1", 0), _LyingHandler)
        httpd.daemon_threads = True
        import threading
        thread = threading.Thread(target=httpd.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True)
        thread.start()
        try:
            base_url = f"http://127.0.0.1:{httpd.server_address[1]}"
            t = GitHubCodeSearchTransport(
                base_url=base_url, raw_base_url=base_url,
                sleeper=sleeps.append, max_attempts=2, base_delay=0.1,
            )
            with pytest.raises(CodeSearchError) as exc_info:
                t.search("x")
        finally:
            httpd.shutdown()
            httpd.server_close()
            thread.join(timeout=5)
        # Retried as transient, then wrapped — never leaked as a raw IncompleteRead.
        from http.client import HTTPException
        assert isinstance(exc_info.value.__cause__, (OSError, HTTPException))
        assert sleeps == [0.1]


class TestTreeSourceRetryReal:
    """H3: GitHubTreeSource (scoped-exhaustive path) is the heaviest GitHub API
    consumer, so its three HTTP sites must retry transitively."""

    TREE_PAYLOAD = {
        "sha": SHA,
        "truncated": False,
        "tree": [
            {"type": "blob", "path": "Lib/x.py", "sha": BLOB, "size": 10},
        ],
    }
    BLOB_API_PAYLOAD = {
        "content": base64.b64encode(BLOB_CONTENT).decode("ascii"),
        "encoding": "base64",
        "sha": BLOB,
        "size": len(BLOB_CONTENT),
    }

    @pytest.mark.parametrize("iteration", range(6))
    def test_list_blobs_retries_502(self, iteration):
        sleeps = []
        with hs.scripted_server([
            (502, {}, b""),
            (200, {"Content-Type": "application/json"}, hs.json_body(self.TREE_PAYLOAD)),
        ]) as h:
            tree = GitHubTreeSource(base_url=h.base_url, sleeper=sleeps.append, base_delay=1.0)
            blobs = tree.list_blobs("o/r", SHA)
        assert len(blobs) == 1
        assert blobs[0].path == "Lib/x.py"
        assert sleeps == [1.0]

    @pytest.mark.parametrize("iteration", range(6))
    def test_read_blob_retries_502(self, iteration):
        sleeps = []
        with hs.scripted_server([
            (502, {}, b""),
            (200, {"Content-Type": "application/json"}, hs.json_body(self.BLOB_API_PAYLOAD)),
        ]) as h:
            tree = GitHubTreeSource(base_url=h.base_url, sleeper=sleeps.append, base_delay=1.0)
            data = tree.read_blob("o/r", BLOB)
        assert data == BLOB_CONTENT
        assert sleeps == [1.0]

    @pytest.mark.parametrize("iteration", range(6))
    def test_read_blob_by_path_retries_502(self, iteration):
        sleeps = []
        with hs.scripted_server([
            (502, {}, b""),
            (200, {"Content-Type": "text/plain"}, b"raw content"),
        ]) as h:
            tree = GitHubTreeSource(
                base_url=h.base_url, raw_base_url=h.base_url,
                sleeper=sleeps.append, base_delay=1.0,
            )
            data = tree.read_blob_by_path("o/r", SHA, "Lib/x.py")
        assert data == b"raw content"
        assert sleeps == [1.0]

    @pytest.mark.parametrize("iteration", range(6))
    def test_tree_404_wrapped_into_tree_read_error(self, iteration):
        with hs.scripted_server([(404, {}, b"")]) as h:
            tree = GitHubTreeSource(base_url=h.base_url)
            with pytest.raises(TreeReadError, match="404"):
                tree.list_blobs("o/r", SHA)
