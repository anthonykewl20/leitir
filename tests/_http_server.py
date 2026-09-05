"""Real local HTTP server harness for retry/integration tests.

Spins up an actual ``http.server.ThreadingHTTPServer`` on an ephemeral port.
Tests talk to it through real sockets with real ``urllib`` — so the kernel's
transport/resolver code raises genuine ``HTTPError`` objects carrying genuine
response headers (``Retry-After``, ``X-RateLimit-Reset``, ...). This is not a
mock: the full HTTP round-trip and urllib parsing path is exercised.

A scripted server serves a list of ``(status, headers, body)`` responses in
order, repeating the last one if the client makes more requests than scripted.
Per-request introspection is available via ``state.request_paths`` and
``state.served_count``.
"""

from __future__ import annotations

import json as _json
import sys
import threading
from collections.abc import Iterator
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import NamedTuple

# Server-thread hygiene counters (issue #205 C-3): every started server
# thread must be confirmed dead before its context manager returns, and the
# started/joined pair lets tests assert no server thread lingers.
_SERVER_THREAD_STATS = {"started": 0, "joined": 0}
_JOIN_TIMEOUT_SECONDS = 5.0


def server_thread_stats() -> dict[str, int]:
    """Snapshot of started vs confirmed-dead server threads."""

    return dict(_SERVER_THREAD_STATS)


def _record_started_thread(thread: threading.Thread) -> None:
    _SERVER_THREAD_STATS["started"] += 1


def _join_server_thread(thread: threading.Thread, port: int) -> None:
    """Join the server thread and fail loudly if it lingers (issue #205 SP-3)."""

    thread.join(timeout=_JOIN_TIMEOUT_SECONDS)
    if thread.is_alive():
        raise AssertionError(
            f"test HTTP server thread {thread.name} on port {port} did not "
            f"terminate within {_JOIN_TIMEOUT_SECONDS}s — lingering server"
        )
    _SERVER_THREAD_STATS["joined"] += 1

# A scripted response: HTTP status code, header dict, bytes body, optional
# pre-response delay in seconds (to force client read timeouts).
Response = tuple[int, dict[str, str], bytes] | tuple[int, dict[str, str], bytes, float]


def json_body(payload) -> bytes:
    return _json.dumps(payload).encode()


class ServerState:
    """Mutable state shared with the handler via the server instance."""

    def __init__(self, responses: list[Response]) -> None:
        self.responses = responses
        self.index = 0
        self.request_paths: list[str] = []
        self.lock = threading.Lock()

    @property
    def served_count(self) -> int:
        return len(self.request_paths)


class _DisconnectTolerantServer(ThreadingHTTPServer):
    def handle_error(self, request: object, client_address: object) -> None:
        # Timeout and truncated-response probes deliberately close sockets.
        # Unexpected handler failures retain the standard traceback.
        if isinstance(sys.exc_info()[1], (BrokenPipeError, ConnectionResetError)):
            return
        super().handle_error(request, client_address)


class _ScriptedHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self) -> None:  # noqa: N802 (BaseHTTPRequestHandler API)
        state: ServerState = self.server.state  # type: ignore[attr-defined]
        with state.lock:
            idx = min(state.index, len(state.responses) - 1)
            state.index += 1
            state.request_paths.append(self.path)
            entry = state.responses[idx]

        status = entry[0]
        headers = entry[1]
        body = entry[2]
        delay = entry[3] if len(entry) > 3 else 0.0
        if delay:
            import time as _time
            _time.sleep(delay)

        self.send_response(status)
        for key, value in headers.items():
            self.send_header(key, value)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if body:
            self.wfile.write(body)

    def log_message(self, *args) -> None:  # silence stderr noise
        pass


class ServerHandle(NamedTuple):
    base_url: str
    state: ServerState


@contextmanager
def scripted_server(responses: list[Response]) -> Iterator[ServerHandle]:
    """Start a real local HTTP server serving ``responses`` in order.

    Yields a :class:`ServerHandle` whose ``base_url`` points at the live
    server (e.g. ``http://127.0.0.1:54321``). The server is shut down on
    exit and its thread must join within the timeout, or the test fails
    loudly (issue #205 C-3) — a discarded join result is prohibited.
    """
    state = ServerState(responses)
    httpd = _DisconnectTolerantServer(("127.0.0.1", 0), _ScriptedHandler)
    httpd.daemon_threads = True
    httpd.state = state  # type: ignore[attr-defined]
    port = httpd.server_address[1]
    thread = threading.Thread(
        target=httpd.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True
    )
    _record_started_thread(thread)
    thread.start()
    try:
        yield ServerHandle(base_url=f"http://127.0.0.1:{port}", state=state)
    finally:
        httpd.shutdown()
        httpd.server_close()
        _join_server_thread(thread, port)


class _RoutedHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self) -> None:  # noqa: N802
        routes: dict = self.server.routes  # type: ignore[attr-defined]
        state: ServerState = self.server.state  # type: ignore[attr-defined]
        path = self.path.split("?", 1)[0]
        entry = routes.get(path) or routes.get("*")
        with state.lock:
            state.request_paths.append(path)
        if entry is None:
            self.send_response(404)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        status, headers, body = entry[:3]
        self.send_response(status)
        for key, value in headers.items():
            self.send_header(key, value)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if body:
            self.wfile.write(body)

    def log_message(self, *args) -> None:
        pass


@contextmanager
def routed_server(routes: dict[str, Response]) -> Iterator[ServerHandle]:
    """Start a real local HTTP server that routes by path.

    ``routes`` maps a request path (or ``"*"`` as fallback) to a
    ``(status, headers, body)`` response. Useful for redirect chains where
    urllib's auto-follow consumes multiple server requests per attempt.
    """
    state = ServerState([])
    httpd = _DisconnectTolerantServer(("127.0.0.1", 0), _RoutedHandler)
    httpd.daemon_threads = True
    httpd.state = state  # type: ignore[attr-defined]
    httpd.routes = routes  # type: ignore[attr-defined]
    port = httpd.server_address[1]
    thread = threading.Thread(
        target=httpd.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True
    )
    _record_started_thread(thread)
    thread.start()
    try:
        yield ServerHandle(base_url=f"http://127.0.0.1:{port}", state=state)
    finally:
        httpd.shutdown()
        httpd.server_close()
        _join_server_thread(thread, port)
