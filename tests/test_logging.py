"""Secret-redacting logging tests."""

from __future__ import annotations

import logging as stdlib_logging

import pytest

from leitir.logging import (
    REDACTED,
    RedactingFilter,
    configure_logging,
    install_redaction,
    redact,
    register_secret,
    safe_record_message,
)

SENTINEL = "super-secret-value-do-not-leak-9f3c"


def test_nested_logging_data_redaction_removes_sensitive_fragments():
    openrouter_key = "sk-or-v1-syntheticOpenRouterKey123"
    hidden_fragment = "SYNTHETIC_HIDDEN_TEST_FRAGMENT_7e91"
    redacted = redact(
        {
            "candidate": {"code": f"# {openrouter_key}\nanswer = 1\n"},
            "diagnostics": f"secret={hidden_fragment}",
            "prior_diff": f"- token={hidden_fragment}\n+ api_key={openrouter_key}",
        }
    )

    rendered = str(redacted)
    assert openrouter_key not in rendered
    assert hidden_fragment not in rendered


class TestRedactionShapes:
    @pytest.mark.parametrize(
        "key",
        [
            "api_key",
            "apiKey",
            "apikey",
            "api-key",
            "token",
            "access_token",
            "secret",
            "client_secret",
            "password",
            "credential",
            "authorization",
            "Authorization",
            "key",
        ],
    )
    def test_sensitive_keys_redacted(self, key):
        out = redact({key: SENTINEL})
        assert out[key] == REDACTED
        assert SENTINEL not in str(out)

    @pytest.mark.parametrize("key", ["model", "endpoint", "tier", "query", "latency_ms"])
    def test_nonsensitive_keys_preserved(self, key):
        out = redact({key: SENTINEL})
        assert out[key] == SENTINEL

    def test_nested_mapping_and_sequence_redaction(self):
        data = {
            "outer": [
                {"api_key": SENTINEL, "model": "tencent/hy3"},
                {"ok": {"token": SENTINEL}},
            ],
            "password": SENTINEL,
        }
        out = redact(data)
        assert out["password"] == REDACTED
        assert out["outer"][0]["api_key"] == REDACTED
        assert out["outer"][0]["model"] == "tencent/hy3"
        assert out["outer"][1]["ok"]["token"] == REDACTED
        assert SENTINEL not in str(out)

    def test_does_not_mutate_caller_data(self):
        data = {"api_key": SENTINEL, "nested": [{"secret": SENTINEL}]}
        original = {"api_key": SENTINEL, "nested": [{"secret": SENTINEL}]}
        redact(data)
        assert data == original
        assert data["api_key"] == SENTINEL
        assert data["nested"][0]["secret"] == SENTINEL

    def test_bearer_header_redacted(self):
        out = redact("Authorization: Bearer abc123xyz")
        assert "abc123xyz" not in out
        assert REDACTED in out
        assert "Bearer" in out
        assert "Authorization" in out

    def test_url_userinfo_redacted(self):
        assert redact("https://user:pass@host.example/path") == (
            "https://[REDACTED]@host.example/path"
        )

    def test_url_without_userinfo_unchanged(self):
        url = "https://host.example/path"
        assert redact(url) == url

    def test_url_fragment_is_removed(self):
        out = redact(f"request failed for https://host.example/path#{SENTINEL}")
        assert SENTINEL not in out
        assert out == "request failed for https://host.example/path"

    def test_private_token_header_is_redacted(self):
        out = redact({"headers": {"PRIVATE-TOKEN": SENTINEL}})
        assert out["headers"]["PRIVATE-TOKEN"] == REDACTED
        assert SENTINEL not in str(out)

    def test_bearer_redaction_in_nested_structures(self):
        data = {"headers": {"Authorization": "Bearer abc123xyz"}}
        out = redact(data)
        # "Authorization" key is sensitive -> whole value becomes REDACTED.
        assert out["headers"]["Authorization"] == REDACTED

    def test_bytes_bearer_redacted(self):
        out = redact(b"Authorization: Bearer abc123xyz")
        assert b"abc123xyz" not in out
        assert REDACTED.encode() in out

    def test_keyvalue_text_redacted(self):
        out = redact("detail api_key=abc123xyz model=tencent/hy3")
        assert "abc123xyz" not in out
        assert REDACTED in out
        assert "tencent/hy3" in out

    def test_scalars_unchanged(self):
        assert redact(42) == 42
        assert redact(None) is None
        assert redact("plain text") == "plain text"


class TestLogFilterIntegration:
    def _make_record(self, msg, *args):
        return stdlib_logging.LogRecord(
            name="leitir.test",
            level=stdlib_logging.INFO,
            pathname=__file__,
            lineno=1,
            msg=msg,
            args=args or None,
            exc_info=None,
        )

    def test_formatted_message_redacts_args(self):
        logger = stdlib_logging.getLogger("leitir.test.redact.args")
        records: list[str] = []

        class Capture(stdlib_logging.Handler):
            def emit(self, record):
                records.append(self.format(record))

        handler = Capture()
        logger.handlers = [handler]
        logger.filters = []
        logger.setLevel(stdlib_logging.INFO)
        install_redaction(logger)
        logger.info("model=%s key=%s", "tencent/hy3", SENTINEL)
        assert records
        assert SENTINEL not in records[0]
        assert "tencent/hy3" in records[0]
        assert REDACTED in records[0]

    def test_filter_redacts_template_bearer(self):
        record = self._make_record("Authorization: Bearer %s", "leak123")
        f = RedactingFilter()
        assert f.filter(record) is True
        rendered = record.getMessage()
        assert "leak123" not in rendered
        assert REDACTED in rendered

    def test_filter_redacts_registered_secret_from_exception_text(self):
        exception_secret = "exception-only-secret-42d9"
        register_secret(exception_secret)
        try:
            raise RuntimeError(f"transport failed: {exception_secret}")
        except RuntimeError:
            record = self._make_record("registry request failed")
            record.exc_info = __import__("sys").exc_info()

        RedactingFilter().filter(record)
        rendered = record.getMessage()
        assert exception_secret not in rendered
        assert REDACTED in rendered

    def test_resolved_credential_is_automatically_redacted_from_exception(self):
        from leitir.credentials import Credentials

        exception_secret = "resolved-exception-secret-72c1"
        assert Credentials({"NPM_TOKEN": exception_secret}).auth_for_url(
            "https://registry.npmjs.org/demo"
        ) is not None
        try:
            raise RuntimeError(f"transport failed: {exception_secret}")
        except RuntimeError:
            record = self._make_record("registry request failed")
            record.exc_info = __import__("sys").exc_info()

        RedactingFilter().filter(record)
        rendered = record.getMessage()
        assert exception_secret not in rendered
        assert REDACTED in rendered

    def test_safe_record_message_does_not_mutate(self):
        record = self._make_record("key=%s", SENTINEL)
        original_args = record.args
        rendered = safe_record_message(record)
        assert SENTINEL not in rendered
        assert REDACTED in rendered
        # Caller's record args are untouched.
        assert record.args == original_args

    def test_dict_args_redacted(self):
        record = stdlib_logging.LogRecord(
            name="leitir.test",
            level=stdlib_logging.INFO,
            pathname=__file__,
            lineno=1,
            msg="config=%(api_key)s ok=%(model)s",
            args={"api_key": SENTINEL, "model": "tencent/hy3"},
            exc_info=None,
        )
        f = RedactingFilter()
        f.filter(record)
        rendered = record.getMessage()
        assert SENTINEL not in rendered
        assert "tencent/hy3" in rendered

    def test_configure_logging_deduplicates_equivalent_stderr_handlers(self):
        logger = stdlib_logging.getLogger("leitir")
        original_handlers = logger.handlers[:]
        logger.handlers = []
        try:
            formatter = stdlib_logging.Formatter("leitir %(levelname)s: %(message)s")
            first = stdlib_logging.StreamHandler()
            first.setLevel(stdlib_logging.DEBUG)
            first.setFormatter(formatter)
            second = stdlib_logging.StreamHandler()
            second.setLevel(stdlib_logging.DEBUG)
            second.setFormatter(formatter)
            configure_logging(stdlib_logging.DEBUG, handler=first)
            configure_logging(stdlib_logging.DEBUG, handler=second)
            assert logger.handlers == [first]
        finally:
            logger.handlers = original_handlers
