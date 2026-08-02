"""Secret-redacting logging tests."""

from __future__ import annotations

import logging as stdlib_logging

import pytest

from leitir.logging import (
    REDACTED,
    RedactingFilter,
    install_redaction,
    redact,
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
