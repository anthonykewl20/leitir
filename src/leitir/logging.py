"""Central logging policy that redacts secret-shaped values before emission."""

from __future__ import annotations

import logging
import re
import threading
import traceback
from collections.abc import Mapping
from typing import Any

REDACTED = "[REDACTED]"

_SENSITIVE_KEY = re.compile(
    r"^(?:authorization|proxy[-_]?authorization|password|passwd|secret|"
    r"client[-_]?secret|credential(?:s)?|token|access[-_]?token|refresh[-_]?token|"
    r"api[-_]?key|apikey|private[-_]?token|x[-_]?api[-_]?key|key)$",
    re.IGNORECASE,
)
_AUTH_HEADER = re.compile(
    r"(?i)(\b(?:proxy-)?authorization\s*:\s*(?:bearer|basic)\s+)"
    r"(?!\[REDACTED\])[^\s,;\]}]+"
)
_BEARER = re.compile(
    r"(?i)(\bbearer\s+)(?!\[REDACTED\])[A-Za-z0-9._~+/=-]+"
)
_KEY_VALUE = re.compile(
    r"""(?ix)
    (["']?(?:api[-_]?key|apikey|access[-_]?token|refresh[-_]?token|token|
       client[-_]?secret|password|passwd|secret|credential(?:s)?|private[-_]?token|
       x[-_]?api[-_]?key|
       key)["']?\s*(?:=|:)\s*)
    (?:
       ["'][^"']*["'] |
       [^\s,;\]}]+
    )
    """
)
_AUTH_VALUE = re.compile(
    r"""(?ix)
    (["']?(?:authorization|proxy[-_]?authorization)["']?\s*(?:=|:)\s*)
    (?!bearer\b|basic\b)
    (?:"[^"]*"|'[^']*'|[^\s,;\]}]+)
    """
)
_OPENROUTER_KEY = re.compile(r"\bsk-or-v1-[A-Za-z0-9._~+/=-]+\b", re.IGNORECASE)
_URL_FRAGMENT = re.compile(r"(?i)(\bhttps?://[^\s#]+)#[^\s]*")
_KNOWN_SECRETS: set[str] = set()
_KNOWN_SECRETS_LOCK = threading.Lock()


def register_secret(value: str) -> None:
    """Register a loaded credential for exact redaction from unstructured text."""
    if not isinstance(value, str):
        raise TypeError("secret must be a string")
    # Very short values cannot be replaced safely in arbitrary prose: a
    # one-character test token would corrupt every subsequent log message.
    # Real provider credentials exceed this floor; short values still receive
    # the normal header/key-value shape redaction.
    if len(value) >= 8:
        with _KNOWN_SECRETS_LOCK:
            _KNOWN_SECRETS.add(value)


def _redact_text(value: str) -> str:
    value = _URL_FRAGMENT.sub(r"\1", value)
    with _KNOWN_SECRETS_LOCK:
        secrets = tuple(sorted(_KNOWN_SECRETS, key=lambda item: (-len(item), item)))
    for secret in secrets:
        value = value.replace(secret, REDACTED)
    value = re.sub(r"(?i)(https?://)[^/@\s]+@", r"\1[REDACTED]@", value)
    value = _OPENROUTER_KEY.sub(REDACTED, value)
    value = _AUTH_HEADER.sub(lambda match: match.group(1) + REDACTED, value)
    value = _BEARER.sub(lambda match: match.group(1) + REDACTED, value)
    value = _AUTH_VALUE.sub(
        lambda match: (
            match.group(0)
            if REDACTED in match.group(0)
            else match.group(1) + REDACTED
        ),
        value,
    )
    return _KEY_VALUE.sub(
        lambda match: (
            match.group(0)
            if REDACTED in match.group(0)
            else match.group(1) + REDACTED
        ),
        value,
    )


def redact(value: Any) -> Any:
    """Return a redacted copy of nested values without mutating the caller."""
    if isinstance(value, Mapping):
        return {
            key: REDACTED if _SENSITIVE_KEY.match(str(key)) else redact(item)
            for key, item in value.items()
        }
    if isinstance(value, tuple):
        return tuple(redact(item) for item in value)
    if isinstance(value, list):
        return [redact(item) for item in value]
    if isinstance(value, set):
        return {redact(item) for item in value}
    if isinstance(value, bytes):
        return _redact_text(value.decode("utf-8", errors="replace")).encode("utf-8")
    if isinstance(value, str):
        return _redact_text(value)
    return value


def safe_record_message(record: logging.LogRecord) -> str:
    """Format a record copy, then redact the complete rendered message."""
    copy = logging.makeLogRecord(record.__dict__.copy())
    # Mapping-style formatting otherwise discards the sensitive key name before
    # textual redaction gets a chance to see it.
    if isinstance(copy.args, Mapping):
        copy.args = redact(copy.args)
    try:
        rendered = copy.getMessage()
    except (KeyError, TypeError, ValueError):
        rendered = f"{redact(copy.msg)} [formatting-error]"
    return redact(rendered)


class RedactingFilter(logging.Filter):
    """Replace a record's message and structured extras with redacted copies."""

    _STANDARD_ATTRIBUTES = frozenset(
        logging.makeLogRecord({}).__dict__
    ) | {"message", "asctime"}

    def filter(self, record: logging.LogRecord) -> bool:
        record.msg = safe_record_message(record)
        record.args = ()
        if record.exc_info:
            exception_text = "".join(traceback.format_exception(*record.exc_info))
            record.msg = f"{record.msg}\n{redact(exception_text)}"
            record.exc_info = None
            record.exc_text = None
        if record.stack_info:
            record.stack_info = redact(record.stack_info)
        for name, value in tuple(record.__dict__.items()):
            if name not in self._STANDARD_ATTRIBUTES:
                record.__dict__[name] = (
                    REDACTED if _SENSITIVE_KEY.match(name) else redact(value)
                )
        return True


def install_redaction(logger: logging.Logger) -> RedactingFilter:
    """Install the policy on a logger and each current handler, idempotently."""
    for current in logger.filters:
        if isinstance(current, RedactingFilter):
            policy = current
            break
    else:
        policy = RedactingFilter()
        logger.addFilter(policy)
    for handler in logger.handlers:
        if not any(isinstance(item, RedactingFilter) for item in handler.filters):
            handler.addFilter(policy)
    return policy


def configure_logging(
    level: int = logging.INFO, *, handler: logging.Handler | None = None
) -> logging.Logger:
    """Configure the ``leitir`` logger without touching the process root logger."""
    logger = logging.getLogger("leitir")
    logger.setLevel(level)
    logger.propagate = False
    if handler is not None and handler not in logger.handlers:
        duplicate = any(
            isinstance(handler, logging.StreamHandler)
            and isinstance(current, logging.StreamHandler)
            and getattr(current, "stream", None) is getattr(handler, "stream", None)
            and current.level == handler.level
            and getattr(current.formatter, "_fmt", None)
            == getattr(handler.formatter, "_fmt", None)
            for current in logger.handlers
        )
        if not duplicate:
            logger.addHandler(handler)
    install_redaction(logger)
    return logger
