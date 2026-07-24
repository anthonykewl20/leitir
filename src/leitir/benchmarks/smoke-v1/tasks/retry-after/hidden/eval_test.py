from datetime import datetime, timedelta, timezone
import pytest
from candidate import retry_after_seconds


def test_delay_and_http_date_forms():
    now = datetime(2026, 1, 22, 10, 0, 0, 500000, tzinfo=timezone.utc)
    assert retry_after_seconds("007", now) == 7
    assert retry_after_seconds("Thu, 22 Jan 2026 10:00:02 GMT", now) == 2
    assert retry_after_seconds("Thu, 22 Jan 2026 09:59:59 GMT", now) == 0


def test_rejects_invalid_or_ambiguous_inputs():
    now = datetime(2026, 1, 22, tzinfo=timezone.utc)
    for value in ("-1", "+1", "1.5", "１２", "not-a-date"):
        with pytest.raises(ValueError):
            retry_after_seconds(value, now)
    with pytest.raises(ValueError):
        retry_after_seconds("1", now.replace(tzinfo=None))
    with pytest.raises(ValueError):
        retry_after_seconds("1", now.astimezone(timezone(timedelta(hours=1))))
