Implement `retry_after_seconds(value, now)` in `candidate.py` using Python 3.11 standard-library facilities and the RFC 9110 Retry-After contract current on 2026-01-22.

`value` is either a non-negative decimal delay in seconds or an HTTP-date. `now` is an aware UTC `datetime`. Return a non-negative integer number of seconds. For a future HTTP-date, round a fractional remaining second up; a past date returns zero. Reject negative delays, malformed values, non-ASCII decimal forms, naive `now`, and non-UTC `now` with `ValueError`.
