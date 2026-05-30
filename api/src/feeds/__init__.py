"""Portal CVE feed adapters.

Each module owns one upstream source and exposes a single coroutine
`ingest(pool, *, lookback_days: int = ...) -> dict` that:
    1. Opens a row in feed_runs (status='running')
    2. Pulls upstream data (paginated, incremental where possible)
    3. UPSERTs into cve_events / cve_references
    4. Closes the feed_runs row with rows_added/updated + cursor_after

Adapters never raise to the caller — they update feed_runs.status to
'failed' with error_message and return the run dict.
"""
