"""Structured logging configuration for the portal API.

Format
------
Two formats are supported, selected by `LOG_FORMAT` env var:
  - `json` (default in production): one JSON object per log line,
    keys = timestamp, level, logger, message, plus any extras
    attached at log call time. Suitable for any log aggregator
    that ingests JSON (Loki, ELK, Datadog, ...).
  - `plain` (default in dev): human-readable two-line format
    with the correlation ID prefixed for easier mental tracking.

Correlation IDs
---------------
The asgi-correlation-id middleware injects a per-request UUID into
a ContextVar; the `CorrelationIdFilter` reads that ContextVar and
attaches `correlation_id` to every log record emitted during the
request. The frontend can pass an `X-Request-ID` header to trace a
request end-to-end; if absent, the middleware generates one and
returns it in the response.

Use
---
Any module that wants to log:

    import logging
    logger = logging.getLogger(__name__)
    logger.info("policy published", extra={"policy_id": str(pid)})

The `extra` dict's keys become top-level fields on the JSON record,
which is what makes structured logging worth using.
"""
from __future__ import annotations

import logging
import sys

from asgi_correlation_id import CorrelationIdFilter
from pythonjsonlogger.jsonlogger import JsonFormatter

from .config import get_settings


_LOG_LEVELS = {
    "debug": logging.DEBUG,
    "info": logging.INFO,
    "warning": logging.WARNING,
    "error": logging.ERROR,
    "critical": logging.CRITICAL,
}


def configure_logging() -> None:
    """Apply the logger configuration. Idempotent — calling this
    twice replaces the handlers cleanly, which matters for tests
    that spin up the app multiple times in one process.

    Routes uvicorn's access + error loggers through the same handler
    chain so every log line — application, framework, ASGI server —
    carries the same correlation_id and structured shape.
    """
    s = get_settings()
    level = _LOG_LEVELS.get(s.log_level.lower(), logging.INFO)

    handler = logging.StreamHandler(sys.stdout)
    handler.addFilter(CorrelationIdFilter())

    if s.log_format == "json":
        formatter = JsonFormatter(
            # Reserved attributes that JsonFormatter knows about; the
            # rest of the record dict gets dumped as-is alongside.
            "%(asctime)s %(levelname)s %(name)s %(message)s %(correlation_id)s",
            rename_fields={
                "asctime": "timestamp",
                "levelname": "level",
                "name": "logger",
            },
            timestamp=True,
        )
    else:
        # Plain dev format. Correlation ID prefixed in square brackets
        # so it's easy to grep when watching multiple requests
        # interleave.
        formatter = logging.Formatter(
            fmt="%(asctime)s [%(correlation_id)s] %(levelname)s %(name)s — %(message)s",
            datefmt="%Y-%m-%dT%H:%M:%S",
        )

    handler.setFormatter(formatter)

    root = logging.getLogger()
    root.setLevel(level)
    # Replace any existing handlers to make this idempotent in tests
    # that reload the app — otherwise every reload doubles output.
    for h in list(root.handlers):
        root.removeHandler(h)
    root.addHandler(handler)

    # Pipe uvicorn's loggers through the same handler so framework
    # and application logs share the correlation ID + format. Setting
    # `propagate=True` makes them bubble up to the root we just set.
    for name in ("uvicorn", "uvicorn.access", "uvicorn.error"):
        u = logging.getLogger(name)
        u.handlers = []
        u.propagate = True
