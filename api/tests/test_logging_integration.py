"""Integration tests for structured logging + correlation IDs.

Pins:
  - The CorrelationIdMiddleware is wired and echoes X-Request-ID
    back on every response.
  - When the client doesn't send X-Request-ID, the middleware
    generates one (UUID4 shape).
  - When the client DOES send one, the middleware honors it
    (end-to-end traceability from frontend through API).
  - The JSON log formatter produces parseable records carrying the
    correlation_id field.

`configure_logging()` is called from main.py at import time, so the
fixture just needs to capture log output.
"""
from __future__ import annotations

import json
import logging
import re
import uuid

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient


pytestmark = [pytest.mark.asyncio(loop_scope="session")]


# asgi-correlation-id uses uuid4().hex by default — 32 hex chars with
# no dashes. Accept either form so the test isn't sensitive to a
# config flip on the middleware's `generator` option.
UUID_RE = re.compile(
    r"^[0-9a-f]{32}$|^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
    re.IGNORECASE,
)


def _normalize(uid: str) -> str:
    """Compare correlation IDs by canonical form so the test
    survives the middleware's dash-stripping normalization."""
    return uid.replace("-", "").lower()


@pytest_asyncio.fixture(loop_scope="session")
async def client():
    """Bare ASGI client — no DB needed for the middleware tests."""
    from main import app

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as c:
        yield c


async def test_response_carries_correlation_id_when_client_omits_it(client):
    """The middleware generates a fresh UUID per request.

    We hit `/health` because it's the simplest endpoint, but we don't
    require 200 — without a real DB in CI it returns 503 from the
    pool probe, and that doesn't affect the middleware test. What
    matters is that the X-Request-ID header is present on every
    response, regardless of status.
    """
    r = await client.get("/health")
    rid = r.headers.get("x-request-id") or r.headers.get("X-Request-ID")
    assert rid is not None, "X-Request-ID header missing on response"
    assert UUID_RE.match(rid), f"X-Request-ID is not a UUID: {rid!r}"


async def test_correlation_id_is_echoed_when_client_sends_one(client):
    """Frontend can stitch its UI events to backend traces by sending
    its own X-Request-ID; the middleware should respect it.

    asgi-correlation-id's default validator only accepts UUID4 (it
    silently generates a fresh ID if the incoming value isn't one),
    so we send a real uuid4. The middleware may normalize dashes
    away on echo — compare canonical forms.

    Same as the test above, we don't require 200 — the middleware
    runs regardless of whether the route succeeds.
    """
    rid_in = str(uuid.uuid4())
    r = await client.get("/health", headers={"X-Request-ID": rid_in})
    rid_out = r.headers.get("x-request-id") or r.headers.get("X-Request-ID")
    assert rid_out is not None
    assert _normalize(rid_out) == _normalize(rid_in)


def test_json_formatter_emits_parseable_records_with_correlation_id():
    """The JsonFormatter is configured on the root logger. Emit a log
    line and confirm it's structured JSON with the expected fields.

    Calls configure_logging() explicitly so the test doesn't depend
    on pytest's caplog fixture (which installs its own
    LogCaptureHandler — a StreamHandler subclass — at autouse, hiding
    our JsonFormatter behind it in handler-iteration order).
    """
    import logging as _l

    from src.core.logging import configure_logging

    configure_logging()

    root = _l.getLogger()
    # configure_logging() removes all existing handlers and adds
    # exactly one StreamHandler. Grab it directly.
    handlers = [h for h in root.handlers if isinstance(h, _l.StreamHandler)]
    assert handlers, "configure_logging() didn't install a StreamHandler"
    handler = handlers[0]
    formatter = handler.formatter
    assert formatter is not None

    record = _l.LogRecord(
        name="test.logger",
        level=_l.INFO,
        pathname=__file__,
        lineno=1,
        msg="policy published",
        args=(),
        exc_info=None,
    )
    # The CorrelationIdFilter normally injects this. Mirror that for
    # the synthetic record so the test exercises the formatter's
    # treatment of the field.
    record.correlation_id = "test-correlation-id"

    formatted = formatter.format(record)
    # If json format is configured, the line should parse as JSON;
    # plain format is a structured string. Both modes must include
    # the correlation id.
    try:
        payload = json.loads(formatted)
        assert payload.get("correlation_id") == "test-correlation-id"
        assert payload.get("message") == "policy published"
        assert payload.get("level") == "INFO"
    except json.JSONDecodeError:
        # Plain format path — fall through to a substring check.
        assert "test-correlation-id" in formatted
        assert "policy published" in formatted
