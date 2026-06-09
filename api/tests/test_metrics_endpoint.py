"""Tests for the Prometheus /metrics endpoint and middleware.

Pins the observable surface for the roadmap's "Alerting on 5xx
spike" follow-on item:
  - The endpoint serves valid Prometheus exposition (content type +
    metric names present).
  - The counter increments per request, labeled with method + route
    template + status_code.
  - The histogram records a duration sample.
  - Cardinality is bounded: requests with UUID path segments use the
    route template, not the rendered URL.
  - /metrics is excluded from instrumentation (scrape traffic must
    not dominate the series).
  - When METRICS_TOKEN is set, /metrics rejects unauthenticated
    callers with 401 and accepts the matching token.

Uses ASGITransport + httpx.AsyncClient with raise_app_exceptions=False
so the app's lifespan (which opens real PG pools) does NOT run, AND
so handlers that crash on missing deps render as 500 responses
rather than bubbling exceptions into the test.
"""
from __future__ import annotations

from uuid import UUID

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient

# Import the app + collectors once; reloading would propagate stale
# module bindings into other test files and contaminate the suite.
from main import app
from src.core.config import get_settings
from src.core.metrics import REQUESTS_TOTAL, REQUEST_DURATION_SECONDS


pytestmark = pytest.mark.asyncio(loop_scope="session")


@pytest.fixture(autouse=True)
def _reset_collectors_and_cache(monkeypatch):
    """Clear per-test process state so values don't leak across cases."""
    REQUESTS_TOTAL.clear()
    REQUEST_DURATION_SECONDS.clear()
    # Per-test env should not include METRICS_TOKEN unless explicitly set.
    monkeypatch.delenv("METRICS_TOKEN", raising=False)
    get_settings.cache_clear()
    yield
    REQUESTS_TOTAL.clear()
    REQUEST_DURATION_SECONDS.clear()
    get_settings.cache_clear()


def _client():
    # raise_app_exceptions=False so handlers that crash render as 500
    # (matching production behavior) rather than bubbling into the test.
    transport = ASGITransport(app=app, raise_app_exceptions=False)
    return AsyncClient(transport=transport, base_url="http://test")


async def test_metrics_endpoint_serves_prometheus_exposition():
    async with _client() as client:
        # Hit /openapi.json (no DB, no auth) so the counter has at
        # least one observation to render.
        await client.get("/openapi.json")
        resp = await client.get("/metrics")
        assert resp.status_code == 200
        ctype = resp.headers["content-type"]
        # Prometheus exposition is text/plain; version=0.0.4; charset=utf-8.
        assert ctype.startswith("text/plain")
        body = resp.text
        assert "portal_http_requests_total" in body
        assert "portal_http_request_duration_seconds" in body


async def test_counter_records_method_route_and_status():
    async with _client() as client:
        await client.get("/openapi.json")
        body = (await client.get("/metrics")).text
        assert 'method="GET"' in body
        assert 'status_code="200"' in body


async def test_histogram_records_duration_samples():
    async with _client() as client:
        await client.get("/openapi.json")
        body = (await client.get("/metrics")).text
        assert "portal_http_request_duration_seconds_count" in body
        assert "portal_http_request_duration_seconds_sum" in body
        assert "portal_http_request_duration_seconds_bucket" in body


async def test_metrics_endpoint_self_excluded_from_counter():
    """Scrape traffic on /metrics must not dominate the series."""
    async with _client() as client:
        for _ in range(3):
            await client.get("/metrics")
        body = (await client.get("/metrics")).text
        assert 'route="/metrics"' not in body


async def test_route_label_uses_template_not_rendered_url():
    """Cardinality guard: parameterized routes must record under the
    TEMPLATE label, not the literal URL — otherwise every distinct
    UUID generates a new series and memory grows unbounded.

    Auth + pool deps are overridden so the request resolves into the
    route handler (which then 5xxs on a None pool). What we verify
    is that the middleware's label extraction sees the template
    regardless of the eventual status.
    """
    from src.core.portal_db import get_portal_pool
    from src.core.sessions import require_tenant_user, require_tenant_user_mfa

    fake_user = {
        "session_id": UUID("11111111-1111-1111-1111-111111111111"),
        "tenant_user_id": UUID("22222222-2222-2222-2222-222222222222"),
        "tenant_id": UUID("33333333-3333-3333-3333-333333333333"),
        "email": "u@example",
        "display_name": "u",
        "role": "editor",
        "mfa_required": False,
        "mfa_enrolled": True,
        "mfa_verified": True,
    }

    async def _fake_user_dep(request=None):
        if request is not None:
            request.state.tenant_user = fake_user
        return fake_user

    async def _fake_pool():
        return None

    app.dependency_overrides[get_portal_pool] = _fake_pool
    app.dependency_overrides[require_tenant_user] = _fake_user_dep
    app.dependency_overrides[require_tenant_user_mfa] = _fake_user_dep
    try:
        async with _client() as client:
            await client.get(
                "/api/portal/v1/me/policies/00000000-0000-0000-0000-000000000001"
            )
            await client.get(
                "/api/portal/v1/me/policies/00000000-0000-0000-0000-000000000002"
            )
            body = (await client.get("/metrics")).text
        # Literal UUIDs must NOT appear in labels.
        assert "00000000-0000-0000-0000-000000000001" not in body
        assert "00000000-0000-0000-0000-000000000002" not in body
        # Template form should appear.
        assert "/portal/v1/me/policies/{policy_id}" in body
    finally:
        app.dependency_overrides.clear()


async def test_metrics_token_required_when_configured(monkeypatch):
    monkeypatch.setenv("METRICS_TOKEN", "topsecret")
    get_settings.cache_clear()
    async with _client() as client:
        resp = await client.get("/metrics")
        assert resp.status_code == 401
        resp = await client.get("/metrics", headers={"X-Metrics-Token": "wrong"})
        assert resp.status_code == 401
        resp = await client.get("/metrics", headers={"X-Metrics-Token": "topsecret"})
        assert resp.status_code == 200


async def test_metrics_open_when_token_empty():
    """Default deployment posture: no token, in-cluster network isolation."""
    async with _client() as client:
        resp = await client.get("/metrics")
        assert resp.status_code == 200
