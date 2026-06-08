"""Unit tests for the AAP client.

Mocks the httpx transport — no real AAP calls. Behavior-level pins
on the contract the router relies on:

  - Missing AAP_URL / AAP_TOKEN → AapNotConfigured
  - Successful launch → dict with 'job' field
  - HTTP 404 from AAP → AapError with "not found" in message
  - HTTP 5xx from AAP → AapError
  - Network error → AapError
  - Response missing 'job' field → AapError
  - extra_vars is passed through verbatim
"""
from __future__ import annotations

from unittest.mock import AsyncMock, patch

import httpx
import pytest


@pytest.fixture
def configured_settings(monkeypatch):
    """Inject AAP env so the client doesn't raise AapNotConfigured.

    Uses monkeypatch on get_settings's cached return value rather
    than setting env vars (which lru_cache would miss)."""
    from src.core.config import Settings, get_settings

    fake = Settings(
        aap_url="https://aap.example.com",
        aap_token="fake-token",
        aap_verify_ssl=False,
    )
    monkeypatch.setattr("src.core.aap_client.get_settings", lambda: fake)
    return fake


@pytest.fixture
def mock_response_factory():
    """Build a fake httpx.Response with a target status + json body."""
    def _make(status_code: int, body: dict | str):
        req = httpx.Request("POST", "https://aap.example.com/x")
        if isinstance(body, dict):
            import json
            return httpx.Response(status_code=status_code, content=json.dumps(body).encode(), request=req)
        return httpx.Response(status_code=status_code, content=body.encode(), request=req)
    return _make


async def test_raises_not_configured_when_url_missing(monkeypatch):
    from src.core.aap_client import AapNotConfigured, launch_job_template
    from src.core.config import Settings

    monkeypatch.setattr(
        "src.core.aap_client.get_settings",
        lambda: Settings(aap_url="", aap_token="t", aap_verify_ssl=True),
    )
    with pytest.raises(AapNotConfigured):
        await launch_job_template(1, {})


async def test_raises_not_configured_when_token_missing(monkeypatch):
    from src.core.aap_client import AapNotConfigured, launch_job_template
    from src.core.config import Settings

    monkeypatch.setattr(
        "src.core.aap_client.get_settings",
        lambda: Settings(aap_url="https://x", aap_token="", aap_verify_ssl=True),
    )
    with pytest.raises(AapNotConfigured):
        await launch_job_template(1, {})


async def test_successful_launch_returns_dict_with_job(configured_settings, mock_response_factory):
    from src.core.aap_client import launch_job_template

    resp = mock_response_factory(201, {
        "job": 42, "status": "pending",
        "url": "/api/v2/jobs/42/",
        "created": "2026-06-07T12:00:00Z",
    })
    mock_post = AsyncMock(return_value=resp)
    with patch("httpx.AsyncClient.post", mock_post):
        result = await launch_job_template(99, {"target_host": "h"})

    assert result["job"] == 42
    assert result["status"] == "pending"
    # The client passes extra_vars wrapped under 'extra_vars'
    call_args = mock_post.call_args
    assert call_args.kwargs["json"] == {"extra_vars": {"target_host": "h"}}
    # Template ID lands in the URL path
    assert "/api/v2/job_templates/99/launch/" in call_args.args[0]
    # Bearer header
    assert call_args.kwargs["headers"]["Authorization"] == "Bearer fake-token"


async def test_404_from_aap_says_not_found(configured_settings, mock_response_factory):
    from src.core.aap_client import AapError, launch_job_template

    resp = mock_response_factory(404, {"detail": "Not found."})
    with patch("httpx.AsyncClient.post", AsyncMock(return_value=resp)):
        with pytest.raises(AapError) as exc:
            await launch_job_template(404, {})

    # Router checks this substring — locking it in here.
    assert "not found" in str(exc.value).lower()


async def test_5xx_from_aap_raises(configured_settings, mock_response_factory):
    from src.core.aap_client import AapError, launch_job_template

    resp = mock_response_factory(500, "<html>Internal Server Error</html>")
    with patch("httpx.AsyncClient.post", AsyncMock(return_value=resp)):
        with pytest.raises(AapError) as exc:
            await launch_job_template(1, {})

    assert "500" in str(exc.value)
    # The HTML page is truncated — sanity-check it didn't blow up
    # logging by being huge
    assert len(str(exc.value)) < 1024


async def test_network_error_raises_aap_error(configured_settings):
    from src.core.aap_client import AapError, launch_job_template

    # httpx.ConnectError is an HTTPError subclass — caught by the
    # client's except clause.
    with patch(
        "httpx.AsyncClient.post",
        AsyncMock(side_effect=httpx.ConnectError("DNS fail")),
    ):
        with pytest.raises(AapError) as exc:
            await launch_job_template(1, {})

    assert "DNS fail" in str(exc.value)


async def test_response_missing_job_field_raises(configured_settings, mock_response_factory):
    from src.core.aap_client import AapError, launch_job_template

    # AAP returns 200 but the body has no 'job' — caller can't proceed.
    resp = mock_response_factory(201, {"status": "pending"})
    with patch("httpx.AsyncClient.post", AsyncMock(return_value=resp)):
        with pytest.raises(AapError) as exc:
            await launch_job_template(1, {})

    assert "job" in str(exc.value).lower()


async def test_non_json_response_raises(configured_settings, mock_response_factory):
    from src.core.aap_client import AapError, launch_job_template

    # AAP returning HTML on a "success" — likely an auth redirect to
    # the login page. The client should refuse to interpret it.
    resp = mock_response_factory(200, "<html>login</html>")
    with patch("httpx.AsyncClient.post", AsyncMock(return_value=resp)):
        with pytest.raises(AapError):
            await launch_job_template(1, {})
