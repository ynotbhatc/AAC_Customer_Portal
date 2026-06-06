"""Per-IP rate limiter exposed as FastAPI Depends factories.

Why not slowapi's decorator?
    slowapi's @limiter.limit decorator wraps the endpoint function,
    and the wrapper's signature inspection collides with FastAPI's
    handling of `from __future__ import annotations` + Annotated[]
    dependencies — Pydantic v2 sees forward-ref strings it can't
    resolve through the wrapper and treats `body` / `pool` as query
    parameters. Switching to a Depends factory sidesteps the wrapping
    entirely and is type-safe.

The limiter itself uses slowapi's `limits` storage so we still get
its battle-tested moving-window logic; we just hand-roll the
FastAPI integration.

Storage backend defaults to in-memory. For multi-worker deployments
set RATE_LIMIT_STORAGE_URI to a `redis://...` URI so counters are
shared across processes.
"""
from __future__ import annotations

from typing import Callable

from fastapi import HTTPException, Request
from limits import parse, RateLimitItem
from limits.aio.strategies import MovingWindowRateLimiter
from limits.storage import storage_from_string

from .config import get_settings


def _client_ip(request: Request) -> str:
    """Identify the caller. Honors X-Forwarded-For when we sit behind
    the nginx proxy in production; falls back to the immediate peer
    when not."""
    fwd = request.headers.get("x-forwarded-for")
    if fwd:
        # First entry is the original client; rest is the proxy chain.
        return fwd.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


# Async storage + moving-window strategy. Instantiated once at import
# time so the test suite can reset() it deterministically between
# cases.
_settings = get_settings()
_storage = storage_from_string(_settings.rate_limit_storage_uri or "async+memory://")
_strategy = MovingWindowRateLimiter(_storage)

# Parse the default once.
_default_item: RateLimitItem = parse(_settings.rate_limit_default)


async def _reset() -> None:
    """Clear all counters. Used by the test fixture."""
    await _storage.reset()


def rate_limit(rule: str) -> Callable:
    """Build a Depends-compatible callable that enforces `rule`.

    `rule` is a slowapi/limits-style string like '10/minute' or
    '5/second;200/minute' (multiple limits separated by ';').
    """
    items = [parse(piece.strip()) for piece in rule.split(";") if piece.strip()]

    async def _dep(request: Request) -> None:
        key = _client_ip(request)
        # Identifier scopes per-rule so a tight /login limit doesn't
        # share counters with a looser /me limit at the same IP.
        for item in items:
            if not await _strategy.hit(item, key, rule):
                # 429 with a JSON detail so the SPA can show a clean
                # message. Retry-After is set from the window so
                # well-behaved clients can back off correctly.
                retry_after = max(int(item.get_expiry()), 1)
                raise HTTPException(
                    status_code=429,
                    detail=f"rate limit exceeded: {item}",
                    headers={"Retry-After": str(retry_after)},
                )

    return _dep


async def _default_dep(request: Request) -> None:
    """Global default applied via app-level middleware. Currently a
    placeholder — the global default is enforced by the per-route
    deps; tight global enforcement would either require a middleware
    that wraps every request, or a catch-all dependency on every
    APIRouter. Left as an extension point for a later PR."""
    return None


# Re-exports used by routers + tests.
__all__ = ["rate_limit", "_reset", "_client_ip"]
