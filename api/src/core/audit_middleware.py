"""Audit middleware.

Logs every mutating API call (POST/PUT/PATCH/DELETE) + every
4xx/5xx response (which catches failed auth attempts) to
`system_audit_log`. Reads are NOT audited — they don't change state
and would 10x audit volume without proportional value.

Pipeline:

    request → CorrelationIdMiddleware → AuditMiddleware → route
                                                                ↓
                                                          response
                                                                ↓
    response ← AuditMiddleware (writes audit row as a
              background task, doesn't block response)

The middleware:

- Reads tenant_user from `request.state.tenant_user` if the auth
  dependency set it. The dependency in core/sessions.py does NOT
  currently set this — wiring that up is the small follow-up that
  populates the WHO column in the audit log. Until then, audit
  rows have tenant_id/user_id NULL but every other field.
- Reads optional `request.state.audit_extra` (dict) for
  endpoint-specific context.
- Reads optional `request.state.audit_resource` (tuple of
  type, id) for the resource_type/resource_id columns.
"""
from __future__ import annotations

import asyncio
from typing import Any, Awaitable, Callable

from asgi_correlation_id import correlation_id
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response


AUDITED_METHODS = {"POST", "PUT", "PATCH", "DELETE"}


class AuditMiddleware(BaseHTTPMiddleware):
    """Logs mutations + failed-auth events to system_audit_log.

    The pool is resolved lazily through a getter so test setup can
    override it via app.dependency_overrides without monkey-patching
    this module.
    """

    def __init__(self, app, pool_getter: Callable[[], Awaitable[Any]]) -> None:
        super().__init__(app)
        self._pool_getter = pool_getter

    async def dispatch(
        self,
        request: Request,
        call_next: Callable[[Request], Awaitable[Response]],
    ) -> Response:
        response = await call_next(request)

        should_audit = (
            request.method in AUDITED_METHODS
            or response.status_code >= 400
        )
        if not should_audit:
            return response

        # Fire-and-forget so the response isn't held by the audit
        # write. record_audit() swallows DB errors so this can't
        # raise back into the request lifecycle either.
        asyncio.create_task(
            self._write_audit(request, response.status_code)
        )
        return response

    async def _write_audit(self, request: Request, status_code: int) -> None:
        # Import inside the method to avoid a top-level circular
        # (audit_middleware → audit → core.* → main.py imports
        # audit_middleware).
        from .audit import record_audit

        try:
            pool = await self._pool_getter()
        except Exception:
            return  # without a pool there's nowhere to write

        tenant_user = getattr(request.state, "tenant_user", None) or {}
        resource = getattr(request.state, "audit_resource", (None, None))
        extra = getattr(request.state, "audit_extra", None) or {}

        client_ip = request.client.host if request.client else None
        user_agent = request.headers.get("user-agent")

        await record_audit(
            pool,
            method=request.method,
            path=request.url.path,
            status_code=status_code,
            tenant_id=_stringify(tenant_user.get("tenant_id")),
            tenant_user_id=_stringify(tenant_user.get("tenant_user_id")),
            resource_type=resource[0],
            resource_id=_stringify(resource[1]) if resource[1] is not None else None,
            correlation_id=correlation_id.get(),
            client_ip=client_ip,
            user_agent=user_agent,
            details=extra,
        )


def _stringify(v: Any) -> str | None:
    """asyncpg accepts UUID objects on uuid columns but the
    audit columns are typed permissively (text for resource_id,
    cast-to-uuid for tenant_id). Coerce to str so callers can
    pass UUID or str interchangeably; None passes through."""
    if v is None:
        return None
    return str(v)
