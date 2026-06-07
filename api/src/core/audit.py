"""System-wide audit logging.

`record_audit()` writes a row to `system_audit_log` (see migration
014). The middleware in `audit_middleware.py` calls this on every
mutating API response via a background task so a failed insert
doesn't break the response.

The audit row carries:

- method + path + status_code: HTTP fingerprint
- tenant_id + tenant_user_id: WHO (may be NULL on anonymous calls
  that hit auth before establishing identity)
- resource_type + resource_id: WHAT (best-effort — the middleware
  extracts the leaf id from the path; routers can attach richer
  values via request.state.audit_extra)
- correlation_id: matches asgi-correlation-id's X-Request-ID for
  app-log → audit-log jumps
- client_ip + user_agent: trust signals for security investigation
- details: jsonb bag for endpoint-specific extras (before/after,
  request body snippets, etc.) — attach via request.state.audit_extra
"""
from __future__ import annotations

import logging
from typing import Any

import asyncpg


logger = logging.getLogger(__name__)


async def record_audit(
    pool: asyncpg.Pool,
    *,
    method: str,
    path: str,
    status_code: int,
    tenant_id: str | None = None,
    tenant_user_id: str | None = None,
    resource_type: str | None = None,
    resource_id: str | None = None,
    correlation_id: str | None = None,
    client_ip: str | None = None,
    user_agent: str | None = None,
    details: dict[str, Any] | None = None,
) -> None:
    """Insert a row into system_audit_log. Best-effort.

    Failures are logged at WARNING level and swallowed — an audit
    insert failure must NOT break the request/response cycle. The
    log line includes the original method+path so the gap is
    observable in the application logs.
    """
    try:
        await pool.execute(
            """
            INSERT INTO system_audit_log (
                tenant_id, tenant_user_id, method, path, status_code,
                resource_type, resource_id, correlation_id,
                client_ip, user_agent, details
            )
            VALUES (
                $1::uuid, $2::uuid, $3, $4, $5,
                $6, $7, $8,
                $9::inet, $10, $11::jsonb
            )
            """,
            tenant_id,
            tenant_user_id,
            method,
            path,
            status_code,
            resource_type,
            resource_id,
            correlation_id,
            client_ip,
            user_agent,
            _json_dumps(details or {}),
        )
    except Exception as exc:  # noqa: BLE001
        # Don't propagate — best-effort by design.
        logger.warning(
            "audit_log_insert_failed",
            extra={
                "audit_method": method,
                "audit_path": path,
                "audit_status": status_code,
                "error": str(exc),
            },
        )


def _json_dumps(d: dict[str, Any]) -> str:
    """asyncpg expects jsonb as a string. Wrapped so the call site
    isn't littered with `json.dumps` and so we can swap in a faster
    serializer later (orjson) without touching every record_audit
    call."""
    import json
    return json.dumps(d, default=str)
