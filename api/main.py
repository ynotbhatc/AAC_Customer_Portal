from fastapi import FastAPI, Header, HTTPException, Response
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager
from typing import Optional

from asgi_correlation_id import CorrelationIdMiddleware

from src.core.audit_middleware import AuditMiddleware
from src.core.config import get_settings
from src.core.csrf import CsrfMiddleware
from src.core.database import get_pool, close_pool
from src.core.logging import configure_logging
from src.core.metrics import MetricsMiddleware, metrics_response
from src.core.portal_db import get_portal_pool, close_portal_pool
from src.routers import (
    aap,
    auth,
    baselines,
    bundles,
    classification,
    compliance,
    enrollments,
    feeds,
    host_mappings,
    legal_holds,
    me,
    me_mfa,
    permissions,
    policies,
    portal_feed,
    remediation,
    reports,
    standard_library,
    tenant_users,
    tenants,
)


@asynccontextmanager
async def lifespan(app: FastAPI):
    await get_pool()           # compliance reader pool
    await get_portal_pool()    # portal-owned DB pool
    yield
    await close_pool()
    await close_portal_pool()


settings = get_settings()
configure_logging()

app = FastAPI(
    title="AAC Customer Portal API",
    description="Read-only API over the AAC compliance_results PostgreSQL database",
    version="0.1.0",
    lifespan=lifespan,
)

# Prometheus exposition — records one counter + one histogram
# observation per request. Added FIRST (= outermost) so the timing
# reflects the wall-clock duration including all downstream
# middleware (audit log, correlation ID, CORS preflight, etc.).
app.add_middleware(MetricsMiddleware)

# CSRF (double-submit) — enforces X-CSRF-Token matches the aac_csrf
# cookie on POST/PATCH/DELETE/PUT, BUT only when the cookie is
# present. Bearer-authed requests (no cookie) pass through; this is
# the Phase N+1 transition: SPA moves to cookies and starts sending
# the header, CLI / pre-N+1 builds keep working on bearer. Phase
# N+2 will drop the bearer path for browser callers.
app.add_middleware(CsrfMiddleware)

# Audit log: writes a row to system_audit_log for every mutating
# request and every 4xx/5xx response. Added BEFORE the correlation
# middleware so the AuditMiddleware sees the correlation_id ContextVar
# set when it inspects the response.
app.add_middleware(AuditMiddleware, pool_getter=get_portal_pool)

# asgi-correlation-id: injects X-Request-ID on every request/response
# so logs from one request can be stitched end-to-end. Added BEFORE
# CORS so the header lands on CORS preflight responses too.
app.add_middleware(CorrelationIdMiddleware)

# CORS — explicit allowlist of headers. Combined with allow_credentials=True
# a wildcard allow_headers=["*"] would let arbitrary client-set headers
# ride credentialed requests; restrict to the ones the portal actually
# uses (Content-Type for JSON, Authorization for bearer tokens, the
# operator's X-Token-Id, and the standard caching headers).
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.allowed_origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PATCH", "DELETE"],
    allow_headers=[
        "Accept",
        "Accept-Language",
        "Authorization",
        "Cache-Control",
        "Content-Language",
        "Content-Type",
        "Origin",
        "X-CSRF-Token",
        "X-Token-Id",
        "X-Portal-Client",
        "X-Requested-With",
    ],
)

app.include_router(compliance.router, prefix="/api")
app.include_router(tenants.router, prefix="/api")
app.include_router(tenant_users.router, prefix="/api")
app.include_router(legal_holds.router, prefix="/api")
app.include_router(feeds.router, prefix="/api")
app.include_router(classification.router, prefix="/api")
app.include_router(enrollments.router, prefix="/api")
app.include_router(enrollments.ops_router, prefix="/api")
app.include_router(portal_feed.router, prefix="/api")
app.include_router(auth.router, prefix="/api")
app.include_router(me.router, prefix="/api")
app.include_router(me_mfa.router, prefix="/api")
app.include_router(permissions.router, prefix="/api")
app.include_router(policies.router, prefix="/api")
app.include_router(bundles.user_router, prefix="/api")
app.include_router(bundles.bridge_router, prefix="/api")
app.include_router(bundles.public_router, prefix="/api")
app.include_router(baselines.user_router, prefix="/api")
app.include_router(baselines.bridge_router, prefix="/api")
app.include_router(standard_library.router, prefix="/api")
app.include_router(host_mappings.router, prefix="/api")
# Stubs — return 501 so the frontend gets a structured error instead of
# a silent 404. Replace each with a real implementation as the
# corresponding feature lands.
app.include_router(remediation.router, prefix="/api")
app.include_router(reports.router, prefix="/api")
app.include_router(aap.router, prefix="/api")


@app.get("/metrics", include_in_schema=False)
async def metrics(
    x_metrics_token: Optional[str] = Header(default=None, alias="X-Metrics-Token"),
):
    """Prometheus exposition.

    When `METRICS_TOKEN` is set in the deployment environment, callers
    MUST present the matching `X-Metrics-Token` header. Otherwise the
    endpoint is open — appropriate for in-cluster Prometheus scraping
    where network isolation is the perimeter. Settings exposes the
    config flag so a deployment doesn't have to touch source code to
    add the gate.

    Read settings inside the handler (not from the module-level `settings`
    binding captured at import) so tests can monkeypatch the env +
    clear the `get_settings` lru_cache without reloading the app.
    """
    expected = get_settings().metrics_token
    if expected:
        # Constant-time compare — even though this token is operator-
        # supplied rather than user-supplied, treating it like any
        # other shared secret avoids ad-hoc timing channels.
        from hmac import compare_digest

        if not x_metrics_token or not compare_digest(x_metrics_token, expected):
            raise HTTPException(status_code=401, detail="invalid metrics token")
    return metrics_response()


@app.get("/health")
async def health(response: Response):
    """Liveness + database-pool readiness.

    Probes both pools with a lightweight `SELECT 1`. Returns HTTP 503
    if either pool is unreachable so the container orchestrator's
    healthcheck reflects the database state, not just the API
    process's. Without this probe, a healthy API container with a
    dead database would be reported healthy.
    """
    failures: list[str] = []
    for name, getter in (("compliance", get_pool), ("portal", get_portal_pool)):
        try:
            pool = await getter()
            async with pool.acquire() as conn:
                await conn.fetchval("SELECT 1")
        except Exception as exc:  # noqa: BLE001 — surface any pool error
            failures.append(f"{name}: {type(exc).__name__}")

    if failures:
        response.status_code = 503
        return {"status": "degraded", "failures": failures}
    return {"status": "ok"}
