from fastapi import FastAPI, Response
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager

from src.core.config import get_settings
from src.core.database import get_pool, close_pool
from src.core.portal_db import get_portal_pool, close_portal_pool
from src.routers import (
    auth,
    baselines,
    bundles,
    classification,
    compliance,
    enrollments,
    feeds,
    me,
    me_mfa,
    policies,
    portal_feed,
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

app = FastAPI(
    title="AAC Customer Portal API",
    description="Read-only API over the AAC compliance_results PostgreSQL database",
    version="0.1.0",
    lifespan=lifespan,
)

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
        "X-Token-Id",
        "X-Requested-With",
    ],
)

app.include_router(compliance.router, prefix="/api")
app.include_router(tenants.router, prefix="/api")
app.include_router(tenant_users.router, prefix="/api")
app.include_router(feeds.router, prefix="/api")
app.include_router(classification.router, prefix="/api")
app.include_router(enrollments.router, prefix="/api")
app.include_router(enrollments.ops_router, prefix="/api")
app.include_router(portal_feed.router, prefix="/api")
app.include_router(auth.router, prefix="/api")
app.include_router(me.router, prefix="/api")
app.include_router(me_mfa.router, prefix="/api")
app.include_router(policies.router, prefix="/api")
app.include_router(bundles.user_router, prefix="/api")
app.include_router(bundles.bridge_router, prefix="/api")
app.include_router(bundles.public_router, prefix="/api")
app.include_router(baselines.user_router, prefix="/api")
app.include_router(baselines.bridge_router, prefix="/api")
app.include_router(standard_library.router, prefix="/api")


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
