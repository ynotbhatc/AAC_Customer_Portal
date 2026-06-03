from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager

from src.core.config import get_settings
from src.core.database import get_pool, close_pool
from src.core.portal_db import get_portal_pool, close_portal_pool
from src.routers import (
    auth,
    classification,
    compliance,
    enrollments,
    feeds,
    me,
    me_mfa,
    portal_feed,
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

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.allowed_origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PATCH", "DELETE"],
    allow_headers=["*"],
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


@app.get("/health")
async def health():
    return {"status": "ok"}
