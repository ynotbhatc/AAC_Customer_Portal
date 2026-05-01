from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager

from src.core.config import get_settings
from src.core.database import get_pool, close_pool
from src.routers import compliance, oscal


@asynccontextmanager
async def lifespan(app: FastAPI):
    await get_pool()   # warm connection pool on startup
    yield
    await close_pool()


settings = get_settings()

app = FastAPI(
    title="AAC Customer Portal API",
    description=(
        "Read-only API over the AAC compliance_results PostgreSQL database. "
        "Supports OIDC bearer token auth (Keycloak / Red Hat SSO) and "
        "OSCAL 1.1.2 Assessment Results export."
    ),
    version="0.2.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.allowed_origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PATCH"],
    allow_headers=["*"],
)

app.include_router(compliance.router, prefix="/api")
app.include_router(oscal.router, prefix="/api")


@app.get("/health")
async def health():
    return {"status": "ok", "version": "0.2.0"}
