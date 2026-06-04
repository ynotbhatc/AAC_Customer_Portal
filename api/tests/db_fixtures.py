"""DB integration fixtures — rootless Podman + testcontainers.

Per AAC convention we use Podman, not Docker. testcontainers talks to
whatever container runtime exposes a docker-API-compatible socket via
the DOCKER_HOST env var. We point it at:

  - macOS:    the running podman-machine's API socket
  - Linux:    the rootless user socket at /run/user/<UID>/podman/podman.sock

Detection runs once per session. If no compatible socket exists,
integration fixtures `pytest.skip()` so the unit-test suite still
passes without a runtime.

Everything in the test path runs as the invoking user — no sudo, no
root containers. This matches what we ship in production.
"""
from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path
from typing import AsyncIterator

import asyncpg
import pytest
import pytest_asyncio


# ── Podman socket discovery ───────────────────────────────────────────


def _discover_podman_socket() -> str | None:
    """Return a `unix://` URL pointing at a usable rootless podman
    socket. None if no runtime is reachable.

    Mac: `podman machine inspect` reports the host-side QEMU/AppleHV
    socket. Linux: the systemd user socket `XDG_RUNTIME_DIR/podman/podman.sock`.
    """
    # Already set explicitly — let the user override.
    existing = os.environ.get("DOCKER_HOST")
    if existing and Path(existing.removeprefix("unix://")).exists():
        return existing

    # Linux rootless.
    xdg = os.environ.get("XDG_RUNTIME_DIR")
    if xdg:
        candidate = Path(xdg) / "podman" / "podman.sock"
        if candidate.exists():
            return f"unix://{candidate}"

    # macOS — query podman machine.
    podman = shutil.which("podman")
    if podman:
        try:
            out = subprocess.check_output(
                [podman, "machine", "inspect", "--format", "{{.ConnectionInfo.PodmanSocket.Path}}"],
                stderr=subprocess.DEVNULL,
                text=True,
            ).strip()
            if out and Path(out).exists():
                return f"unix://{out}"
        except (subprocess.CalledProcessError, FileNotFoundError):
            pass

    return None


_PODMAN_SOCKET: str | None | type = type  # sentinel for unset


def _ensure_podman_env() -> None:
    """Set DOCKER_HOST + TESTCONTAINERS_RYUK_DISABLED early so
    testcontainers picks them up at import time. Idempotent."""
    global _PODMAN_SOCKET
    if _PODMAN_SOCKET is type:
        _PODMAN_SOCKET = _discover_podman_socket()

    if _PODMAN_SOCKET is None:
        return

    os.environ.setdefault("DOCKER_HOST", _PODMAN_SOCKET)
    # Ryuk is testcontainers' cleanup sidecar; it doesn't always behave
    # under rootless podman. Containers are session-scoped and cleaned
    # up explicitly in the fixture teardown.
    os.environ.setdefault("TESTCONTAINERS_RYUK_DISABLED", "true")


# ── Session-scoped PostgreSQL container ───────────────────────────────


@pytest.fixture(scope="session")
def pg_container():
    """Spin up a single PostgreSQL 15 container for the session.

    Skips the test if no rootless podman socket is reachable — keeps
    `pytest -m integration` non-fatal on dev machines without a
    container runtime."""
    _ensure_podman_env()
    if _PODMAN_SOCKET is None:
        pytest.skip("no rootless podman socket — install podman or "
                    "start podman machine; integration tests skipped")

    from testcontainers.postgres import PostgresContainer

    container = PostgresContainer("docker.io/library/postgres:15-alpine")
    container.start()
    try:
        yield container
    finally:
        container.stop()


# ── Per-session DB pool + applied migrations ──────────────────────────


@pytest_asyncio.fixture(scope="session", loop_scope="session")
async def pg_dsn(pg_container) -> str:
    """asyncpg-style DSN pointing at the test container."""
    # testcontainers exposes a sqlalchemy URL by default; reshape to
    # asyncpg's accepted form.
    host = pg_container.get_container_host_ip()
    port = pg_container.get_exposed_port(5432)
    return f"postgresql://{pg_container.username}:{pg_container.password}@{host}:{port}/{pg_container.dbname}"


@pytest_asyncio.fixture(scope="session", loop_scope="session")
async def pg_pool_initialized(pg_dsn: str) -> AsyncIterator[asyncpg.Pool]:
    """Open a pool against the test DB and apply all migrations once.

    Migrations run in numeric order from api/migrations/. Migration 003a
    (taxonomy seed) is interpolated between 003 and 004 by the natural
    sort, which matches the production apply order.
    """
    pool = await asyncpg.create_pool(pg_dsn, min_size=2, max_size=4)
    try:
        api_root = Path(__file__).parent.parent
        migrations_dir = api_root / "migrations"
        sql_files = sorted(migrations_dir.glob("*.sql"))
        async with pool.acquire() as conn:
            for sql_file in sql_files:
                sql = sql_file.read_text()
                # asyncpg.execute happily handles multi-statement SQL
                # including BEGIN/COMMIT — no special chunking needed.
                await conn.execute(sql)
        yield pool
    finally:
        await pool.close()


@pytest_asyncio.fixture(loop_scope="session")
async def pg_pool(pg_pool_initialized: asyncpg.Pool) -> AsyncIterator[asyncpg.Pool]:
    """Yield the session pool, then truncate every test table for the
    next test. Faster than rebuilding the schema per-test.

    We don't reset sequences — UUID PKs don't need it, and bigserial
    keys (policy_audit_log.id) don't materially matter to test
    assertions."""
    yield pg_pool_initialized

    # Truncate every table customers touch — keeps the schema +
    # shared library tables (abstract_controls, target_mappings)
    # intact. CASCADE so FK dependents go too.
    async with pg_pool_initialized.acquire() as conn:
        await conn.execute(
            """
            TRUNCATE
              tenants,
              tenant_tokens,
              tenant_inventory_catalog,
              tenant_pull_runs,
              tenant_users,
              tenant_user_mfa_factors,
              tenant_user_sessions,
              tenant_user_password_resets,
              customer_policies,
              customer_policy_targets,
              policy_audit_log,
              policy_uploads,
              policy_bundles,
              tenant_enrollments,
              tenant_vendor_subscriptions,
              tenant_filter_preferences,
              tenant_cve_matches
            RESTART IDENTITY CASCADE
            """
        )
