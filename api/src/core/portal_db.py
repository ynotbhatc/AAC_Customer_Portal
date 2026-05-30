"""
Separate asyncpg pool for the portal's OWN PostgreSQL database
(`aac_portal`), distinct from the customer-side compliance database that
core/database.py reads from.

Portal-owned tables (tenants, cve_events, cve_artifacts, ...) live here.
"""
import asyncpg
from .config import get_settings

_portal_pool: asyncpg.Pool | None = None


async def get_portal_pool() -> asyncpg.Pool:
    global _portal_pool
    if _portal_pool is None:
        s = get_settings()
        _portal_pool = await asyncpg.create_pool(
            host=s.portal_pg_host,
            port=s.portal_pg_port,
            database=s.portal_pg_database,
            user=s.portal_pg_user,
            password=s.portal_pg_password,
            min_size=2,
            max_size=10,
        )
    return _portal_pool


async def close_portal_pool() -> None:
    global _portal_pool
    if _portal_pool:
        await _portal_pool.close()
        _portal_pool = None
