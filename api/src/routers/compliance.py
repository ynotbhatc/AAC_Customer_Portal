from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Query
from ..core.database import get_pool
from ..core.sessions import require_tenant_user
from ..models.compliance import ComplianceResult, FrameworkSummary, HostSummary, ComplianceTrend
import asyncpg

# Every endpoint on this router requires a logged-in tenant user.
# Compliance data is sensitive — read-access was previously
# unauthenticated, which was the foundation gap the reviewer agent
# called out. Multi-tenant scoping of the underlying compliance_results
# table is a follow-on PR (P0-A2); for now the auth wall stops the
# trivial unauth-read case.
router = APIRouter(
    prefix="/compliance",
    tags=["compliance"],
    dependencies=[Depends(require_tenant_user)],
)


@router.get("/results", response_model=list[ComplianceResult])
async def list_results(
    hostname: str | None = None,
    framework: str | None = None,
    limit: int = Query(default=50, le=500),
    pool: asyncpg.Pool = Depends(get_pool),
):
    conditions = []
    args = []
    if hostname:
        args.append(hostname)
        conditions.append(f"hostname = ${len(args)}")
    if framework:
        args.append(framework)
        conditions.append(f"framework = ${len(args)}")

    where = f"WHERE {' AND '.join(conditions)}" if conditions else ""
    args.append(limit)

    rows = await pool.fetch(
        f"""
        SELECT id, hostname, framework, policy_name, policy_version,
               total_controls, passed_controls, failed_controls,
               compliance_percentage, compliant, violations, metadata,
               evaluation_timestamp
        FROM compliance_results
        {where}
        ORDER BY evaluation_timestamp DESC
        LIMIT ${len(args)}
        """,
        *args,
    )
    return [dict(r) for r in rows]


@router.get("/results/{result_id}", response_model=ComplianceResult)
async def get_result(
    result_id: int,
    pool: asyncpg.Pool = Depends(get_pool),
):
    """Single compliance result by id — frontend's `getResult(id)`.

    Returns 404 if no such row; previously this path was unrouted and
    silently 404'd on the framework router level, which hid the gap.
    """
    row = await pool.fetchrow(
        """
        SELECT id, hostname, framework, policy_name, policy_version,
               total_controls, passed_controls, failed_controls,
               compliance_percentage, compliant, violations, metadata,
               evaluation_timestamp
        FROM compliance_results
        WHERE id = $1
        """,
        result_id,
    )
    if row is None:
        raise HTTPException(status_code=404, detail=f"result {result_id} not found")
    return dict(row)


@router.get("/frameworks", response_model=list[FrameworkSummary])
async def list_frameworks(pool: asyncpg.Pool = Depends(get_pool)):
    # Trend = latest 7d avg vs prior 7d avg: ≥5pp gain = improving,
    # ≥5pp drop = declining, anything in between = stable. The 5pp
    # threshold filters day-to-day noise.
    rows = await pool.fetch(
        """
        WITH windows AS (
            SELECT
                framework,
                compliance_percentage,
                compliant,
                hostname,
                evaluation_timestamp,
                CASE
                    WHEN evaluation_timestamp >= NOW() - INTERVAL '7 days'
                        THEN 'current'
                    WHEN evaluation_timestamp >= NOW() - INTERVAL '14 days'
                        THEN 'prior'
                END AS window
            FROM compliance_results
            WHERE evaluation_timestamp >= NOW() - INTERVAL '14 days'
        ),
        current_window AS (
            SELECT
                framework,
                ROUND(AVG(compliance_percentage), 1) AS latest_percentage,
                COUNT(*) FILTER (WHERE compliant) AS compliant_hosts,
                COUNT(DISTINCT hostname) AS total_hosts,
                MAX(evaluation_timestamp) AS last_assessed
            FROM windows
            WHERE window = 'current'
            GROUP BY framework
        ),
        prior_window AS (
            SELECT
                framework,
                AVG(compliance_percentage) AS prior_percentage
            FROM windows
            WHERE window = 'prior'
            GROUP BY framework
        )
        SELECT
            c.framework,
            c.latest_percentage,
            c.compliant_hosts,
            c.total_hosts,
            c.last_assessed,
            CASE
                WHEN p.prior_percentage IS NULL THEN 'stable'
                WHEN c.latest_percentage - p.prior_percentage >= 5 THEN 'improving'
                WHEN p.prior_percentage - c.latest_percentage >= 5 THEN 'declining'
                ELSE 'stable'
            END AS trend
        FROM current_window c
        LEFT JOIN prior_window p USING (framework)
        ORDER BY c.framework
        """
    )
    return [dict(r) for r in rows]


@router.get("/hosts", response_model=list[HostSummary])
async def list_hosts(pool: asyncpg.Pool = Depends(get_pool)):
    # critical_violations = sum of failed_controls across each host's
    # most recent assessment per framework. Today treats every failed
    # control as "critical" because compliance_results.violations is a
    # list of strings with no per-violation severity. Once severity is
    # added to the table, narrow this to severity = 'critical'.
    rows = await pool.fetch(
        """
        WITH ranked AS (
            SELECT
                hostname,
                framework,
                compliance_percentage,
                failed_controls,
                evaluation_timestamp,
                ROW_NUMBER() OVER (
                    PARTITION BY hostname, framework
                    ORDER BY evaluation_timestamp DESC
                ) AS rn
            FROM compliance_results
            WHERE evaluation_timestamp >= NOW() - INTERVAL '7 days'
        ),
        latest_per_framework AS (
            SELECT * FROM ranked WHERE rn = 1
        )
        SELECT
            hostname,
            COUNT(DISTINCT framework) AS frameworks_assessed,
            ROUND(AVG(compliance_percentage), 1) AS overall_compliance,
            MAX(evaluation_timestamp) AS last_assessed,
            COALESCE(SUM(failed_controls), 0)::int AS critical_violations
        FROM latest_per_framework
        GROUP BY hostname
        ORDER BY critical_violations DESC, overall_compliance ASC
        """
    )
    return [dict(r) for r in rows]


@router.get("/trend", response_model=list[ComplianceTrend])
async def get_trend(
    framework: str,
    hostname: str | None = None,
    days: int = Query(default=30, le=365),
    pool: asyncpg.Pool = Depends(get_pool),
):
    args: list = [framework, days]
    host_filter = ""
    if hostname:
        args.append(hostname)
        host_filter = f"AND hostname = ${len(args)}"

    rows = await pool.fetch(
        f"""
        SELECT
            DATE_TRUNC('day', evaluation_timestamp) AS date,
            ROUND(AVG(compliance_percentage), 1) AS compliance_percentage,
            SUM(passed_controls) AS passed_controls,
            SUM(failed_controls) AS failed_controls
        FROM compliance_results
        WHERE framework = $1
          AND evaluation_timestamp >= NOW() - make_interval(days => $2)
          {host_filter}
        GROUP BY DATE_TRUNC('day', evaluation_timestamp)
        ORDER BY date ASC
        """,
        *args,
    )
    return [dict(r) for r in rows]
