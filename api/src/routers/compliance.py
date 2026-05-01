from fastapi import APIRouter, Depends, Query
from ..core.database import get_pool
from ..models.compliance import ComplianceResult, FrameworkSummary, HostSummary, ComplianceTrend
import asyncpg

router = APIRouter(prefix="/compliance", tags=["compliance"])


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


@router.get("/frameworks", response_model=list[FrameworkSummary])
async def list_frameworks(pool: asyncpg.Pool = Depends(get_pool)):
    rows = await pool.fetch(
        """
        SELECT
            framework,
            ROUND(AVG(compliance_percentage), 1) AS latest_percentage,
            COUNT(*) FILTER (WHERE compliant) AS compliant_hosts,
            COUNT(DISTINCT hostname) AS total_hosts,
            MAX(evaluation_timestamp) AS last_assessed
        FROM compliance_results
        WHERE evaluation_timestamp >= NOW() - INTERVAL '7 days'
        GROUP BY framework
        ORDER BY framework
        """
    )
    return [dict(r) for r in rows]


@router.get("/hosts", response_model=list[HostSummary])
async def list_hosts(pool: asyncpg.Pool = Depends(get_pool)):
    rows = await pool.fetch(
        """
        SELECT
            hostname,
            COUNT(DISTINCT framework) AS frameworks_assessed,
            ROUND(AVG(compliance_percentage), 1) AS overall_compliance,
            MAX(evaluation_timestamp) AS last_assessed
        FROM compliance_results
        WHERE evaluation_timestamp >= NOW() - INTERVAL '7 days'
        GROUP BY hostname
        ORDER BY overall_compliance ASC
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
          AND evaluation_timestamp >= NOW() - ($2 || ' days')::INTERVAL
          {host_filter}
        GROUP BY DATE_TRUNC('day', evaluation_timestamp)
        ORDER BY date ASC
        """,
        *args,
    )
    return [dict(r) for r in rows]
