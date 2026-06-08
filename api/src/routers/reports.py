"""Reports router — real implementation (P1).

Replaces the 501 stub from PR #42. Generates a compliance report
in CSV / JSON / PDF format for the current tenant, scoped via
tenant_host_mapping (migration 015, populated through #54's UI).

v1 surface — `docs/audit_reports_design.md` describes the eventual
per-framework templates + signed bundles. This v1 ships a generic
table-based report that works for every framework. Sign + per-
framework templates come in a follow-up.
"""
from __future__ import annotations

from typing import Annotated, Any, Literal
from uuid import UUID

import asyncpg
from fastapi import APIRouter, Depends, HTTPException, Query, Response

from ..core.database import get_pool
from ..core.portal_db import get_portal_pool
from ..core.report_generator import (
    render_csv,
    render_json,
    render_pdf,
    summarize,
)
from ..core.sessions import require_tenant_user
from ..core.tenant_scope import allowed_hostnames


router = APIRouter(
    prefix="/reports",
    tags=["reports"],
    dependencies=[Depends(require_tenant_user)],
)


Format = Literal["csv", "json", "pdf"]


# Default lookback for the report — operators can change this when we
# add a `since` query parameter in v2. For now the report is "current
# state" = the last 30 days, which matches how the compliance dashboard
# computes the framework summary.
_DEFAULT_LOOKBACK_DAYS = 30

# Cap on result rows per report. Hard cap protects against memory
# blowups on very wide tenants; large customers can use the JSON/CSV
# output instead of PDF.
_MAX_ROWS = 10_000


_MIME = {
    "csv":  "text/csv",
    "json": "application/json",
    "pdf":  "application/pdf",
}


@router.get("/download")
async def download_report(
    framework: str | None = Query(default=None, description="Filter by framework key (e.g. cis_rhel9). Omit for all frameworks."),
    hostname: str | None = Query(default=None, description="Filter by hostname. Must be in this tenant's allowed set."),
    days: int = Query(default=_DEFAULT_LOOKBACK_DAYS, ge=1, le=365),
    format: Format = Query(default="json"),
    user: Annotated[dict[str, Any], Depends(require_tenant_user)] = None,  # type: ignore[assignment]
    portal_pool: asyncpg.Pool = Depends(get_portal_pool),
    compliance_pool: asyncpg.Pool = Depends(get_pool),
):
    """Generate + return a compliance report.

    Tenant scoping: rows are filtered to hostnames mapped to the
    caller's tenant via tenant_host_mapping. A caller with no
    mapped hosts gets an empty (but valid) report — never 404, so
    the frontend can render "you have no mapped hosts" inline.

    `hostname=foreign` returns the same empty-report shape (no
    info leak about whether that host exists).

    Framework scoping: when the caller filters by framework, pass it
    through to `allowed_hostnames` so a host mapped *only* for
    `cis_rhel9` can't be used to pull `iso27001` rows. A mapping
    with framework=NULL still counts ("all frameworks"); a mapping
    with a different framework is excluded.
    """
    allowed = await allowed_hostnames(
        portal_pool, user["tenant_id"], framework=framework,
    )
    if hostname is not None and hostname not in allowed:
        # Return the empty-shape rather than 403 so caller can't
        # probe other tenants' hostnames.
        rows: list[dict] = []
    elif not allowed:
        rows = []
    else:
        # Build the WHERE clause incrementally so optional filters
        # don't force-include columns we don't need.
        conditions = [
            "hostname = ANY($1::text[])",
            "evaluation_timestamp >= NOW() - make_interval(days => $2)",
        ]
        args: list[Any] = [sorted(allowed), days]
        if framework:
            args.append(framework)
            conditions.append(f"framework = ${len(args)}")
        if hostname:
            args.append(hostname)
            conditions.append(f"hostname = ${len(args)}")
        args.append(_MAX_ROWS)

        result_rows = await compliance_pool.fetch(
            f"""
            SELECT id, hostname, framework, policy_name, policy_version,
                   total_controls, passed_controls, failed_controls,
                   compliance_percentage, compliant, violations, metadata,
                   evaluation_timestamp
              FROM compliance_results
             WHERE {" AND ".join(conditions)}
             ORDER BY evaluation_timestamp DESC, hostname ASC
             LIMIT ${len(args)}
            """,
            *args,
        )
        rows = [dict(r) for r in result_rows]

    summary = summarize(rows, framework)

    # Report header labels this as "Tenant" — so it must be the
    # tenant's display name, not the user's. Falls back to the user
    # context only if the tenant row is somehow missing (defensive;
    # FK constraints make this impossible in practice).
    tenant_display_name = await portal_pool.fetchval(
        "SELECT display_name FROM tenants WHERE id = $1::uuid",
        str(user["tenant_id"]),
    )
    tenant_label = (
        tenant_display_name
        or user.get("display_name")
        or user["email"]
    )

    if format == "csv":
        body = render_csv(rows, summary, tenant_label)
    elif format == "json":
        body = render_json(rows, summary, tenant_label)
    elif format == "pdf":
        body = render_pdf(rows, summary, tenant_label)
    else:  # pragma: no cover — pydantic Literal blocks anything else
        raise HTTPException(status_code=400, detail=f"unsupported format: {format}")

    # Suggested filename includes the framework (or 'all') + format
    fname = f"aac-report-{framework or 'all'}.{format}"
    return Response(
        content=body,
        media_type=_MIME[format],
        headers={"Content-Disposition": f'attachment; filename="{fname}"'},
    )
