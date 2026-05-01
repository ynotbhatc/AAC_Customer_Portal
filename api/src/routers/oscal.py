"""
OSCAL Assessment Results export router.

Transforms AAC compliance_results PostgreSQL rows into NIST OSCAL 1.1.2
Assessment Results format (JSON or YAML).

OSCAL spec: https://pages.nist.gov/OSCAL/reference/latest/assessment-results/

Mapping:
  compliance_results.hostname        → result.subjects[].subject-uuid (hashed)
  compliance_results.framework       → result.title + control-selections description
  compliance_results.policy_name     → metadata.title
  compliance_results.violations      → findings (not-satisfied) + observations
  compliance_results.passed_controls → findings (satisfied)
  compliance_results.evaluation_timestamp → result.start / result.end
"""

import hashlib
import json
import uuid
from datetime import datetime, timezone

import asyncpg
import yaml
from fastapi import APIRouter, Depends, Query
from fastapi.responses import Response

from ..core.auth import CurrentUser
from ..core.database import get_pool

router = APIRouter(prefix="/oscal", tags=["oscal"])

OSCAL_VERSION = "1.1.2"
AAC_VERSION = "1.0.0"


def _host_uuid(hostname: str) -> str:
    """Deterministic UUID derived from hostname for OSCAL subject references."""
    return str(uuid.UUID(bytes=hashlib.md5(hostname.encode()).digest()))


def _row_to_result(row: dict) -> dict:
    """Convert a single compliance_results row to an OSCAL result object."""
    host_uuid = _host_uuid(row["hostname"])
    ts = row["evaluation_timestamp"]
    if isinstance(ts, datetime):
        ts_str = ts.isoformat()
    else:
        ts_str = str(ts)

    violations: list[dict] = row.get("violations") or []

    # One observation per violation
    observations = []
    findings = []

    for v in violations[:50]:  # cap at 50 per result
        obs_uuid = str(uuid.uuid4())
        control_id = v.get("control_id", "unknown")
        description = v.get("description", "")
        severity = v.get("severity", "medium")

        obs = {
            "uuid": obs_uuid,
            "title": f"Control violation: {control_id}",
            "description": description,
            "methods": ["AUTOMATED"],
            "subjects": [{"subject-uuid": host_uuid, "type": "component"}],
            "collected": ts_str,
            "relevant-evidence": [
                {
                    "description": f"Severity: {severity}. "
                    + v.get("remediation", "See remediation guidance."),
                }
            ],
        }
        observations.append(obs)

        finding = {
            "uuid": str(uuid.uuid4()),
            "title": f"Not satisfied: {control_id}",
            "description": description,
            "target": {
                "type": "objective-id",
                "target-id": control_id,
                "status": {"state": "not-satisfied"},
            },
            "related-observations": [{"observation-uuid": obs_uuid}],
        }
        findings.append(finding)

    # Add a summary satisfied finding if compliant
    if row.get("compliant") and row.get("passed_controls", 0) > 0:
        findings.append(
            {
                "uuid": str(uuid.uuid4()),
                "title": f"Assessment passed: {row['policy_name']}",
                "description": (
                    f"{row['passed_controls']} of {row['total_controls']} controls satisfied."
                ),
                "target": {
                    "type": "objective-id",
                    "target-id": f"{row['framework']}.overall",
                    "status": {"state": "satisfied"},
                },
                "related-observations": [],
            }
        )

    return {
        "uuid": str(uuid.uuid4()),
        "title": f"{row['policy_name']} — {row['hostname']}",
        "description": (
            f"Automated compliance assessment of {row['hostname']} against "
            f"{row['framework']} ({row['policy_name']}). "
            f"Score: {row['compliance_percentage']}% "
            f"({row['passed_controls']}/{row['total_controls']} controls passed)."
        ),
        "start": ts_str,
        "end": ts_str,
        "reviewed-controls": {
            "control-selections": [
                {
                    "description": f"{row['framework']} controls assessed on {row['hostname']}",
                    "include-all": {},
                }
            ]
        },
        "subjects": [
            {
                "uuid": host_uuid,
                "type": "component",
                "title": row["hostname"],
                "description": f"Managed host: {row['hostname']}",
                "props": [
                    {"name": "hostname", "value": row["hostname"]},
                    {"name": "framework", "value": row["framework"]},
                ],
            }
        ],
        "observations": observations,
        "findings": findings,
    }


def _build_oscal_document(rows: list[dict], framework: str) -> dict:
    results = [_row_to_result(dict(r)) for r in rows]
    now = datetime.now(timezone.utc).isoformat()

    return {
        "assessment-results": {
            "uuid": str(uuid.uuid4()),
            "metadata": {
                "title": f"AAC Compliance Assessment — {framework}",
                "last-modified": now,
                "version": AAC_VERSION,
                "oscal-version": OSCAL_VERSION,
                "remarks": (
                    "Generated by Ansible Automated Compliance (AAC). "
                    "Data sourced from PostgreSQL compliance_results table."
                ),
            },
            "import-ap": {
                "href": f"#assessment-plan-{framework}",
                "remarks": "Assessment plan derived from AAC job template configuration.",
            },
            "results": results,
        }
    }


@router.get("/assessment-results")
async def get_assessment_results(
    user: CurrentUser,
    framework: str = Query(..., description="Framework key, e.g. cis_rhel9"),
    hostname: str | None = None,
    limit: int = Query(default=20, le=100),
    pool: asyncpg.Pool = Depends(get_pool),
):
    """Return OSCAL Assessment Results JSON for a framework."""
    rows = await _fetch_rows(pool, framework, hostname, limit)
    return _build_oscal_document(rows, framework)


@router.get("/assessment-results/download")
async def download_assessment_results(
    user: CurrentUser,
    framework: str = Query(...),
    hostname: str | None = None,
    format: str = Query(default="json", pattern="^(json|yaml)$"),
    limit: int = Query(default=100, le=500),
    pool: asyncpg.Pool = Depends(get_pool),
):
    """Download OSCAL Assessment Results as JSON or YAML file."""
    rows = await _fetch_rows(pool, framework, hostname, limit)
    doc = _build_oscal_document(rows, framework)
    filename = f"oscal-assessment-{framework}"

    if format == "yaml":
        content = yaml.dump(doc, default_flow_style=False, allow_unicode=True)
        return Response(
            content=content,
            media_type="application/yaml",
            headers={"Content-Disposition": f'attachment; filename="{filename}.yaml"'},
        )

    content = json.dumps(doc, indent=2, default=str)
    return Response(
        content=content,
        media_type="application/json",
        headers={"Content-Disposition": f'attachment; filename="{filename}.json"'},
    )


async def _fetch_rows(
    pool: asyncpg.Pool,
    framework: str,
    hostname: str | None,
    limit: int,
) -> list:
    args: list = [framework, limit]
    host_filter = ""
    if hostname:
        args.append(hostname)
        host_filter = f"AND hostname = ${len(args)}"

    return await pool.fetch(
        f"""
        SELECT DISTINCT ON (hostname)
            hostname, framework, policy_name, policy_version,
            total_controls, passed_controls, failed_controls,
            compliance_percentage, compliant, violations, metadata,
            evaluation_timestamp
        FROM compliance_results
        WHERE framework = $1
          {host_filter}
        ORDER BY hostname, evaluation_timestamp DESC
        LIMIT $2
        """,
        *args,
    )
