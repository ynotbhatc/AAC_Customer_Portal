"""Compliance report generators (v1 — P1 reports-download).

Three formats, common input shape:

    rows: list[dict]    one dict per compliance_results row
    summary: dict       roll-up: framework, generated_at, tenant, totals
    tenant_label: str   display label for the tenant on the report

The router (`/api/reports/download`) supplies all three from a
single tenant-scoped query and dispatches to the right generator
based on the `format` query parameter.

v2 (per `docs/audit_reports_design.md`) adds per-framework
templates, signed PDFs with per-evidence-item signatures, and DOCX.
This v1 is intentionally generic — every framework gets the same
table-based layout, no signatures.
"""
from __future__ import annotations

import csv
import io
import json
from datetime import datetime, timezone
from typing import Any


# ── JSON ─────────────────────────────────────────────────────────────


def render_json(rows: list[dict], summary: dict, tenant_label: str) -> bytes:
    """Direct GRC-platform-ingestion format. Per the design doc's
    "every claim is verifiable" principle, every row is included
    verbatim with its evaluation_timestamp + violations array."""
    payload = {
        "report_version": "1.0",
        "tenant_label": tenant_label,
        "generated_at": _iso_now(),
        "summary": summary,
        "results": [_clean_row(r) for r in rows],
    }
    return json.dumps(payload, default=str, indent=2).encode("utf-8")


# ── CSV ──────────────────────────────────────────────────────────────


def render_csv(rows: list[dict], summary: dict, tenant_label: str) -> bytes:
    """One row per compliance_results entry. Violations are joined
    with " | " into a single column so the file opens cleanly in
    Excel without per-cell array-handling tricks.

    The header carries the tenant + framework + timestamp so an
    auditor knows what the file came from when it's renamed."""
    buf = io.StringIO()
    # Metadata header lines (CSV-comment style with a leading #)
    buf.write(f"# AAC Compliance Report\n")
    buf.write(f"# Tenant: {tenant_label}\n")
    buf.write(f"# Framework: {summary.get('framework', '(all)')}\n")
    buf.write(f"# Generated: {_iso_now()}\n")
    buf.write(f"# Rows: {summary.get('row_count', len(rows))}\n")
    buf.write("\n")

    writer = csv.writer(buf)
    writer.writerow([
        "hostname",
        "framework",
        "evaluation_timestamp",
        "compliance_percentage",
        "compliant",
        "total_controls",
        "passed_controls",
        "failed_controls",
        "policy_name",
        "policy_version",
        "violations",
    ])
    for r in rows:
        violations = r.get("violations") or []
        # violations is either a list of strings or list of dicts
        # depending on writer side. Join on " | " regardless.
        if isinstance(violations, list):
            v_str = " | ".join(
                v if isinstance(v, str) else json.dumps(v, default=str)
                for v in violations
            )
        else:
            v_str = str(violations or "")
        writer.writerow([
            r.get("hostname"),
            r.get("framework"),
            r.get("evaluation_timestamp"),
            r.get("compliance_percentage"),
            r.get("compliant"),
            r.get("total_controls"),
            r.get("passed_controls"),
            r.get("failed_controls"),
            r.get("policy_name"),
            r.get("policy_version"),
            v_str,
        ])
    return buf.getvalue().encode("utf-8")


# ── PDF ──────────────────────────────────────────────────────────────


def render_pdf(rows: list[dict], summary: dict, tenant_label: str) -> bytes:
    """Generic per-framework report PDF.

    Layout:
      Page 1: cover with tenant + framework + generation timestamp
              + roll-up totals + overall compliance %.
      Pages 2+: per-host table of latest-per-framework compliance %,
              flagged hosts (sub-threshold) listed with top
              violations.

    Generated with reportlab — pure Python, no system deps. Output
    is functional; for the typographically-polished signed PDF the
    design doc describes, see v2 (separate PR).
    """
    # Import inside the function so the dependency is loaded only
    # when actually rendering — keeps test discovery + startup fast.
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import LETTER
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import inch
    from reportlab.platypus import (
        SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak,
    )

    buf = io.BytesIO()
    doc = SimpleDocTemplate(
        buf,
        pagesize=LETTER,
        leftMargin=0.75 * inch,
        rightMargin=0.75 * inch,
        topMargin=0.75 * inch,
        bottomMargin=0.75 * inch,
        title="AAC Compliance Report",
        author="AAC Customer Portal",
    )

    styles = getSampleStyleSheet()
    h1 = styles["Heading1"]
    h2 = styles["Heading2"]
    body = styles["BodyText"]
    small = ParagraphStyle(
        "small", parent=body, fontSize=8, textColor=colors.grey,
    )

    story: list[Any] = []

    # ── Cover ──────────────────────────────────────────────────────
    story.append(Paragraph("AAC Compliance Report", h1))
    story.append(Paragraph(f"Tenant: <b>{_esc(tenant_label)}</b>", body))
    story.append(Paragraph(
        f"Framework: <b>{_esc(summary.get('framework', '(all frameworks)'))}</b>",
        body,
    ))
    story.append(Paragraph(f"Generated: {_esc(_iso_now())}", body))
    story.append(Spacer(1, 0.25 * inch))

    # Summary table
    summary_data = [
        ["Metric", "Value"],
        ["Hosts assessed", str(summary.get("host_count", 0))],
        ["Total results", str(summary.get("row_count", len(rows)))],
        ["Overall compliance %", f"{summary.get('overall_pct', 0):.1f}%"],
        ["Compliant results", str(summary.get("compliant_count", 0))],
        ["Failed results", str(summary.get("failed_count", 0))],
    ]
    t = Table(summary_data, colWidths=[3 * inch, 2.5 * inch])
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1f2937")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("GRID", (0, 0), (-1, -1), 0.25, colors.lightgrey),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.whitesmoke, colors.white]),
    ]))
    story.append(t)
    story.append(Spacer(1, 0.25 * inch))
    story.append(Paragraph(
        "Every row in the detail tables corresponds to a compliance_results "
        "entry. Hosts are filtered to those mapped to your tenant via "
        "tenant_host_mapping; you will not see data for hosts outside your "
        "scope.",
        small,
    ))

    if rows:
        story.append(PageBreak())
        story.append(Paragraph("Detail", h2))

        # Detail table — keep it short enough to fit on the page;
        # truncate violations for the PDF (JSON/CSV carry the full
        # list).
        detail_header = [
            "Hostname", "Framework", "Compliance %",
            "Failed", "Last assessed",
        ]
        detail_rows = [detail_header]
        for r in rows[:200]:   # cap at 200 to keep the PDF bounded
            detail_rows.append([
                Paragraph(_esc(str(r.get("hostname") or "")), small),
                Paragraph(_esc(str(r.get("framework") or "")), small),
                f"{r.get('compliance_percentage', 0):.1f}",
                str(r.get("failed_controls", 0)),
                Paragraph(_esc(str(r.get("evaluation_timestamp") or "")), small),
            ])
        if len(rows) > 200:
            detail_rows.append([
                f"… plus {len(rows) - 200} more (download CSV/JSON for full set)",
                "", "", "", "",
            ])

        dt = Table(
            detail_rows,
            colWidths=[1.7 * inch, 1.3 * inch, 1.0 * inch, 0.7 * inch, 1.7 * inch],
            repeatRows=1,
        )
        dt.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#374151")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 7),
            ("GRID", (0, 0), (-1, -1), 0.25, colors.lightgrey),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.whitesmoke, colors.white]),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ]))
        story.append(dt)

    doc.build(story)
    return buf.getvalue()


# ── Helpers ──────────────────────────────────────────────────────────


def _iso_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _esc(s: str) -> str:
    """Escape a string for embedding in a ReportLab Paragraph (which
    treats `<>` as markup)."""
    return (s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;"))


def _clean_row(r: dict) -> dict:
    """Stringify timestamps + UUIDs so the JSON output is portable
    across tools. asyncpg returns datetimes that json.dumps's default
    str= handler also covers, but being explicit here protects
    against schema drift."""
    out = {}
    for k, v in r.items():
        if hasattr(v, "isoformat"):
            out[k] = v.isoformat()
        elif hasattr(v, "hex") and not isinstance(v, (bytes, bytearray)):
            out[k] = str(v)
        else:
            out[k] = v
    return out


def summarize(rows: list[dict], framework: str | None) -> dict:
    """Build the summary dict the renderers consume. Pure function —
    no DB access; the router does the SQL."""
    host_count = len({r.get("hostname") for r in rows if r.get("hostname")})
    compliant_count = sum(1 for r in rows if r.get("compliant"))
    failed_count = sum(1 for r in rows if r.get("compliant") is False)
    overall_pct = (
        sum(float(r.get("compliance_percentage") or 0) for r in rows) / len(rows)
        if rows else 0.0
    )
    return {
        "framework": framework or "(all frameworks)",
        "row_count": len(rows),
        "host_count": host_count,
        "compliant_count": compliant_count,
        "failed_count": failed_count,
        "overall_pct": round(overall_pct, 1),
    }
