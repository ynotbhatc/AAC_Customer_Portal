"""Unit tests for the pure-function report generators.

Integration coverage lives in test_reports_download.py — these are
fast, no-DB checks that verify the generator output shape directly.
"""
from __future__ import annotations

import csv
import io
import json
from datetime import datetime, timezone


SAMPLE_ROWS = [
    {
        "id": 1,
        "hostname": "host-a",
        "framework": "cis_rhel9",
        "policy_name": "CIS RHEL 9",
        "policy_version": "v2.0.0",
        "total_controls": 100,
        "passed_controls": 95,
        "failed_controls": 5,
        "compliance_percentage": 95.0,
        "compliant": True,
        "violations": ["CIS 1.1.1: not compliant", "CIS 1.1.2: failure"],
        "metadata": {"section": "1"},
        "evaluation_timestamp": datetime(2026, 6, 8, 12, 0, tzinfo=timezone.utc),
    },
    {
        "id": 2,
        "hostname": "host-b",
        "framework": "cis_rhel9",
        "policy_name": "CIS RHEL 9",
        "policy_version": "v2.0.0",
        "total_controls": 100,
        "passed_controls": 50,
        "failed_controls": 50,
        "compliance_percentage": 50.0,
        "compliant": False,
        "violations": ["CIS 2.2.1: missing"],
        "metadata": {"section": "2"},
        "evaluation_timestamp": datetime(2026, 6, 8, 11, 0, tzinfo=timezone.utc),
    },
]


def _summary():
    from src.core.report_generator import summarize
    return summarize(SAMPLE_ROWS, framework="cis_rhel9")


def test_summarize_counts():
    s = _summary()
    assert s["framework"] == "cis_rhel9"
    assert s["row_count"] == 2
    assert s["host_count"] == 2
    assert s["compliant_count"] == 1
    assert s["failed_count"] == 1
    # Overall = (95 + 50) / 2 = 72.5
    assert s["overall_pct"] == 72.5


def test_summarize_handles_empty():
    from src.core.report_generator import summarize
    s = summarize([], framework=None)
    assert s["row_count"] == 0
    assert s["host_count"] == 0
    assert s["overall_pct"] == 0.0
    assert s["framework"] == "(all frameworks)"


def test_render_json_includes_every_row_and_summary():
    from src.core.report_generator import render_json
    out = render_json(SAMPLE_ROWS, _summary(), tenant_label="Acme")
    body = json.loads(out)
    assert body["report_version"] == "1.0"
    assert body["tenant_label"] == "Acme"
    assert body["summary"]["row_count"] == 2
    assert len(body["results"]) == 2
    # Timestamps serialized as ISO strings
    assert "T" in body["results"][0]["evaluation_timestamp"]


def test_render_csv_has_comment_header_and_data():
    from src.core.report_generator import render_csv
    text = render_csv(SAMPLE_ROWS, _summary(), tenant_label="Acme").decode("utf-8")
    assert "# AAC Compliance Report" in text
    assert "# Tenant: Acme" in text
    assert "# Framework: cis_rhel9" in text
    # Header + 2 data rows
    data = text[text.index("hostname"):]
    rows = list(csv.reader(io.StringIO(data)))
    assert rows[0][0] == "hostname"
    assert len(rows) == 3
    # Violations joined by " | "
    assert " | " in rows[1][-1]


def test_render_pdf_returns_pdf_bytes():
    from src.core.report_generator import render_pdf
    out = render_pdf(SAMPLE_ROWS, _summary(), tenant_label="Acme")
    assert out.startswith(b"%PDF-"), "PDF magic bytes missing"
    # End-of-file marker (allowing trailing whitespace/newlines)
    assert b"%%EOF" in out[-32:]
    # Sanity: non-trivial size
    assert len(out) > 1000


def test_render_pdf_empty_rows_still_valid():
    """Empty result set must still produce a valid PDF (cover page
    only). Used when a tenant has no mapped hosts yet."""
    from src.core.report_generator import render_pdf, summarize
    out = render_pdf([], summarize([], "cis_rhel9"), tenant_label="Acme")
    assert out.startswith(b"%PDF-")
    assert len(out) > 500


def test_render_pdf_escapes_html_chars_in_tenant_label():
    """Tenant labels can contain <, >, & — make sure ReportLab's
    Paragraph parser doesn't choke on them by treating them as
    markup."""
    from src.core.report_generator import render_pdf, summarize
    out = render_pdf([], summarize([], None), tenant_label="A&B <Co>")
    assert out.startswith(b"%PDF-")
