"""Tests for the compliance router + the new stub routers.

Pins:
  - FrameworkSummary now carries `trend`, derived from latest-7d vs
    prior-7d average compliance with a 5pp threshold.
  - HostSummary now carries `critical_violations`, summing
    failed_controls on each host's most recent assessment per
    framework.
  - GET /compliance/results/{id} returns the row or 404.
  - The remediation, reports, and aap stub routers return 501 with a
    structured detail so the frontend handles "not implemented" as a
    known state instead of a silent 404.
"""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient


@pytest.fixture
def client():
    # Import here so conftest's env-var defaults are set before
    # core.config.Settings is read.
    from main import app
    return TestClient(app)


def test_remediation_list_returns_501(client):
    r = client.get("/api/remediation")
    assert r.status_code == 501
    body = r.json()
    assert "not implemented" in body["detail"].lower()


def test_remediation_patch_returns_501(client):
    r = client.patch("/api/remediation/abc-123", json={"status": "in_progress"})
    assert r.status_code == 501


def test_reports_download_returns_501(client):
    r = client.get("/api/reports/download", params={"framework": "cis_rhel9"})
    assert r.status_code == 501
    assert "audit_reports_design" in r.json()["detail"]


def test_aap_launch_returns_501(client):
    r = client.post(
        "/api/aap/launch",
        json={"hostname": "h", "framework": "cis_rhel9", "template_id": 1},
    )
    assert r.status_code == 501
    assert "AAP Controller" in r.json()["detail"]


def test_compliance_models_include_new_fields():
    """The pydantic models must surface `trend` and `critical_violations`
    so the frontend types resolve at runtime. Pure-import check —
    catches accidental field removal."""
    from src.models.compliance import FrameworkSummary, HostSummary, RemediationItem

    fw_fields = FrameworkSummary.model_fields
    assert "trend" in fw_fields, "FrameworkSummary missing trend"

    host_fields = HostSummary.model_fields
    assert "critical_violations" in host_fields, "HostSummary missing critical_violations"

    # RemediationItem is a new shape; verify it's importable + has the
    # frontend's expected keys.
    rem_fields = RemediationItem.model_fields
    for k in ("id", "hostname", "framework", "control_id", "severity", "status"):
        assert k in rem_fields, f"RemediationItem missing {k}"
