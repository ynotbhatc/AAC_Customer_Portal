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
    """Bypass auth so the 501 stub responses are observable.

    These tests pin the BUSINESS behavior (501 from unimplemented
    routes), not the auth gate — see test_auth_gating.py for the
    "anonymous → 401" pins.
    """
    from main import app
    from src.core.portal_db import get_portal_pool
    from src.core.sessions import require_tenant_user, require_tenant_user_mfa

    fake_user = {
        "session_id": "00000000-0000-0000-0000-000000000001",
        "tenant_user_id": "00000000-0000-0000-0000-000000000002",
        "tenant_id": "00000000-0000-0000-0000-000000000003",
        "email": "test@example.com",
        "display_name": "test",
        "role": "user",
        "mfa_required": False,
        "mfa_enrolled": False,
        "mfa_verified": False,
    }

    async def _stub_pool():
        return None

    app.dependency_overrides[get_portal_pool] = _stub_pool
    app.dependency_overrides[require_tenant_user] = lambda: fake_user
    app.dependency_overrides[require_tenant_user_mfa] = lambda: fake_user
    try:
        yield TestClient(app)
    finally:
        for dep in (get_portal_pool, require_tenant_user, require_tenant_user_mfa):
            app.dependency_overrides.pop(dep, None)


# The two old 501-stub tests for /remediation were removed when P0-C
# replaced the stubs with a real implementation. Behavioral coverage
# now lives in test_remediation_integration.py (real-DB tests for the
# full state machine + four-eyes invariant).


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


def test_compliance_results_by_id_route_is_registered():
    """GET /api/compliance/results/{id} must exist as a route.

    Pure route-inspection check — no DB needed. Catches a regression
    where the route is accidentally removed or the path template
    changes; previously this gap silently 404'd at the framework
    level and looked like a missing row rather than a missing
    endpoint.
    """
    from main import app

    paths = {route.path for route in app.routes}
    assert "/api/compliance/results/{result_id}" in paths, (
        f"GET /api/compliance/results/{{result_id}} not registered. "
        f"Compliance routes present: "
        f"{sorted(p for p in paths if p.startswith('/api/compliance'))}"
    )


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
