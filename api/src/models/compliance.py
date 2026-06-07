from pydantic import BaseModel
from datetime import datetime
from typing import Literal


Trend = Literal["improving", "declining", "stable"]
Severity = Literal["critical", "high", "medium", "low"]
RemediationStatus = Literal["open", "in_progress", "resolved"]


class ComplianceResult(BaseModel):
    id: int
    hostname: str
    framework: str
    policy_name: str
    policy_version: str | None
    total_controls: int
    passed_controls: int
    failed_controls: int
    compliance_percentage: float
    compliant: bool
    violations: list[dict] | None
    metadata: dict | None
    evaluation_timestamp: datetime


class FrameworkSummary(BaseModel):
    framework: str
    latest_percentage: float
    compliant_hosts: int
    total_hosts: int
    last_assessed: datetime
    # Computed as latest-7-day vs prior-7-day average compliance: a >5pp
    # gain is "improving", >5pp drop is "declining", anything in between
    # is "stable". Thresholds picked to filter normal noise.
    trend: Trend


class HostSummary(BaseModel):
    hostname: str
    frameworks_assessed: int
    overall_compliance: float
    last_assessed: datetime
    # Count of failed controls on the host's latest assessment per
    # framework, summed. Today every failed control counts as
    # "critical" because the compliance_results.violations payload
    # has no per-violation severity field — it carries entries but
    # not a structured severity. When per-violation severity reaches
    # this table, narrow this to severity = 'critical'.
    critical_violations: int


class ComplianceTrend(BaseModel):
    date: datetime
    compliance_percentage: float
    passed_controls: int
    failed_controls: int


class RemediationItem(BaseModel):
    id: str
    hostname: str
    framework: str
    control_id: str
    description: str
    severity: Severity
    status: RemediationStatus
    assigned_to: str | None = None
    created_at: datetime
    updated_at: datetime
