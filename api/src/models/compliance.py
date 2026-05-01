from pydantic import BaseModel
from datetime import datetime


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


class HostSummary(BaseModel):
    hostname: str
    frameworks_assessed: int
    overall_compliance: float
    last_assessed: datetime


class ComplianceTrend(BaseModel):
    date: datetime
    compliance_percentage: float
    passed_controls: int
    failed_controls: int
