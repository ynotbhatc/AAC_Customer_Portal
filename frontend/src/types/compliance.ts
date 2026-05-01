export interface ComplianceResult {
  id: number;
  hostname: string;
  framework: string;
  policy_name: string;
  policy_version: string;
  total_controls: number;
  passed_controls: number;
  failed_controls: number;
  compliance_percentage: number;
  compliant: boolean;
  violations: Violation[];
  metadata: Record<string, unknown>;
  evaluation_timestamp: string;
}

export interface Violation {
  control_id: string;
  description: string;
  severity: "critical" | "high" | "medium" | "low";
  remediation?: string;
}

export interface FrameworkSummary {
  framework: string;
  latest_percentage: number;
  compliant_hosts: number;
  total_hosts: number;
  last_assessed: string;
  trend: "improving" | "declining" | "stable";
}

export interface HostSummary {
  hostname: string;
  frameworks_assessed: number;
  overall_compliance: number;
  critical_violations: number;
  last_assessed: string;
}

export interface ComplianceTrend {
  date: string;
  compliance_percentage: number;
  passed_controls: number;
  failed_controls: number;
}

export interface RemediationItem {
  id: string;
  hostname: string;
  framework: string;
  control_id: string;
  description: string;
  severity: "critical" | "high" | "medium" | "low";
  status: "open" | "in_progress" | "resolved";
  assigned_to?: string;
  created_at: string;
  updated_at: string;
}
