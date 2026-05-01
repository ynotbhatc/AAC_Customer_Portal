import axios from "axios";
import type {
  ComplianceResult,
  FrameworkSummary,
  HostSummary,
  ComplianceTrend,
  RemediationItem,
} from "../types/compliance";

const api = axios.create({
  baseURL: import.meta.env.VITE_API_URL ?? "/api",
  withCredentials: true,
});

// ── Compliance Results ────────────────────────────────────────────────────────

export const getResults = (params?: {
  hostname?: string;
  framework?: string;
  limit?: number;
}) => api.get<ComplianceResult[]>("/compliance/results", { params }).then((r) => r.data);

export const getResult = (id: number) =>
  api.get<ComplianceResult>(`/compliance/results/${id}`).then((r) => r.data);

export const getFrameworks = () =>
  api.get<FrameworkSummary[]>("/compliance/frameworks").then((r) => r.data);

export const getHosts = () =>
  api.get<HostSummary[]>("/compliance/hosts").then((r) => r.data);

export const getTrend = (params: {
  hostname?: string;
  framework: string;
  days?: number;
}) => api.get<ComplianceTrend[]>("/compliance/trend", { params }).then((r) => r.data);

// ── Remediation ───────────────────────────────────────────────────────────────

export const getRemediationItems = (params?: {
  hostname?: string;
  status?: string;
  severity?: string;
}) =>
  api.get<RemediationItem[]>("/remediation", { params }).then((r) => r.data);

export const updateRemediationStatus = (
  id: string,
  status: RemediationItem["status"]
) => api.patch(`/remediation/${id}`, { status }).then((r) => r.data);

// ── Reports ───────────────────────────────────────────────────────────────────

export const downloadReport = async (params: {
  hostname?: string;
  framework: string;
  format: "pdf" | "csv" | "json";
}) => {
  const response = await api.get("/reports/download", {
    params,
    responseType: "blob",
  });
  const url = URL.createObjectURL(response.data);
  const a = document.createElement("a");
  a.href = url;
  a.download = `aac-report-${params.framework}.${params.format}`;
  a.click();
  URL.revokeObjectURL(url);
};

// ── AAP Actions ───────────────────────────────────────────────────────────────

export const launchAssessment = (params: {
  hostname: string;
  framework: string;
  template_id: number;
}) => api.post("/aap/launch", params).then((r) => r.data);

export default api;
