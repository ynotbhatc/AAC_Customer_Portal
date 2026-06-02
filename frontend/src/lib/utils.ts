import clsx, { ClassValue } from "clsx";
import { twMerge } from "tailwind-merge";
import { formatDistanceToNow, parseISO } from "date-fns";

export const cn = (...inputs: ClassValue[]) => twMerge(clsx(inputs));

export const relTime = (iso: string | null | undefined): string => {
  if (!iso) return "—";
  try {
    return formatDistanceToNow(parseISO(iso), { addSuffix: true });
  } catch {
    return iso;
  }
};

export const severityColor = (s: string | null | undefined): string => {
  switch ((s ?? "").toUpperCase()) {
    case "CRITICAL":
      return "bg-red-100 text-red-800";
    case "HIGH":
      return "bg-orange-100 text-orange-800";
    case "MEDIUM":
      return "bg-yellow-100 text-yellow-800";
    case "LOW":
      return "bg-blue-100 text-blue-800";
    default:
      return "bg-slate-100 text-slate-700";
  }
};

export const tierColor = (t: string): string => {
  switch (t) {
    case "premium":
      return "bg-purple-100 text-purple-800";
    case "standard":
      return "bg-blue-100 text-blue-800";
    case "airgapped":
      return "bg-slate-200 text-slate-800";
    case "free":
    default:
      return "bg-slate-100 text-slate-700";
  }
};

export const statusColor = (s: string): string => {
  switch (s) {
    case "active":
      return "bg-green-100 text-green-800";
    case "pending":
      return "bg-yellow-100 text-yellow-800";
    case "suspended":
      return "bg-red-100 text-red-800";
    case "deleted":
      return "bg-slate-300 text-slate-700";
    default:
      return "bg-slate-100 text-slate-700";
  }
};

export const extractErr = (err: unknown): string => {
  // axios error → response body detail; otherwise message
  const e = err as { response?: { data?: { detail?: string } }; message?: string };
  return e?.response?.data?.detail ?? e?.message ?? "unknown error";
};
