import { useState } from "react";
import { Link, useParams } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  createToken,
  enrollBucket,
  getPreferences,
  getTenant,
  listBuckets,
  listEnrollments,
  listMatches,
  listTokens,
  listVendorSubscriptions,
  listVendors,
  removeVendorSubscription,
  revokeToken,
  setPreferences,
  setVendorSubscription,
  triggerInventoryPullForTenant,
  triggerMatchForTenant,
  unenrollBucket,
} from "../lib/api";
import type {
  FilterPreferences,
  Severity,
  TokenCreated,
} from "../types/cve";
import {
  cn,
  extractErr,
  relTime,
  severityColor,
  statusColor,
  tierColor,
} from "../lib/utils";

type Tab = "tokens" | "enrollments" | "vendors" | "preferences" | "matches";

const TABS: { id: Tab; label: string }[] = [
  { id: "tokens", label: "Tokens" },
  { id: "enrollments", label: "Bucket enrollments" },
  { id: "vendors", label: "Vendor subscriptions" },
  { id: "preferences", label: "Filter preferences" },
  { id: "matches", label: "CVE matches" },
];

export default function TenantDetailPage() {
  const { id = "" } = useParams();
  const [tab, setTab] = useState<Tab>("tokens");

  const { data: tenant, isLoading } = useQuery({
    queryKey: ["tenant", id],
    queryFn: () => getTenant(id),
    enabled: !!id,
  });

  if (isLoading) return <div className="text-slate-500">Loading…</div>;
  if (!tenant) return <div className="text-red-700">Tenant not found.</div>;

  return (
    <div className="space-y-6">
      <div className="text-xs text-slate-500">
        <Link to="/tenants" className="hover:underline">Tenants</Link>
        <span className="mx-1">/</span>
        <span>{tenant.display_name}</span>
      </div>

      <header className="flex items-start justify-between">
        <div>
          <h1 className="text-2xl font-semibold text-slate-900">
            {tenant.display_name}
          </h1>
          <div className="flex items-center gap-2 mt-2">
            <span className={`badge ${tierColor(tenant.tier)}`}>{tenant.tier}</span>
            <span className={`badge ${statusColor(tenant.status)}`}>
              {tenant.status}
            </span>
            {tenant.contact_email && (
              <span className="text-sm text-slate-500">
                {tenant.contact_email}
              </span>
            )}
          </div>
          {tenant.aac_bridge_url && (
            <div className="text-xs text-slate-500 mt-2 font-mono">
              Bridge: {tenant.aac_bridge_url}
              {!tenant.aac_bridge_verify_ssl && " (TLS verify off)"}
            </div>
          )}
        </div>
        <div className="text-xs text-slate-500 text-right">
          <div>Tenant id</div>
          <div className="font-mono text-slate-700">{tenant.id}</div>
        </div>
      </header>

      <div className="border-b border-slate-200">
        <nav className="flex gap-1">
          {TABS.map((t) => (
            <button
              key={t.id}
              onClick={() => setTab(t.id)}
              className={cn(
                "px-4 py-2 text-sm border-b-2 -mb-px",
                tab === t.id
                  ? "border-brand-600 text-brand-700 font-medium"
                  : "border-transparent text-slate-600 hover:text-slate-900"
              )}
            >
              {t.label}
            </button>
          ))}
        </nav>
      </div>

      {tab === "tokens" && <TokensTab tenantId={id} />}
      {tab === "enrollments" && <EnrollmentsTab tenantId={id} />}
      {tab === "vendors" && <VendorsTab tenantId={id} />}
      {tab === "preferences" && <PreferencesTab tenantId={id} />}
      {tab === "matches" && <MatchesTab tenantId={id} />}
    </div>
  );
}

// ── Tokens ──────────────────────────────────────────────────────────

// The full set of M2M scopes the bridge can use. A bridge typically
// holds one token with all three for unified pulls, but the operator
// CAN issue narrower tokens for separation of concerns (e.g. a
// policy-bundle-only token shared with a downstream consumer).
const AVAILABLE_SCOPES = [
  {
    name: "inventory_pull",
    label: "Inventory pull",
    description: "Bridge pulls the tenant's host inventory.",
  },
  {
    name: "cve_feed",
    label: "CVE feed",
    description: "Bridge pulls the tenant's filtered CVE feed.",
  },
  {
    name: "policy_bundle_pull",
    label: "Policy bundle pull",
    description:
      "Bridge pulls the signed OPA policy bundle and verifies the envelope.",
  },
] as const;

const DEFAULT_SCOPES = AVAILABLE_SCOPES.map((s) => s.name);

function TokensTab({ tenantId }: { tenantId: string }) {
  const qc = useQueryClient();
  const [showNew, setShowNew] = useState(false);
  const [justCreated, setJustCreated] = useState<TokenCreated | null>(null);
  const [desc, setDesc] = useState("");
  const [scopes, setScopes] = useState<string[]>([...DEFAULT_SCOPES]);

  const { data: tokens } = useQuery({
    queryKey: ["tokens", tenantId],
    queryFn: () => listTokens(tenantId, false),
  });

  const create = useMutation({
    mutationFn: () =>
      createToken(tenantId, { description: desc || null, scopes }),
    onSuccess: (t) => {
      setJustCreated(t);
      setShowNew(false);
      setDesc("");
      setScopes([...DEFAULT_SCOPES]);
      qc.invalidateQueries({ queryKey: ["tokens", tenantId] });
    },
  });

  const toggleScope = (name: string) => {
    setScopes((prev) =>
      prev.includes(name) ? prev.filter((s) => s !== name) : [...prev, name]
    );
  };

  const revoke = useMutation({
    mutationFn: (token_id: string) => revokeToken(tenantId, token_id, "revoked from operator UI"),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["tokens", tenantId] }),
  });

  return (
    <div className="space-y-4">
      {justCreated && (
        <div className="card p-4 border-green-300 bg-green-50">
          <div className="font-semibold text-green-900">Token created</div>
          <p className="text-xs text-green-800 mt-1">
            Copy the secret now — it cannot be shown again.
          </p>
          <div className="mt-3 grid grid-cols-1 gap-2 text-sm">
            <KV label="token_id" value={justCreated.token_id} />
            <KV label="token_secret" value={justCreated.token_secret} mono />
          </div>
          <button className="btn-secondary mt-3" onClick={() => setJustCreated(null)}>
            Dismiss
          </button>
        </div>
      )}

      <div className="flex justify-between">
        <h2 className="text-lg font-semibold">Active tokens</h2>
        {!showNew && (
          <button className="btn-primary" onClick={() => setShowNew(true)}>
            + Issue token
          </button>
        )}
      </div>

      {showNew && (
        <div className="card p-4 space-y-3">
          <div>
            <label className="label">Description</label>
            <input
              className="input"
              placeholder="e.g. AAC primary bridge"
              value={desc}
              onChange={(e) => setDesc(e.target.value)}
            />
          </div>
          <div>
            <label className="label">Scopes</label>
            <p className="text-xs text-slate-500 mb-2">
              All three are checked by default — a primary bridge token
              normally holds the full set. Untick to issue a narrower
              token (e.g. policy-bundle only).
            </p>
            <div className="space-y-2">
              {AVAILABLE_SCOPES.map((s) => (
                <label key={s.name} className="flex items-start gap-2">
                  <input
                    type="checkbox"
                    className="mt-1"
                    checked={scopes.includes(s.name)}
                    onChange={() => toggleScope(s.name)}
                  />
                  <span>
                    <span className="text-sm font-medium text-slate-900">
                      {s.label}
                    </span>{" "}
                    <code className="text-[11px] text-slate-500">
                      {s.name}
                    </code>
                    <span className="block text-xs text-slate-500">
                      {s.description}
                    </span>
                  </span>
                </label>
              ))}
            </div>
            {scopes.length === 0 ? (
              <p className="text-xs text-amber-700 mt-2">
                A token with no scopes can authenticate but cannot pull
                anything. Pick at least one.
              </p>
            ) : null}
          </div>
          {create.error && (
            <div className="text-sm text-red-700">{extractErr(create.error)}</div>
          )}
          <div className="flex justify-end gap-2">
            <button className="btn-secondary" onClick={() => setShowNew(false)}>
              Cancel
            </button>
            <button
              className="btn-primary"
              onClick={() => create.mutate()}
              disabled={create.isPending || scopes.length === 0}
            >
              {create.isPending ? "Creating…" : "Create token"}
            </button>
          </div>
        </div>
      )}

      <div className="card">
        {tokens && tokens.length === 0 && (
          <div className="p-4 text-sm text-slate-500">No active tokens.</div>
        )}
        {tokens && tokens.length > 0 && (
          <table className="w-full text-sm">
            <thead className="bg-slate-50 text-xs uppercase text-slate-600">
              <tr>
                <th className="text-left px-4 py-2">token_id</th>
                <th className="text-left px-4 py-2">Description</th>
                <th className="text-left px-4 py-2">Scopes</th>
                <th className="text-left px-4 py-2">Last used</th>
                <th className="text-left px-4 py-2">Created</th>
                <th></th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-200">
              {tokens.map((t) => (
                <tr key={t.id}>
                  <td className="px-4 py-2 font-mono text-xs">{t.token_id}</td>
                  <td className="px-4 py-2">{t.description ?? "—"}</td>
                  <td className="px-4 py-2 text-xs">
                    {(t.scopes ?? []).join(", ")}
                  </td>
                  <td className="px-4 py-2 text-xs text-slate-500">
                    {relTime(t.last_used_at)}
                  </td>
                  <td className="px-4 py-2 text-xs text-slate-500">
                    {relTime(t.created_at)}
                  </td>
                  <td className="px-4 py-2 text-right">
                    <button
                      className="text-xs text-red-600 hover:underline"
                      onClick={() => {
                        if (confirm(`Revoke token ${t.token_id}?`)) {
                          revoke.mutate(t.token_id);
                        }
                      }}
                    >
                      Revoke
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}

function KV({ label, value, mono = false }: { label: string; value: string; mono?: boolean }) {
  return (
    <div>
      <div className="text-xs text-slate-500">{label}</div>
      <div
        className={cn(
          "text-sm break-all",
          mono && "font-mono bg-white border border-slate-200 rounded px-2 py-1"
        )}
      >
        {value}
      </div>
    </div>
  );
}

// ── Enrollments ─────────────────────────────────────────────────────
function EnrollmentsTab({ tenantId }: { tenantId: string }) {
  const qc = useQueryClient();
  const { data: enrolls } = useQuery({
    queryKey: ["enrollments", tenantId],
    queryFn: () => listEnrollments(tenantId),
  });
  const { data: buckets } = useQuery({
    queryKey: ["buckets"],
    queryFn: () => listBuckets(),
  });

  const enrolledKeys = new Set((enrolls ?? []).map((e) => e.key));

  const enroll = useMutation({
    mutationFn: (key: string) => enrollBucket(tenantId, key),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["enrollments", tenantId] }),
  });
  const unenroll = useMutation({
    mutationFn: (key: string) => unenrollBucket(tenantId, key),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["enrollments", tenantId] }),
  });
  const pull = useMutation({ mutationFn: () => triggerInventoryPullForTenant(tenantId) });
  const match = useMutation({ mutationFn: () => triggerMatchForTenant(tenantId) });

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <p className="text-sm text-slate-600">
          Enrolled buckets define which CVE categories this tenant receives.
        </p>
        <div className="flex gap-2">
          <button
            className="btn-secondary"
            onClick={() => pull.mutate()}
            disabled={pull.isPending}
          >
            {pull.isPending ? "Pulling…" : "Trigger inventory pull"}
          </button>
          <button
            className="btn-secondary"
            onClick={() => match.mutate()}
            disabled={match.isPending}
          >
            {match.isPending ? "Matching…" : "Trigger match"}
          </button>
        </div>
      </div>

      <div className="card">
        <table className="w-full text-sm">
          <thead className="bg-slate-50 text-xs uppercase text-slate-600">
            <tr>
              <th className="text-left px-4 py-2">Bucket</th>
              <th className="text-left px-4 py-2">Type</th>
              <th className="text-right px-4 py-2">CVEs tagged</th>
              <th className="text-right px-4 py-2">Enrolled?</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-200">
            {buckets?.map((b) => {
              const on = enrolledKeys.has(b.key);
              return (
                <tr key={b.id}>
                  <td className="px-4 py-2">
                    <div className="font-medium">{b.display_name}</div>
                    <div className="text-xs text-slate-500 font-mono">{b.key}</div>
                  </td>
                  <td className="px-4 py-2 text-xs text-slate-600">{b.bucket_type}</td>
                  <td className="px-4 py-2 text-right text-slate-700">{b.cve_count}</td>
                  <td className="px-4 py-2 text-right">
                    {on ? (
                      <button
                        className="text-xs text-red-600 hover:underline"
                        onClick={() => unenroll.mutate(b.key)}
                      >
                        Remove
                      </button>
                    ) : (
                      <button
                        className="text-xs text-brand-600 hover:underline"
                        onClick={() => enroll.mutate(b.key)}
                      >
                        Enroll
                      </button>
                    )}
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
    </div>
  );
}

// ── Vendor subscriptions ─────────────────────────────────────────────
function VendorsTab({ tenantId }: { tenantId: string }) {
  const qc = useQueryClient();
  const { data: subs } = useQuery({
    queryKey: ["vendor-subs", tenantId],
    queryFn: () => listVendorSubscriptions(tenantId),
  });
  const { data: vendors } = useQuery({
    queryKey: ["vendors"],
    queryFn: () => listVendors(),
  });
  const subMap = new Map((subs ?? []).map((s) => [s.vendor_key, s]));

  const set = useMutation({
    mutationFn: ({ key, allow }: { key: string; allow: boolean }) =>
      setVendorSubscription(tenantId, key, allow),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["vendor-subs", tenantId] }),
  });
  const remove = useMutation({
    mutationFn: (key: string) => removeVendorSubscription(tenantId, key),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["vendor-subs", tenantId] }),
  });

  return (
    <div className="card">
      <table className="w-full text-sm">
        <thead className="bg-slate-50 text-xs uppercase text-slate-600">
          <tr>
            <th className="text-left px-4 py-2">Vendor</th>
            <th className="text-left px-4 py-2">Buckets</th>
            <th className="text-right px-4 py-2">CVEs tagged</th>
            <th className="text-right px-4 py-2">Subscription</th>
          </tr>
        </thead>
        <tbody className="divide-y divide-slate-200">
          {vendors?.map((v) => {
            const sub = subMap.get(v.key);
            return (
              <tr key={v.id}>
                <td className="px-4 py-2">
                  <div className="font-medium">{v.display_name}</div>
                  <div className="text-xs text-slate-500 font-mono">{v.key}</div>
                </td>
                <td className="px-4 py-2 text-xs text-slate-600">
                  {(v.buckets ?? []).join(", ") || "—"}
                </td>
                <td className="px-4 py-2 text-right">{v.cve_count}</td>
                <td className="px-4 py-2 text-right space-x-2">
                  <button
                    className={cn(
                      "text-xs",
                      sub?.allow ? "text-green-700 font-semibold" : "text-brand-600 hover:underline"
                    )}
                    onClick={() => set.mutate({ key: v.key, allow: true })}
                  >
                    Allow
                  </button>
                  <button
                    className={cn(
                      "text-xs",
                      sub && !sub.allow
                        ? "text-red-700 font-semibold"
                        : "text-slate-500 hover:underline"
                    )}
                    onClick={() => set.mutate({ key: v.key, allow: false })}
                  >
                    Block
                  </button>
                  {sub && (
                    <button
                      className="text-xs text-slate-400 hover:underline"
                      onClick={() => remove.mutate(v.key)}
                    >
                      Clear
                    </button>
                  )}
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}

// ── Preferences ──────────────────────────────────────────────────────
function PreferencesTab({ tenantId }: { tenantId: string }) {
  const qc = useQueryClient();
  const { data: prefs } = useQuery({
    queryKey: ["prefs", tenantId],
    queryFn: () => getPreferences(tenantId),
  });
  const [local, setLocal] = useState<Partial<FilterPreferences>>({});

  const merged: FilterPreferences = {
    min_severity: (local.min_severity ?? prefs?.min_severity ?? "MEDIUM") as Severity,
    deliver_kev_regardless:
      local.deliver_kev_regardless ?? prefs?.deliver_kev_regardless ?? true,
    deliver_tag_only: local.deliver_tag_only ?? prefs?.deliver_tag_only ?? false,
    auto_apply_kev: local.auto_apply_kev ?? prefs?.auto_apply_kev ?? false,
  };

  const save = useMutation({
    mutationFn: () => setPreferences(tenantId, merged),
    onSuccess: () => {
      setLocal({});
      qc.invalidateQueries({ queryKey: ["prefs", tenantId] });
    },
  });

  return (
    <div className="card p-6 space-y-5 max-w-2xl">
      <div>
        <label className="label">Minimum severity</label>
        <select
          className="input max-w-xs"
          value={merged.min_severity}
          onChange={(e) => setLocal({ ...local, min_severity: e.target.value as Severity })}
        >
          <option value="LOW">LOW</option>
          <option value="MEDIUM">MEDIUM</option>
          <option value="HIGH">HIGH</option>
          <option value="CRITICAL">CRITICAL</option>
        </select>
        <p className="text-xs text-slate-500 mt-1">
          CVEs below this severity are filtered out unless KEV pass-through applies.
        </p>
      </div>

      <Toggle
        label="Deliver KEV regardless of severity"
        on={merged.deliver_kev_regardless}
        onChange={(v) => setLocal({ ...local, deliver_kev_regardless: v })}
      />
      <Toggle
        label="Deliver only tagged CVEs (suppress raw feed)"
        on={merged.deliver_tag_only}
        onChange={(v) => setLocal({ ...local, deliver_tag_only: v })}
      />
      <Toggle
        label="Auto-apply KEV remediation (AAC will run remediation workflow)"
        on={merged.auto_apply_kev}
        onChange={(v) => setLocal({ ...local, auto_apply_kev: v })}
      />

      <div className="flex justify-end gap-2 pt-2">
        <button
          className="btn-primary"
          disabled={Object.keys(local).length === 0 || save.isPending}
          onClick={() => save.mutate()}
        >
          {save.isPending ? "Saving…" : "Save preferences"}
        </button>
      </div>
    </div>
  );
}

function Toggle({
  label,
  on,
  onChange,
}: {
  label: string;
  on: boolean;
  onChange: (v: boolean) => void;
}) {
  return (
    <div className="flex items-center justify-between">
      <span className="text-sm text-slate-700">{label}</span>
      <button
        type="button"
        onClick={() => onChange(!on)}
        className={cn(
          "relative inline-flex h-6 w-11 rounded-full transition-colors",
          on ? "bg-brand-600" : "bg-slate-300"
        )}
      >
        <span
          className={cn(
            "inline-block h-5 w-5 transform rounded-full bg-white shadow transition-transform mt-0.5",
            on ? "translate-x-5" : "translate-x-1"
          )}
        />
      </button>
    </div>
  );
}

// ── Matches ──────────────────────────────────────────────────────────
function MatchesTab({ tenantId }: { tenantId: string }) {
  const [sev, setSev] = useState<Severity | "">("");
  const [kev, setKev] = useState(false);

  const { data: matches, isLoading } = useQuery({
    queryKey: ["matches", tenantId, sev, kev],
    queryFn: () =>
      listMatches(tenantId, {
        severity: sev || undefined,
        kev_only: kev || undefined,
        limit: 200,
      }),
  });

  return (
    <div className="space-y-4">
      <div className="flex items-center gap-3 text-sm">
        <select
          className="input max-w-xs"
          value={sev}
          onChange={(e) => setSev(e.target.value as Severity | "")}
        >
          <option value="">All severities</option>
          <option value="CRITICAL">CRITICAL</option>
          <option value="HIGH">HIGH</option>
          <option value="MEDIUM">MEDIUM</option>
          <option value="LOW">LOW</option>
        </select>
        <label className="flex items-center gap-2 text-slate-700">
          <input
            type="checkbox"
            checked={kev}
            onChange={(e) => setKev(e.target.checked)}
          />
          KEV only
        </label>
      </div>

      <div className="card">
        {isLoading && <div className="p-4 text-slate-500">Loading…</div>}
        {matches && matches.length === 0 && (
          <div className="p-4 text-sm text-slate-500">No matches for this filter.</div>
        )}
        {matches && matches.length > 0 && (
          <table className="w-full text-sm">
            <thead className="bg-slate-50 text-xs uppercase text-slate-600">
              <tr>
                <th className="text-left px-4 py-2">CVE</th>
                <th className="text-left px-4 py-2">Severity</th>
                <th className="text-left px-4 py-2">KEV</th>
                <th className="text-left px-4 py-2">Matched</th>
                <th className="text-left px-4 py-2">State</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-200">
              {matches.map((m) => (
                <tr key={m.cve_id}>
                  <td className="px-4 py-2 font-mono text-xs">{m.cve_id}</td>
                  <td className="px-4 py-2">
                    <span className={`badge ${severityColor(m.cvss_v3_severity)}`}>
                      {m.cvss_v3_severity ?? "—"}{" "}
                      {m.cvss_v3 != null && `(${m.cvss_v3})`}
                    </span>
                  </td>
                  <td className="px-4 py-2 text-xs">{m.kev_member ? "yes" : "—"}</td>
                  <td className="px-4 py-2 text-xs text-slate-500">
                    {relTime(m.matched_at)}
                  </td>
                  <td className="px-4 py-2 text-xs">
                    {m.suppressed_at
                      ? "suppressed"
                      : m.acknowledged_at
                      ? "acknowledged"
                      : m.delivered_at
                      ? "delivered"
                      : "new"}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}
