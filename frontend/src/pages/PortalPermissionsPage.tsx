import { useEffect, useState } from "react";
import { Link } from "react-router-dom";

import { userPermissionsGet } from "../lib/api";
import { extractErr } from "../lib/utils";
import type {
  PermissionsResponse,
  PermissionUser,
  RoleCapability,
} from "../types/permissions";

/**
 * Permission audit — who has what role inside this tenant.
 *
 * Read-only for every tenant role. The data is strictly tenant-
 * scoped on the backend; this page never sees rows from another
 * tenant. The caller's own row is highlighted via `self=true`.
 *
 * Renders two sections:
 *   - Roster: tenant_users + their roles
 *   - Capability matrix: what each role is gated to do, sourced from
 *     the static catalog in api/src/routers/permissions.py
 */
export default function PortalPermissionsPage() {
  const [data, setData] = useState<PermissionsResponse | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    let cancelled = false;
    userPermissionsGet()
      .then((d) => {
        if (!cancelled) setData(d);
      })
      .catch((e) => {
        if (!cancelled) setErr(extractErr(e));
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, []);

  return (
    <div className="container py-6 space-y-6">
      <div>
        <Link to="/portal" className="text-sm text-blue-600 hover:underline">
          ← Back to portal
        </Link>
        <h1 className="text-2xl font-semibold mt-2">Permissions</h1>
        <p className="text-sm text-slate-500 mt-1">
          Who has what role inside this tenant. Read-only; ask an account owner
          to make changes.
        </p>
      </div>

      {loading ? <div className="text-sm text-slate-500">Loading…</div> : null}
      {err ? <div className="text-sm text-red-600">{err}</div> : null}

      {data ? (
        <>
          <UsersTable users={data.users} />
          <CapabilityMatrix roles={data.roles} />
        </>
      ) : null}
    </div>
  );
}


function UsersTable({ users }: { users: PermissionUser[] }) {
  return (
    <section className="card p-4">
      <h2 className="font-semibold mb-3">Users</h2>
      {users.length === 0 ? (
        <p className="text-sm text-slate-500">No users in this tenant.</p>
      ) : (
        <table className="w-full text-sm">
          <thead className="text-left text-xs uppercase text-slate-500">
            <tr>
              <th className="py-2 pr-3">Email</th>
              <th className="py-2 pr-3">Display name</th>
              <th className="py-2 pr-3">Role</th>
            </tr>
          </thead>
          <tbody>
            {users.map((u) => (
              <tr
                key={u.tenant_user_id}
                className={u.self ? "bg-blue-50" : ""}
                data-testid={u.self ? "row-self" : "row-other"}
              >
                <td className="py-2 pr-3 font-mono text-xs">
                  {u.email}
                  {u.self ? (
                    <span className="ml-2 text-[10px] uppercase tracking-wide text-blue-700">
                      you
                    </span>
                  ) : null}
                </td>
                <td className="py-2 pr-3">{u.display_name || "—"}</td>
                <td className="py-2 pr-3">
                  <RoleBadge role={u.role} />
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </section>
  );
}


function RoleBadge({ role }: { role: PermissionUser["role"] }) {
  const cls =
    role === "account_owner"
      ? "bg-purple-100 text-purple-800"
      : role === "editor"
      ? "bg-emerald-100 text-emerald-800"
      : "bg-slate-100 text-slate-700";
  return (
    <code className={`inline-block text-xs font-mono px-2 py-0.5 rounded ${cls}`}>
      {role}
    </code>
  );
}


function CapabilityMatrix({ roles }: { roles: RoleCapability[] }) {
  return (
    <section className="card p-4">
      <h2 className="font-semibold mb-3">Role capabilities</h2>
      <p className="text-xs text-slate-500 mb-3">
        Each role inherits all capabilities of the roles below it. Capabilities
        are listed where they are first added.
      </p>
      <div className="space-y-4">
        {roles.map((r) => (
          <div key={r.name}>
            <div className="flex items-baseline gap-2">
              <RoleBadge role={r.name} />
              <p className="text-sm text-slate-700">{r.description}</p>
            </div>
            <ul className="list-disc list-inside text-sm text-slate-600 mt-1 ml-4">
              {r.capabilities.map((c) => (
                <li key={c}>{c}</li>
              ))}
            </ul>
          </div>
        ))}
      </div>
    </section>
  );
}
