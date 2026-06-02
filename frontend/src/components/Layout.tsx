import { NavLink, Outlet, useNavigate } from "react-router-dom";
import { clearAdminToken } from "../lib/auth";
import { cn } from "../lib/utils";

const nav = [
  { to: "/", label: "Dashboard", end: true },
  { to: "/tenants", label: "Tenants" },
  { to: "/feeds", label: "Feeds & CVE ingest" },
  { to: "/cves", label: "CVE browser" },
  { to: "/taxonomy", label: "Buckets & Vendors" },
];

export default function Layout() {
  const navigate = useNavigate();
  const onLogout = () => {
    clearAdminToken();
    navigate("/login", { replace: true });
  };

  return (
    <div className="min-h-screen flex">
      <aside className="w-60 bg-slate-900 text-slate-200 flex flex-col">
        <div className="px-5 py-5 border-b border-slate-700">
          <div className="font-semibold text-white">AAC Portal</div>
          <div className="text-xs text-slate-400">Operator console</div>
        </div>
        <nav className="flex-1 px-3 py-4 space-y-1">
          {nav.map((n) => (
            <NavLink
              key={n.to}
              to={n.to}
              end={n.end}
              className={({ isActive }) =>
                cn(
                  "block rounded px-3 py-2 text-sm transition-colors",
                  isActive
                    ? "bg-brand-600 text-white"
                    : "text-slate-300 hover:bg-slate-800 hover:text-white"
                )
              }
            >
              {n.label}
            </NavLink>
          ))}
        </nav>
        <div className="px-3 py-4 border-t border-slate-700 space-y-2">
          <NavLink
            to="/my-products"
            className="block text-xs text-slate-400 hover:text-white px-3"
          >
            → Tenant view (My Products)
          </NavLink>
          <button
            onClick={onLogout}
            className="w-full text-left text-xs text-slate-400 hover:text-white px-3 py-1"
          >
            Sign out
          </button>
        </div>
      </aside>

      <main className="flex-1 bg-slate-50">
        <div className="max-w-7xl mx-auto px-6 py-8">
          <Outlet />
        </div>
      </main>
    </div>
  );
}
