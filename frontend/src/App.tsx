import { Navigate, Route, Routes } from "react-router-dom";
import { useState, useEffect } from "react";
import Layout from "./components/Layout";
import LoginPage from "./pages/LoginPage";
import DashboardPage from "./pages/DashboardPage";
import TenantsPage from "./pages/TenantsPage";
import TenantDetailPage from "./pages/TenantDetailPage";
import FeedsPage from "./pages/FeedsPage";
import CvesPage from "./pages/CvesPage";
import TaxonomyPage from "./pages/TaxonomyPage";
import MyProductsPage from "./pages/MyProductsPage";
import TenantLoginPage from "./pages/TenantLoginPage";
import PortalLoginPage from "./pages/PortalLoginPage";
import PortalResetPasswordPage from "./pages/PortalResetPasswordPage";
import PortalHomePage from "./pages/PortalHomePage";
import { getAdminToken, getUserSession } from "./lib/auth";

const RequireAdmin = ({ children }: { children: React.ReactNode }) => {
  const [authed, setAuthed] = useState<boolean>(Boolean(getAdminToken()));
  useEffect(() => {
    // Re-check on tab focus / storage events so a parallel-tab logout
    // doesn't leave this tab in a half-authed state.
    const onStorage = () => setAuthed(Boolean(getAdminToken()));
    window.addEventListener("storage", onStorage);
    return () => window.removeEventListener("storage", onStorage);
  }, []);
  if (!authed) return <Navigate to="/login" replace />;
  return <>{children}</>;
};

const RequirePortalUser = ({ children }: { children: React.ReactNode }) => {
  const [authed, setAuthed] = useState<boolean>(Boolean(getUserSession()));
  useEffect(() => {
    const onStorage = () => setAuthed(Boolean(getUserSession()));
    window.addEventListener("storage", onStorage);
    return () => window.removeEventListener("storage", onStorage);
  }, []);
  if (!authed) return <Navigate to="/portal/login" replace />;
  return <>{children}</>;
};

export default function App() {
  return (
    <Routes>
      <Route path="/login" element={<LoginPage />} />
      <Route path="/my-products/login" element={<TenantLoginPage />} />
      <Route path="/my-products" element={<MyProductsPage />} />

      {/* Policy ingestion portal — tenant_user session auth (PR 15+) */}
      <Route path="/portal/login" element={<PortalLoginPage />} />
      <Route
        path="/portal/reset-password"
        element={<PortalResetPasswordPage />}
      />
      <Route
        path="/portal/me"
        element={
          <RequirePortalUser>
            <PortalHomePage />
          </RequirePortalUser>
        }
      />

      <Route
        path="/"
        element={
          <RequireAdmin>
            <Layout />
          </RequireAdmin>
        }
      >
        <Route index element={<DashboardPage />} />
        <Route path="tenants" element={<TenantsPage />} />
        <Route path="tenants/:id" element={<TenantDetailPage />} />
        <Route path="feeds" element={<FeedsPage />} />
        <Route path="cves" element={<CvesPage />} />
        <Route path="taxonomy" element={<TaxonomyPage />} />
      </Route>

      <Route path="*" element={<Navigate to="/" replace />} />
    </Routes>
  );
}
