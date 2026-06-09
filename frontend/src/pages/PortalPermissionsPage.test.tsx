/**
 * Permission audit page tests. Pins the rendered shape against the
 * api contract in api/src/routers/permissions.py.
 */
import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";

import type { PermissionsResponse } from "../types/permissions";

vi.mock("../lib/api", () => ({
  userPermissionsGet: vi.fn(),
}));

import { userPermissionsGet } from "../lib/api";
import PortalPermissionsPage from "./PortalPermissionsPage";


const fixture: PermissionsResponse = {
  users: [
    {
      tenant_user_id: "u-owner",
      email: "owner@a.example",
      display_name: "A Owner",
      role: "account_owner",
      self: false,
    },
    {
      tenant_user_id: "u-editor",
      email: "editor@a.example",
      display_name: "A Editor",
      role: "editor",
      self: true,
    },
    {
      tenant_user_id: "u-viewer",
      email: "viewer@a.example",
      display_name: null,
      role: "viewer",
      self: false,
    },
  ],
  roles: [
    {
      name: "viewer",
      description: "Read-only.",
      capabilities: ["Read policies"],
    },
    {
      name: "editor",
      description: "Mutate policies + bundles + baselines + AAP + remediation.",
      capabilities: ["Upload policies", "Publish targets"],
    },
    {
      name: "account_owner",
      description: "Tenant admin.",
      capabilities: ["Manage host mappings"],
    },
  ],
};


function renderPage() {
  return render(
    <MemoryRouter>
      <PortalPermissionsPage />
    </MemoryRouter>
  );
}


describe("PortalPermissionsPage", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("renders all three users with their roles", async () => {
    vi.mocked(userPermissionsGet).mockResolvedValue(fixture);
    renderPage();
    await waitFor(() => {
      expect(screen.getByText("owner@a.example")).toBeInTheDocument();
    });
    expect(screen.getByText("editor@a.example")).toBeInTheDocument();
    expect(screen.getByText("viewer@a.example")).toBeInTheDocument();
  });

  it("highlights the caller's row with self=true", async () => {
    vi.mocked(userPermissionsGet).mockResolvedValue(fixture);
    renderPage();
    await waitFor(() => {
      expect(screen.getByTestId("row-self")).toBeInTheDocument();
    });
    // The caller-row contains the editor email; the others are "other" rows.
    expect(screen.getByTestId("row-self").textContent).toContain(
      "editor@a.example"
    );
    expect(screen.getAllByTestId("row-other")).toHaveLength(2);
  });

  it("renders the role capability matrix", async () => {
    vi.mocked(userPermissionsGet).mockResolvedValue(fixture);
    renderPage();
    await waitFor(() => {
      expect(screen.getByText(/Role capabilities/i)).toBeInTheDocument();
    });
    expect(screen.getByText("Upload policies")).toBeInTheDocument();
    expect(screen.getByText("Manage host mappings")).toBeInTheDocument();
    expect(screen.getByText("Read policies")).toBeInTheDocument();
  });

  it("shows an error message when the API fails", async () => {
    vi.mocked(userPermissionsGet).mockRejectedValue(
      new Error("backend exploded")
    );
    renderPage();
    await waitFor(() => {
      expect(screen.getByText(/backend exploded/i)).toBeInTheDocument();
    });
  });

  it("shows '—' for users with no display name", async () => {
    vi.mocked(userPermissionsGet).mockResolvedValue(fixture);
    renderPage();
    await waitFor(() => {
      expect(screen.getByText("viewer@a.example")).toBeInTheDocument();
    });
    // The viewer row has display_name=null → "—" cell.
    expect(screen.getAllByText("—").length).toBeGreaterThanOrEqual(1);
  });
});
