import { describe, expect, it, vi, beforeEach, afterEach } from "vitest";
import { render, screen, waitFor, fireEvent } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";

// vi.mock must come BEFORE importing the component under test —
// otherwise the page captures the real api module and the mocks are
// silently no-ops. Vitest hoists vi.mock calls, but the import order
// is the readable contract; mirror other portal page tests.
vi.mock("../lib/api", () => ({
  userHostMappingsList: vi.fn(),
  userHostMappingCreate: vi.fn(),
  userHostMappingDelete: vi.fn(),
}));

import PortalHostMappingsPage from "./PortalHostMappingsPage";
import {
  userHostMappingCreate,
  userHostMappingDelete,
  userHostMappingsList,
} from "../lib/api";

const renderPage = () =>
  render(
    <MemoryRouter>
      <PortalHostMappingsPage />
    </MemoryRouter>,
  );

// Preserve + restore window.confirm so stub from one test can't leak
// into the next worker run.
const originalConfirm = window.confirm;

beforeEach(() => {
  vi.clearAllMocks();
  // Default: no rows, no errors
  (userHostMappingsList as ReturnType<typeof vi.fn>).mockResolvedValue([]);
});

afterEach(() => {
  window.confirm = originalConfirm;
});

describe("PortalHostMappingsPage", () => {
  it("shows empty-state copy when no mappings exist", async () => {
    renderPage();
    await waitFor(() => {
      expect(
        screen.getByText(/No host mappings configured yet/i),
      ).toBeInTheDocument();
    });
  });

  it("renders existing rows with hostname + framework", async () => {
    (userHostMappingsList as ReturnType<typeof vi.fn>).mockResolvedValue([
      {
        id: "row-1",
        tenant_id: "t-1",
        hostname: "host-a.example",
        framework: "cis_rhel9",
        created_at: "2026-06-08T00:00:00Z",
        created_by: null,
      },
      {
        id: "row-2",
        tenant_id: "t-1",
        hostname: "host-b.example",
        framework: null,
        created_at: "2026-06-08T01:00:00Z",
        created_by: null,
      },
    ]);

    renderPage();

    await waitFor(() => {
      expect(screen.getByText("host-a.example")).toBeInTheDocument();
      expect(screen.getByText("host-b.example")).toBeInTheDocument();
      expect(screen.getByText("cis_rhel9")).toBeInTheDocument();
      // null framework rendered as "all frameworks"
      expect(screen.getByText("all frameworks")).toBeInTheDocument();
    });
  });

  it("posts a new mapping when the form is submitted", async () => {
    (userHostMappingCreate as ReturnType<typeof vi.fn>).mockResolvedValue({
      id: "new-1",
      tenant_id: "t-1",
      hostname: "new-host.example",
      framework: null,
      created_at: "2026-06-08T02:00:00Z",
      created_by: null,
    });

    renderPage();

    await waitFor(() =>
      expect(
        screen.getByText(/No host mappings configured yet/i),
      ).toBeInTheDocument(),
    );

    fireEvent.change(screen.getByPlaceholderText("host.example"), {
      target: { value: "new-host.example" },
    });
    fireEvent.click(screen.getByRole("button", { name: /Add mapping/ }));

    await waitFor(() => {
      expect(userHostMappingCreate).toHaveBeenCalledWith({
        hostname: "new-host.example",
        framework: null,
      });
    });
  });

  it("displays an error when create fails", async () => {
    (userHostMappingCreate as ReturnType<typeof vi.fn>).mockRejectedValue({
      response: { status: 409, data: { detail: "mapping for ... already exists" } },
    });

    renderPage();
    await waitFor(() =>
      expect(
        screen.getByText(/No host mappings configured yet/i),
      ).toBeInTheDocument(),
    );

    fireEvent.change(screen.getByPlaceholderText("host.example"), {
      target: { value: "dup.example" },
    });
    fireEvent.click(screen.getByRole("button", { name: /Add mapping/ }));

    await waitFor(() => {
      expect(screen.getByText(/already exists/)).toBeInTheDocument();
    });
  });

  it("calls delete and reloads when user confirms", async () => {
    (userHostMappingsList as ReturnType<typeof vi.fn>).mockResolvedValueOnce([
      {
        id: "row-1",
        tenant_id: "t-1",
        hostname: "to-delete.example",
        framework: null,
        created_at: "2026-06-08T00:00:00Z",
        created_by: null,
      },
    ]);
    (userHostMappingDelete as ReturnType<typeof vi.fn>).mockResolvedValue(undefined);
    // After delete, reload returns empty
    (userHostMappingsList as ReturnType<typeof vi.fn>).mockResolvedValueOnce([]);

    // Stub window.confirm so the click goes through
    window.confirm = vi.fn().mockReturnValue(true);

    renderPage();
    await waitFor(() =>
      expect(screen.getByText("to-delete.example")).toBeInTheDocument(),
    );

    fireEvent.click(screen.getByTestId("delete-row-1"));

    await waitFor(() => {
      expect(userHostMappingDelete).toHaveBeenCalledWith("row-1");
    });
  });

  it("does NOT call delete if confirm is cancelled", async () => {
    (userHostMappingsList as ReturnType<typeof vi.fn>).mockResolvedValueOnce([
      {
        id: "row-1",
        tenant_id: "t-1",
        hostname: "stays.example",
        framework: null,
        created_at: "2026-06-08T00:00:00Z",
        created_by: null,
      },
    ]);
    window.confirm = vi.fn().mockReturnValue(false);

    renderPage();
    await waitFor(() =>
      expect(screen.getByText("stays.example")).toBeInTheDocument(),
    );

    fireEvent.click(screen.getByTestId("delete-row-1"));
    expect(userHostMappingDelete).not.toHaveBeenCalled();
  });
});
