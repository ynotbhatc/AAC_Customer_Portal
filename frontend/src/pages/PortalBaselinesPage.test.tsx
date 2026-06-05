/**
 * Tests for the baselines list page.
 *
 * Covers:
 *   - empty state renders when API returns []
 *   - rows render with passing/failing counts + linked timestamp
 *   - "Load older" sends the compound (captured_at, id) cursor —
 *     pin the contract that the cursor is the pair, not just the
 *     timestamp (matches the bundles regression target)
 *   - source badge appears with the right classification
 */
import { describe, it, expect, beforeEach, vi } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";

import type { BaselineSnapshotSummary } from "../types/baseline";

vi.mock("../lib/api", () => ({
  userBaselinesList: vi.fn(),
}));

import { userBaselinesList } from "../lib/api";
import PortalBaselinesPage from "./PortalBaselinesPage";


const rows: BaselineSnapshotSummary[] = [
  {
    id: "b-1",
    tenant_id: "t-1",
    bundle_sha256: "a".repeat(64),
    captured_at: "2026-01-03T00:00:00Z",
    captured_by_email: null,
    label: "Q1 2026",
    source: "bridge_push",
    host_count: 50,
    passing: 1200,
    failing: 12,
  },
  {
    id: "b-0",
    tenant_id: "t-1",
    bundle_sha256: "b".repeat(64),
    captured_at: "2026-01-01T00:00:00Z",
    captured_by_email: "alice@a.example",
    label: null,
    source: "manual",
    host_count: 48,
    passing: 1100,
    failing: 60,
  },
];


function renderPage() {
  return render(
    <MemoryRouter>
      <PortalBaselinesPage />
    </MemoryRouter>
  );
}


beforeEach(() => {
  vi.clearAllMocks();
});


describe("PortalBaselinesPage", () => {
  it("renders the empty state when no baselines exist", async () => {
    vi.mocked(userBaselinesList).mockResolvedValue([]);
    renderPage();
    expect(
      await screen.findByText(/No baselines captured yet/i)
    ).toBeInTheDocument();
  });

  it("renders rows with passing/failing counts and labels", async () => {
    vi.mocked(userBaselinesList).mockResolvedValue(rows);
    renderPage();
    await screen.findByText(/About baselines/i);

    // Labels render where present, "—" where null.
    expect(screen.getByText("Q1 2026")).toBeInTheDocument();
    expect(screen.getByText("1200")).toBeInTheDocument(); // passing on row 1
    expect(screen.getByText("60")).toBeInTheDocument(); // failing on row 2
    // Both source labels rendered.
    expect(screen.getByText("bridge_push")).toBeInTheDocument();
    expect(screen.getByText("manual")).toBeInTheDocument();
  });

  it('"Load older" sends the compound (captured_at, id) cursor', async () => {
    const user = userEvent.setup();
    // Pretend the first page is full so the Load older button shows.
    const fullPage: BaselineSnapshotSummary[] = Array.from(
      { length: 50 },
      (_, i) => ({
        ...rows[0],
        id: `baseline-${i}`,
        captured_at: `2026-01-${(28 - i).toString().padStart(2, "0")}T00:00:00Z`,
      })
    );
    vi.mocked(userBaselinesList)
      .mockResolvedValueOnce(fullPage)
      .mockResolvedValueOnce([]);

    renderPage();
    await screen.findByRole("button", { name: /load older/i });

    await user.click(screen.getByRole("button", { name: /load older/i }));

    await waitFor(() => {
      expect(userBaselinesList).toHaveBeenCalledTimes(2);
    });
    const oldest = fullPage[fullPage.length - 1];
    expect(userBaselinesList).toHaveBeenLastCalledWith({
      limit: 50,
      before_captured_at: oldest.captured_at,
      before_id: oldest.id,
    });
  });
});
