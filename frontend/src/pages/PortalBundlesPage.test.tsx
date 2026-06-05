/**
 * Tests for the bundles overview page.
 *
 * Covers:
 *   - empty state when `/me/bundles/current/manifest` returns 404
 *   - Build → builds + refetches current + history
 *   - history table renders rows + marks the current row via the
 *     `current` pill
 *   - the "current" pill detection is sha-based, not index-based
 *     (regression target — the prior implementation also required
 *     idx === 0 and would lose the pill if the row drifted off
 *     page 1 of pagination)
 *   - "Load older" passes the compound (built_at, bundle_id) cursor
 *
 * api lib is fully mocked.
 */
import { describe, it, expect, beforeEach, vi } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";

import type {
  BundleHistoryEntry,
  BundleManifest,
} from "../types/bundle";

vi.mock("../lib/api", () => ({
  userBundleBuild: vi.fn(),
  userBundleCurrentManifest: vi.fn(),
  userBundleHistory: vi.fn(),
}));

import {
  userBundleBuild,
  userBundleCurrentManifest,
  userBundleHistory,
} from "../lib/api";
import PortalBundlesPage from "./PortalBundlesPage";


const manifest: BundleManifest = {
  bundle_id: "b-1",
  tenant_id: "t-1",
  bundle_sha256: "a".repeat(64),
  bundle_byte_size: 4096,
  target_count: 3,
  customer_policy_ids: ["p-1", "p-2"],
  excluded_target_count: 0,
  excluded_targets_log: [],
  built_at: "2026-01-02T00:00:00Z",
  signing_key_id: "key-1",
  manifest: { hello: "world" },
};

const history: BundleHistoryEntry[] = [
  {
    bundle_id: "b-1",
    bundle_sha256: "a".repeat(64),
    bundle_byte_size: 4096,
    target_count: 3,
    excluded_target_count: 0,
    built_at: "2026-01-02T00:00:00Z",
    signing_key_id: "key-1",
    built_by_email: "alice@a.example",
  },
  {
    bundle_id: "b-0",
    bundle_sha256: "b".repeat(64),
    bundle_byte_size: 2048,
    target_count: 2,
    excluded_target_count: 1,
    built_at: "2026-01-01T00:00:00Z",
    signing_key_id: "key-1",
    built_by_email: "alice@a.example",
  },
];


function renderPage() {
  return render(
    <MemoryRouter>
      <PortalBundlesPage />
    </MemoryRouter>
  );
}


beforeEach(() => {
  vi.clearAllMocks();
});


describe("PortalBundlesPage", () => {
  it("shows the empty state when no bundle has been built", async () => {
    vi.mocked(userBundleCurrentManifest).mockRejectedValue({
      response: { status: 404 },
    });
    vi.mocked(userBundleHistory).mockResolvedValue([]);

    renderPage();

    expect(
      await screen.findByText(/No bundle has been built for this tenant yet/i)
    ).toBeInTheDocument();
    // The Build button is always present, but no current-bundle card.
    expect(
      screen.getByRole("button", { name: /build bundle/i })
    ).toBeInTheDocument();
    expect(screen.queryByText(/Current bundle/i)).not.toBeInTheDocument();
  });

  it("renders the current bundle metadata and history when present", async () => {
    vi.mocked(userBundleCurrentManifest).mockResolvedValue(manifest);
    vi.mocked(userBundleHistory).mockResolvedValue(history);

    renderPage();

    expect(await screen.findByText(/Current bundle/i)).toBeInTheDocument();
    expect(screen.getByText(/key-1/)).toBeInTheDocument();
    expect(screen.getByText(/2 policies/)).toBeInTheDocument();

    // History table renders one row per entry; the most recent
    // (matching sha) gets a "current" pill. Both rows show
    // alice@a.example so getAllByText is the right matcher.
    expect(screen.getAllByText(/current/i).length).toBeGreaterThan(0);
    expect(screen.getAllByText(/alice@a\.example/).length).toBe(2);
  });

  it('marks the row matching the current sha with the "current" pill, regardless of position', async () => {
    // Three history entries where the *third* (oldest) matches the
    // current sha. The pill should still appear on the matching row,
    // even though it's not idx === 0 — regression target for the prior
    // implementation that also required idx === 0.
    const oldCurrent: BundleHistoryEntry = {
      ...history[1],
      bundle_id: "b-oldcur",
      bundle_sha256: "c".repeat(64),
      built_at: "2025-12-31T00:00:00Z",
    };
    const manifestOldCurrent: BundleManifest = {
      ...manifest,
      bundle_id: "b-oldcur",
      bundle_sha256: "c".repeat(64),
      built_at: "2025-12-31T00:00:00Z",
    };

    vi.mocked(userBundleCurrentManifest).mockResolvedValue(manifestOldCurrent);
    vi.mocked(userBundleHistory).mockResolvedValue([
      history[0],
      history[1],
      oldCurrent,
    ]);

    renderPage();
    await screen.findByText(/Current bundle/i);

    // Find the row containing the oldest sha and assert it carries
    // the current pill.
    expect(
      await screen.findByText("current", { selector: "span" })
    ).toBeInTheDocument();
  });

  it("Build → calls build + refetches manifest + history", async () => {
    const user = userEvent.setup();
    vi.mocked(userBundleCurrentManifest).mockResolvedValue(manifest);
    vi.mocked(userBundleHistory).mockResolvedValue([history[1]]);
    vi.mocked(userBundleBuild).mockResolvedValue({
      bundle_id: "b-2",
      bundle_sha256: "d".repeat(64),
      bundle_byte_size: 5000,
      target_count: 4,
      excluded_target_count: 0,
      customer_policy_ids: ["p-1"],
      built_at: "2026-01-03T00:00:00Z",
      signing_key_id: "key-1",
    });

    renderPage();
    await screen.findByText(/Current bundle/i);

    await user.click(screen.getByRole("button", { name: /build bundle/i }));

    await waitFor(() => {
      expect(userBundleBuild).toHaveBeenCalledTimes(1);
    });
    // Build is followed by a refetch of both manifest and history.
    await waitFor(() => {
      expect(userBundleCurrentManifest).toHaveBeenCalledTimes(2);
      expect(userBundleHistory).toHaveBeenCalledTimes(2);
    });
  });

  it('"Load older" sends the compound (built_at, bundle_id) cursor', async () => {
    const user = userEvent.setup();
    // Pretend the first page is full so the Load older button shows.
    const fullPage = Array.from({ length: 50 }, (_, i) => ({
      ...history[0],
      bundle_id: `bundle-${i}`,
      bundle_sha256: `${i.toString(16).padStart(2, "0")}`.repeat(32),
      built_at: `2026-01-${(28 - i).toString().padStart(2, "0")}T00:00:00Z`,
    }));
    vi.mocked(userBundleCurrentManifest).mockResolvedValue(manifest);
    vi.mocked(userBundleHistory)
      .mockResolvedValueOnce(fullPage)
      .mockResolvedValueOnce([]);

    renderPage();
    await screen.findByText(/Current bundle/i);
    await screen.findByRole("button", { name: /load older/i });

    await user.click(screen.getByRole("button", { name: /load older/i }));

    await waitFor(() => {
      expect(userBundleHistory).toHaveBeenCalledTimes(2);
    });
    // Second call should include the cursor from the oldest entry of
    // page 1 — both built_at AND bundle_id, not just the timestamp.
    const oldest = fullPage[fullPage.length - 1];
    expect(userBundleHistory).toHaveBeenLastCalledWith({
      limit: 50,
      before_built_at: oldest.built_at,
      before_id: oldest.bundle_id,
    });
  });
});
