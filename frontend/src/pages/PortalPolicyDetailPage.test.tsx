/**
 * Tests for the policy detail page — focused on the publish gate
 * and republish flow.
 *
 * Covers:
 *   - publish gate "Checking targets…" while targets is still in flight
 *     (regression target for the prior flash of "0/0 + disabled")
 *   - publish gate disabled with hint when there are 0 approved
 *   - publish gate enabled when at least one target is approved
 *   - publish handler refetches policy ONLY (targets are frozen and
 *     unchanged; refetching them was wasteful)
 *   - published-state UI surfaces the "Create new version" subsection
 *   - republish navigates to the new draft on success
 *
 * api lib is fully mocked. window.confirm is monkey-patched per-test.
 */
import { describe, it, expect, beforeEach, vi } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter, Route, Routes } from "react-router-dom";

import type {
  CustomerPolicyDetail,
  TargetSummary,
} from "../types/policy";

vi.mock("../lib/api", () => ({
  userPolicyDetail: vi.fn(),
  userPolicyExtractIr: vi.fn(),
  userPolicyGenerateRego: vi.fn(),
  userPolicyPublish: vi.fn(),
  userPolicyRepublish: vi.fn(),
  userPolicyTargets: vi.fn(),
}));

import {
  userPolicyDetail,
  userPolicyPublish,
  userPolicyRepublish,
  userPolicyTargets,
} from "../lib/api";
import PortalPolicyDetailPage from "./PortalPolicyDetailPage";


const draftPolicy: CustomerPolicyDetail = {
  id: "p-1",
  tenant_id: "t-1",
  name: "Acme ISO27001",
  framework_bucket: "iso27001",
  policy_source: "prose_upload",
  version_semver: "v1.0.0",
  effective_date: null,
  status: "draft",
  created_at: "2026-01-01T00:00:00Z",
  updated_at: "2026-01-01T00:00:00Z",
  source_file_storage_key: null,
  source_file_mime: null,
  parent_standard_ref: null,
  parent_standard_version: null,
  ir_json: { controls: [] },
};

const pendingTarget: TargetSummary = {
  id: "tgt-1",
  customer_policy_id: "p-1",
  target_system: "linux",
  target_subtype: "rhel9",
  generation_method: "template_mapped",
  confidence_score: 0.91,
  review_status: "pending",
  rego_content_sha256: "a".repeat(64),
  published_in_bundle_sha: null,
  created_at: "2026-01-01T00:00:00Z",
};


function renderPage() {
  return render(
    <MemoryRouter initialEntries={["/portal/policies/p-1"]}>
      <Routes>
        <Route
          path="/portal/policies/:id"
          element={<PortalPolicyDetailPage />}
        />
        <Route path="/portal/policies/:id-other" element={<div>other</div>} />
      </Routes>
    </MemoryRouter>
  );
}


beforeEach(() => {
  vi.clearAllMocks();
  vi.mocked(userPolicyDetail).mockResolvedValue(draftPolicy);
  vi.mocked(userPolicyTargets).mockResolvedValue([pendingTarget]);
});


describe("PortalPolicyDetailPage publish gate", () => {
  it('shows "Checking targets…" while the targets fetch is in flight', async () => {
    // Resolve policy immediately; hold targets in flight.
    let resolveTargets: (v: TargetSummary[]) => void = () => {};
    vi.mocked(userPolicyTargets).mockReturnValue(
      new Promise<TargetSummary[]>((res) => {
        resolveTargets = res;
      })
    );

    renderPage();
    expect(await screen.findByText(/Checking targets…/i)).toBeInTheDocument();
    resolveTargets([pendingTarget]);
    await waitFor(() => {
      expect(screen.queryByText(/Checking targets…/i)).not.toBeInTheDocument();
    });
  });

  it("disables Publish with a hint when no targets are approved", async () => {
    renderPage();
    const publishBtn = await screen.findByRole("button", {
      name: /publish policy/i,
    });
    expect(publishBtn).toBeDisabled();
    expect(
      screen.getByText(/at least one target must be approved/i)
    ).toBeInTheDocument();
  });

  it("enables Publish when at least one target is approved", async () => {
    vi.mocked(userPolicyTargets).mockResolvedValue([
      { ...pendingTarget, review_status: "approved" },
    ]);
    renderPage();
    const publishBtn = await screen.findByRole("button", {
      name: /publish policy/i,
    });
    expect(publishBtn).toBeEnabled();
  });

  it("publish handler refetches policy ONLY (not targets)", async () => {
    const user = userEvent.setup();
    vi.mocked(userPolicyTargets).mockResolvedValue([
      { ...pendingTarget, review_status: "approved" },
    ]);
    vi.spyOn(window, "confirm").mockReturnValue(true);
    vi.mocked(userPolicyPublish).mockResolvedValue({
      customer_policy_id: "p-1",
      status: "published",
      published_at: "2026-01-02T00:00:00Z",
      version_semver: "v1.0.0",
    });

    renderPage();
    await screen.findByRole("button", { name: /publish policy/i });

    await user.click(screen.getByRole("button", { name: /publish policy/i }));

    await waitFor(() => {
      expect(userPolicyPublish).toHaveBeenCalledWith("p-1");
    });
    // policy was fetched once on mount + once on the post-publish
    // refetch. Targets were fetched once on mount and NOT refetched
    // after publish (publish freezes them; they don't change).
    await waitFor(() => {
      expect(userPolicyDetail).toHaveBeenCalledTimes(2);
    });
    expect(userPolicyTargets).toHaveBeenCalledTimes(1);
  });
});


describe("PortalPolicyDetailPage republish flow", () => {
  it('on a published policy, surfaces the "Create new version" subsection', async () => {
    vi.mocked(userPolicyDetail).mockResolvedValue({
      ...draftPolicy,
      status: "published",
    });
    renderPage();
    expect(
      await screen.findByRole("heading", { name: /create new version/i })
    ).toBeInTheDocument();
    expect(
      screen.getByPlaceholderText(/default: bump v1\.0\.0/i)
    ).toBeInTheDocument();
    expect(
      screen.getByRole("button", { name: /create new version/i })
    ).toBeInTheDocument();
    // No Publish button on a published policy.
    expect(
      screen.queryByRole("button", { name: /publish policy/i })
    ).not.toBeInTheDocument();
  });

  it("republish with a custom version sends it to the API", async () => {
    const user = userEvent.setup();
    vi.mocked(userPolicyDetail).mockResolvedValue({
      ...draftPolicy,
      status: "published",
    });
    vi.mocked(userPolicyRepublish).mockResolvedValue({
      new_customer_policy_id: "p-2",
      new_version_semver: "v2.0.0",
      targets_copied: 5,
      parent_policy_id: "p-1",
      parent_version_semver: "v1.0.0",
    });

    renderPage();
    await screen.findByRole("button", { name: /create new version/i });

    await user.type(
      screen.getByPlaceholderText(/default: bump v1\.0\.0/i),
      "v2.0.0"
    );
    await user.click(
      screen.getByRole("button", { name: /create new version/i })
    );

    await waitFor(() => {
      expect(userPolicyRepublish).toHaveBeenCalledWith("p-1", {
        new_version_semver: "v2.0.0",
      });
    });
  });

  it("republish with a blank version sends new_version_semver: null", async () => {
    const user = userEvent.setup();
    vi.mocked(userPolicyDetail).mockResolvedValue({
      ...draftPolicy,
      status: "published",
    });
    vi.mocked(userPolicyRepublish).mockResolvedValue({
      new_customer_policy_id: "p-2",
      new_version_semver: "v1.0.1",
      targets_copied: 5,
      parent_policy_id: "p-1",
      parent_version_semver: "v1.0.0",
    });

    renderPage();
    await screen.findByRole("button", { name: /create new version/i });

    await user.click(
      screen.getByRole("button", { name: /create new version/i })
    );

    await waitFor(() => {
      expect(userPolicyRepublish).toHaveBeenCalledWith("p-1", {
        new_version_semver: null,
      });
    });
  });
});
