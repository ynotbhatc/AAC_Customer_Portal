/**
 * Tests for the per-target review page.
 *
 * Covers:
 *   - happy-path render (metadata + Rego shown, action buttons enabled)
 *   - Approve calls the API with the optional reason then refetches detail
 *   - Reject button is disabled until reason is non-empty (client-side
 *     enforcement of the workflow rule)
 *   - Edit → Save POSTs the new Rego; on 422 the opa stderr surfaces
 *     inline and the page stays in edit mode for the user to retry
 *   - When the parent policy is `published` the frozen banner shows and
 *     mutating actions are hidden (no approve/reject/edit)
 *
 * The lib/api module is fully mocked. Tests assert on call arguments
 * and on rendered text so they don't bind to specific button styling.
 */
import { describe, it, expect, beforeEach, vi } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter, Route, Routes } from "react-router-dom";

import type { CustomerPolicyDetail, TargetDetail } from "../types/policy";

vi.mock("../lib/api", () => ({
  userPolicyDetail: vi.fn(),
  userPolicyTargetDetail: vi.fn(),
  userPolicyTargetEdit: vi.fn(),
  userPolicyTargetApprove: vi.fn(),
  userPolicyTargetReject: vi.fn(),
}));

// Resolved post-mock so the page imports the mocked module.
import {
  userPolicyDetail,
  userPolicyTargetApprove,
  userPolicyTargetDetail,
  userPolicyTargetEdit,
  userPolicyTargetReject,
} from "../lib/api";
import PortalPolicyTargetReviewPage from "./PortalPolicyTargetReviewPage";


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

const pendingTarget: TargetDetail = {
  id: "tgt-1",
  customer_policy_id: "p-1",
  target_system: "linux",
  target_subtype: "rhel9",
  generation_method: "template_mapped",
  confidence_score: 0.93,
  review_status: "pending",
  rego_content_sha256: "a".repeat(64),
  published_in_bundle_sha: null,
  created_at: "2026-01-01T00:00:00Z",
  rego_storage_key: "pgrego:art-1",
  rego_text:
    "package linux.rhel9\n\nimport rego.v1\n\ndefault compliant := false\n",
};


function renderPage() {
  return render(
    <MemoryRouter initialEntries={["/portal/policies/p-1/targets/tgt-1"]}>
      <Routes>
        <Route
          path="/portal/policies/:policyId/targets/:targetId"
          element={<PortalPolicyTargetReviewPage />}
        />
      </Routes>
    </MemoryRouter>
  );
}


beforeEach(() => {
  vi.clearAllMocks();
  vi.mocked(userPolicyDetail).mockResolvedValue(draftPolicy);
  vi.mocked(userPolicyTargetDetail).mockResolvedValue(pendingTarget);
});


describe("PortalPolicyTargetReviewPage", () => {
  it("renders metadata and the Rego module on a draft policy", async () => {
    renderPage();
    expect(await screen.findByText("linux/rhel9")).toBeInTheDocument();
    // "pending" appears in both the status badge and descriptive copy
    // elsewhere on the page; assert via getAllByText so we don't
    // become brittle to that copy moving.
    expect(screen.getAllByText(/pending/i).length).toBeGreaterThan(0);
    expect(screen.getByText(/Target metadata/)).toBeInTheDocument();
    expect(screen.getByText(/package linux\.rhel9/)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /edit/i })).toBeInTheDocument();
    expect(
      screen.getByRole("button", { name: /approve target/i })
    ).toBeInTheDocument();
    expect(
      screen.getByRole("button", { name: /reject target/i })
    ).toBeInTheDocument();
  });

  it("approves with an optional reason and refetches the target", async () => {
    const user = userEvent.setup();
    vi.mocked(userPolicyTargetApprove).mockResolvedValue({
      ...pendingTarget,
      review_status: "approved",
    });
    // Second call after approve returns the refreshed detail.
    vi.mocked(userPolicyTargetDetail)
      .mockResolvedValueOnce(pendingTarget)
      .mockResolvedValueOnce({ ...pendingTarget, review_status: "approved" });

    renderPage();
    await screen.findByText("linux/rhel9");

    await user.type(
      screen.getByPlaceholderText(/Reason \(optional\)/i),
      "policy approved on review"
    );
    await user.click(screen.getByRole("button", { name: /approve target/i }));

    await waitFor(() => {
      expect(userPolicyTargetApprove).toHaveBeenCalledWith("p-1", "tgt-1", {
        reason: "policy approved on review",
      });
    });
    // Proof of the post-mutation refetch is the second call to the
    // target detail endpoint. Asserting on rendered badge text is too
    // brittle because "approved" appears in static copy too.
    await waitFor(() => {
      expect(userPolicyTargetDetail).toHaveBeenCalledTimes(2);
    });
  });

  it("approve with a blank reason sends reason: null", async () => {
    const user = userEvent.setup();
    vi.mocked(userPolicyTargetApprove).mockResolvedValue({
      ...pendingTarget,
      review_status: "approved",
    });

    renderPage();
    await screen.findByText("linux/rhel9");

    await user.click(screen.getByRole("button", { name: /approve target/i }));

    await waitFor(() => {
      expect(userPolicyTargetApprove).toHaveBeenCalledWith("p-1", "tgt-1", {
        reason: null,
      });
    });
  });

  it("reject button stays disabled until a reason is entered", async () => {
    const user = userEvent.setup();
    renderPage();
    const rejectBtn = await screen.findByRole("button", {
      name: /reject target/i,
    });
    expect(rejectBtn).toBeDisabled();

    await user.type(
      screen.getByPlaceholderText(/Reason \(required\)/i),
      "rego references nonexistent input field"
    );
    expect(rejectBtn).toBeEnabled();
  });

  it("reject calls the API with the typed reason", async () => {
    const user = userEvent.setup();
    vi.mocked(userPolicyTargetReject).mockResolvedValue({
      ...pendingTarget,
      review_status: "rejected",
    });

    renderPage();
    await screen.findByText("linux/rhel9");

    await user.type(
      screen.getByPlaceholderText(/Reason \(required\)/i),
      "fails on rhel9 baseline"
    );
    await user.click(screen.getByRole("button", { name: /reject target/i }));

    await waitFor(() => {
      expect(userPolicyTargetReject).toHaveBeenCalledWith("p-1", "tgt-1", {
        reason: "fails on rhel9 baseline",
      });
    });
  });

  it("surfaces opa stderr inline when Save returns 422", async () => {
    const user = userEvent.setup();
    // The page expects 422-shaped axios errors of the form
    //   { response: { status: 422, data: { detail: { stderr: "..." } } } }
    vi.mocked(userPolicyTargetEdit).mockRejectedValue({
      response: {
        status: 422,
        data: {
          detail: {
            reason: "opa_check failed",
            stderr:
              "1 error occurred: rules.rego:2: rego_parse_error: var cannot start with digit",
          },
        },
      },
    });

    renderPage();
    await screen.findByText("linux/rhel9");

    await user.click(screen.getByRole("button", { name: /^edit$/i }));
    const textarea = await screen.findByRole("textbox");
    // Replace contents so the Save button enables.
    await user.clear(textarea);
    await user.type(textarea, "broken rego");
    await user.click(
      screen.getByRole("button", { name: /save changes/i })
    );

    // The stderr renders in a code/pre block; assert on text presence.
    expect(
      await screen.findByText(/rego_parse_error: var cannot start with digit/)
    ).toBeInTheDocument();
    // Page stays in edit mode (Save button visible) so the user can fix.
    expect(
      screen.getByRole("button", { name: /save changes/i })
    ).toBeInTheDocument();
  });

  it("renders the frozen banner and hides actions when published", async () => {
    vi.mocked(userPolicyDetail).mockResolvedValue({
      ...draftPolicy,
      status: "published",
    });

    renderPage();
    await screen.findByText("linux/rhel9");

    expect(
      screen.getByText(/this policy is published\. targets are frozen/i)
    ).toBeInTheDocument();
    expect(
      screen.queryByRole("button", { name: /^edit$/i })
    ).not.toBeInTheDocument();
    expect(
      screen.queryByRole("button", { name: /approve target/i })
    ).not.toBeInTheDocument();
    expect(
      screen.queryByRole("button", { name: /reject target/i })
    ).not.toBeInTheDocument();
  });
});
