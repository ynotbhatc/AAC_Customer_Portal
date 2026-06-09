/**
 * Reset-password page security tests.
 *
 * Closes docs/security_roadmap.md "Reset token in URL query param".
 * The page must NOT pre-fill the token field from `?token=`, and it
 * must strip the token from window.location.search before any
 * subrequest can leak it via Referer.
 */
import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";

vi.mock("../lib/api", () => ({
  userPasswordResetConfirm: vi.fn(),
}));

import PortalResetPasswordPage from "./PortalResetPasswordPage";


function renderWithLocation(search: string) {
  // jsdom lets us mutate the URL directly.
  window.history.replaceState(null, "", `/portal/reset-password${search}`);
  return render(
    <MemoryRouter>
      <PortalResetPasswordPage />
    </MemoryRouter>
  );
}


describe("PortalResetPasswordPage URL-token leak prevention", () => {
  beforeEach(() => {
    // Reset to a clean URL between tests so cross-test contamination
    // can't hide a regression.
    window.history.replaceState(null, "", "/portal/reset-password");
  });

  it("does not pre-fill the token input from ?token= in the URL", () => {
    renderWithLocation("?token=ABCD.efgh");
    const input = screen.getByLabelText(/reset token/i) as HTMLInputElement;
    expect(input.value).toBe("");
  });

  it("strips ?token= from the URL on mount", async () => {
    renderWithLocation("?token=ABCD.efgh");
    await waitFor(() => {
      expect(window.location.search).toBe("");
    });
  });

  it("preserves other query params while stripping token", async () => {
    renderWithLocation("?token=ABCD.efgh&keep=this");
    await waitFor(() => {
      expect(window.location.search).toBe("?keep=this");
    });
  });

  it("shows a notice when a token-bearing URL was sanitized", async () => {
    renderWithLocation("?token=ABCD.efgh");
    expect(
      await screen.findByText(/no longer accepts reset tokens from the URL/i)
    ).toBeInTheDocument();
  });

  it("does not show the notice on a clean URL", () => {
    renderWithLocation("");
    expect(
      screen.queryByText(/no longer accepts reset tokens from the URL/i)
    ).not.toBeInTheDocument();
  });
});
