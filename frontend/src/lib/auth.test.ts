/**
 * `readCsrfCookie` tests — Phase N+1 of the cookie-auth migration.
 *
 * The reader has to work in two environments:
 *   - production: cookie is `__Host-aac_csrf` (Secure-only on HTTPS)
 *   - dev / test: cookie is `aac_csrf` (works over http://localhost)
 *
 * No build-time prod/dev flag exists on the frontend, so the reader
 * tries both names and returns whichever is present, prod-name first.
 * These tests pin that precedence.
 */
import { afterEach, beforeEach, describe, expect, it } from "vitest";

import { readCsrfCookie } from "./auth";


// document.cookie is a getter/setter; assigning "" with Max-Age=0
// removes the cookie. We reset between tests so order doesn't matter.
const RESET_NAMES = ["__Host-aac_csrf", "aac_csrf"];

function clearCookies(): void {
  for (const name of RESET_NAMES) {
    document.cookie = `${name}=; Max-Age=0; path=/`;
  }
}

describe("readCsrfCookie", () => {
  beforeEach(clearCookies);
  afterEach(clearCookies);

  it("returns null when no CSRF cookie is set", () => {
    expect(readCsrfCookie()).toBeNull();
  });

  it("reads the dev cookie when only that is set", () => {
    document.cookie = "aac_csrf=dev-token-value; path=/";
    expect(readCsrfCookie()).toBe("dev-token-value");
  });

  it("prefers the prod cookie when both are set", () => {
    // jsdom refuses to *set* a `__Host-` cookie via document.cookie
    // over http (matches the spec — `__Host-` requires Secure). We
    // bypass the setter by stubbing the document.cookie getter
    // directly with both values; the reader only reads.
    const desc = Object.getOwnPropertyDescriptor(Document.prototype, "cookie");
    Object.defineProperty(document, "cookie", {
      configurable: true,
      get: () => "aac_csrf=dev-value; __Host-aac_csrf=prod-value",
    });
    try {
      expect(readCsrfCookie()).toBe("prod-value");
    } finally {
      if (desc) Object.defineProperty(document, "cookie", desc);
    }
  });

  it("ignores unrelated cookies", () => {
    document.cookie = "some_other_cookie=ignore-me; path=/";
    document.cookie = "aac_csrf=the-one; path=/";
    expect(readCsrfCookie()).toBe("the-one");
  });
});
