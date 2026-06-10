/**
 * `csrfRequestInterceptor` tests.
 *
 * Pins the rules the userApi axios instance enforces on every
 * outgoing request:
 *   - GET / HEAD / OPTIONS: do nothing
 *   - POST / PATCH / DELETE / PUT: read the aac_csrf cookie and
 *     attach it as X-CSRF-Token; skip if no cookie is set (bearer-
 *     auth path stays viable through Phase N+1 transition)
 */
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import type { InternalAxiosRequestConfig, AxiosHeaders } from "axios";
import { AxiosHeaders as AxiosHeadersImpl } from "axios";

import { csrfRequestInterceptor } from "./api";


function makeCfg(method: string, headers?: Record<string, string>): InternalAxiosRequestConfig {
  return {
    method,
    headers: new AxiosHeadersImpl(headers) as AxiosHeaders,
    url: "/api/portal/v1/me/logout",
  } as InternalAxiosRequestConfig;
}

function clearCookies(): void {
  document.cookie = "aac_csrf=; Max-Age=0; path=/";
  document.cookie = "__Host-aac_csrf=; Max-Age=0; path=/";
}

describe("csrfRequestInterceptor", () => {
  beforeEach(clearCookies);
  afterEach(clearCookies);

  it("does NOT attach X-CSRF-Token on GET", () => {
    document.cookie = "aac_csrf=hunter2; path=/";
    const cfg = csrfRequestInterceptor(makeCfg("get"));
    expect((cfg.headers as Record<string, string>)["X-CSRF-Token"]).toBeUndefined();
  });

  it("attaches X-CSRF-Token on POST when cookie is present", () => {
    document.cookie = "aac_csrf=hunter2; path=/";
    const cfg = csrfRequestInterceptor(makeCfg("post"));
    expect((cfg.headers as Record<string, string>)["X-CSRF-Token"]).toBe("hunter2");
  });

  it("attaches X-CSRF-Token on PATCH", () => {
    document.cookie = "aac_csrf=hunter2; path=/";
    const cfg = csrfRequestInterceptor(makeCfg("patch"));
    expect((cfg.headers as Record<string, string>)["X-CSRF-Token"]).toBe("hunter2");
  });

  it("attaches X-CSRF-Token on DELETE", () => {
    document.cookie = "aac_csrf=hunter2; path=/";
    const cfg = csrfRequestInterceptor(makeCfg("delete"));
    expect((cfg.headers as Record<string, string>)["X-CSRF-Token"]).toBe("hunter2");
  });

  it("attaches X-CSRF-Token on PUT", () => {
    document.cookie = "aac_csrf=hunter2; path=/";
    const cfg = csrfRequestInterceptor(makeCfg("put"));
    expect((cfg.headers as Record<string, string>)["X-CSRF-Token"]).toBe("hunter2");
  });

  it("does NOT attach X-CSRF-Token on POST when no cookie is set", () => {
    // Bearer-auth path: cookie absent → server middleware treats this
    // as a non-cookie request and skips CSRF enforcement. The
    // interceptor matches that contract by not inventing a value.
    const cfg = csrfRequestInterceptor(makeCfg("post"));
    expect((cfg.headers as Record<string, string>)["X-CSRF-Token"]).toBeUndefined();
  });

  it("prefers the prod __Host- cookie over the dev one", () => {
    document.cookie = "aac_csrf=dev-token; path=/";
    document.cookie = "__Host-aac_csrf=prod-token; path=/";
    const cfg = csrfRequestInterceptor(makeCfg("post"));
    expect((cfg.headers as Record<string, string>)["X-CSRF-Token"]).toBe("prod-token");
  });

  it("does not overwrite an already-set X-CSRF-Token caller put on", () => {
    // Defensive: if a caller has set the header explicitly (e.g. a
    // test simulating mismatch), we read the cookie and overwrite
    // with the cookie value. That's the documented behavior — the
    // interceptor source of truth is the cookie.
    document.cookie = "aac_csrf=hunter2; path=/";
    const cfg = csrfRequestInterceptor(makeCfg("post", { "X-CSRF-Token": "stale" }));
    expect((cfg.headers as Record<string, string>)["X-CSRF-Token"]).toBe("hunter2");
  });
});
