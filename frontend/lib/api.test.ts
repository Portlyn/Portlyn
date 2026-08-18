import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { ApiError, apiFetch, buildApiUrl, setApiToken, setUnauthorizedHandler } from "@/lib/api";

function jsonResponse(body: unknown, status = 200) {
  return new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } });
}

function lastInit(): RequestInit {
  const mock = globalThis.fetch as unknown as ReturnType<typeof vi.fn>;
  return mock.mock.calls[mock.mock.calls.length - 1][1] as RequestInit;
}

function lastHeaders(): Headers {
  return lastInit().headers as Headers;
}

describe("apiFetch", () => {
  beforeEach(() => {
    globalThis.fetch = vi.fn().mockImplementation(async () => jsonResponse({ ok: true }));
    setApiToken(null);
    setUnauthorizedHandler(null);
    document.cookie = "portlyn_csrf=; expires=Thu, 01 Jan 1970 00:00:00 GMT; path=/";
  });

  afterEach(() => {
    vi.restoreAllMocks();
    setApiToken(null);
    setUnauthorizedHandler(null);
  });

  it("sends credentials and skips the cache", async () => {
    await apiFetch("/api/v1/me");
    const init = lastInit();
    expect(init.credentials).toBe("include");
    expect(init.cache).toBe("no-store");
  });

  it("attaches the bearer token once it is set", async () => {
    await apiFetch("/api/v1/me");
    expect(lastHeaders().has("Authorization")).toBe(false);

    setApiToken("token-abc");
    await apiFetch("/api/v1/me");
    expect(lastHeaders().get("Authorization")).toBe("Bearer token-abc");
  });

  it("omits the bearer token when auth is disabled", async () => {
    setApiToken("token-abc");
    await apiFetch("/api/v1/auth/config", undefined, { auth: false });
    expect(lastHeaders().has("Authorization")).toBe(false);
  });

  it("sends the CSRF token on state changing requests only", async () => {
    document.cookie = "portlyn_csrf=csrf-value; path=/";

    await apiFetch("/api/v1/me");
    expect(lastHeaders().has("X-CSRF-Token")).toBe(false);

    await apiFetch("/api/v1/me", { method: "POST", body: "{}" });
    expect(lastHeaders().get("X-CSRF-Token")).toBe("csrf-value");

    await apiFetch("/api/v1/me", { method: "delete" });
    expect(lastHeaders().get("X-CSRF-Token")).toBe("csrf-value");
  });

  it("sets a JSON content type when there is a body", async () => {
    await apiFetch("/api/v1/me", { method: "POST", body: "{}" });
    expect(lastHeaders().get("Content-Type")).toBe("application/json");
  });

  it("returns undefined for 204 responses", async () => {
    globalThis.fetch = vi.fn().mockImplementation(async () => new Response(null, { status: 204 }));
    await expect(apiFetch("/api/v1/services/1")).resolves.toBeUndefined();
  });

  it("turns error payloads into ApiError", async () => {
    globalThis.fetch = vi
      .fn()
      .mockImplementation(async () => jsonResponse({ error: { message: "nope", code: "forbidden" } }, 403));

    const error = (await apiFetch("/api/v1/services").catch((err) => err)) as ApiError;
    expect(error).toBeInstanceOf(ApiError);
    expect(error.status).toBe(403);
    expect(error.code).toBe("forbidden");
    expect(error.message).toBe("nope");
  });

  it("falls back to a status message when the body is not JSON", async () => {
    globalThis.fetch = vi.fn().mockImplementation(async () => new Response("<html>", { status: 500 }));
    const error = (await apiFetch("/api/v1/services").catch((err) => err)) as ApiError;
    expect(error.message).toBe("Request failed with status 500");
  });

  it("calls the unauthorized handler on 401", async () => {
    globalThis.fetch = vi.fn().mockImplementation(async () => jsonResponse({ error: { message: "no" } }, 401));
    const handler = vi.fn();
    setUnauthorizedHandler(handler);

    await apiFetch("/api/v1/me").catch(() => undefined);
    expect(handler).toHaveBeenCalledTimes(1);
  });

  it("leaves the unauthorized handler alone when opted out", async () => {
    globalThis.fetch = vi.fn().mockImplementation(async () => jsonResponse({ error: { message: "no" } }, 401));
    const handler = vi.fn();
    setUnauthorizedHandler(handler);

    await apiFetch("/api/v1/me", undefined, { handleUnauthorized: false }).catch(() => undefined);
    expect(handler).not.toHaveBeenCalled();
  });

  it("does not fire the unauthorized handler for other error codes", async () => {
    globalThis.fetch = vi.fn().mockImplementation(async () => jsonResponse({ error: { message: "no" } }, 403));
    const handler = vi.fn();
    setUnauthorizedHandler(handler);

    await apiFetch("/api/v1/me").catch(() => undefined);
    expect(handler).not.toHaveBeenCalled();
  });
});

describe("buildApiUrl", () => {
  it("roots paths that are missing a leading slash", () => {
    expect(buildApiUrl("api/v1/me")).toBe("/api/v1/me");
    expect(buildApiUrl("/api/v1/me")).toBe("/api/v1/me");
  });
});
