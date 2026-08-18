import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { setApiToken } from "@/lib/api";
import {
  disableMFA,
  enableMFA,
  finishPasskeyLogin,
  login,
  logout,
  regenerateRecoveryCodes,
  verifyMFA,
  verifyOTP
} from "@/lib/auth";

function jsonResponse(body: unknown, status = 200) {
  return new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } });
}

function fetchMock() {
  return globalThis.fetch as unknown as ReturnType<typeof vi.fn>;
}

function callAt(index: number) {
  const call = fetchMock().mock.calls[index];
  return { url: call[0] as string, init: call[1] as RequestInit };
}

function bodyAt(index: number) {
  return JSON.parse(callAt(index).init.body as string);
}

describe("password login", () => {
  beforeEach(() => {
    globalThis.fetch = vi.fn().mockImplementation(async () => jsonResponse({ token: "session-token" }));
    setApiToken(null);
  });

  afterEach(() => {
    vi.restoreAllMocks();
    setApiToken(null);
  });

  it("posts the credentials to the login endpoint", async () => {
    await login("admin@example.test", "hunter2");
    const { url, init } = callAt(0);
    expect(url).toBe("/api/v1/auth/login");
    expect(init.method).toBe("POST");
    expect(bodyAt(0)).toEqual({ email: "admin@example.test", password: "hunter2" });
  });

  it("does not send an old token along with the login request", async () => {
    setApiToken("stale-token");
    await login("admin@example.test", "hunter2");
    expect((callAt(0).init.headers as Headers).has("Authorization")).toBe(false);
  });

  it("stores the returned token for later requests", async () => {
    await login("admin@example.test", "hunter2");
    await enableMFA("123456");
    expect((callAt(1).init.headers as Headers).get("Authorization")).toBe("Bearer session-token");
  });

  it("does not store a token when the login is not complete", async () => {
    globalThis.fetch = vi.fn().mockImplementation(async () => jsonResponse({ requires_mfa: true, mfa_token: "mfa-token" }));

    const response = await login("admin@example.test", "hunter2");
    expect(response.requires_mfa).toBe(true);

    await enableMFA("123456");
    expect((callAt(1).init.headers as Headers).has("Authorization")).toBe(false);
  });

  it("keeps the error from the server", async () => {
    globalThis.fetch = vi
      .fn()
      .mockImplementation(async () => jsonResponse({ error: { message: "invalid credentials", code: "unauthorized" } }, 401));

    await expect(login("admin@example.test", "wrong")).rejects.toThrow("invalid credentials");
  });
});

describe("second factor", () => {
  beforeEach(() => {
    globalThis.fetch = vi.fn().mockImplementation(async () => jsonResponse({ token: "post-mfa-token" }));
    setApiToken(null);
  });

  afterEach(() => {
    vi.restoreAllMocks();
    setApiToken(null);
  });

  it("exchanges the mfa token for a session token", async () => {
    await verifyMFA("mfa-token", "123456");
    expect(callAt(0).url).toBe("/api/v1/auth/verify-mfa");
    expect(bodyAt(0)).toEqual({ mfa_token: "mfa-token", code: "123456" });

    await enableMFA("123456");
    expect((callAt(1).init.headers as Headers).get("Authorization")).toBe("Bearer post-mfa-token");
  });

  it("sends the mfa token unauthenticated", async () => {
    setApiToken("half-session");
    await verifyMFA("mfa-token", "123456");
    expect((callAt(0).init.headers as Headers).has("Authorization")).toBe(false);
  });

  it("requires a code to disable mfa or regenerate recovery codes", async () => {
    await disableMFA("654321");
    expect(callAt(0).url).toBe("/api/v1/me/mfa/disable");
    expect(bodyAt(0)).toEqual({ code: "654321" });

    await regenerateRecoveryCodes("654321");
    expect(callAt(1).url).toBe("/api/v1/me/mfa/recovery-codes");
    expect(bodyAt(1)).toEqual({ code: "654321" });
  });
});

describe("one time codes and passkeys", () => {
  beforeEach(() => {
    globalThis.fetch = vi.fn().mockImplementation(async () => jsonResponse({ token: "otp-token" }));
    setApiToken(null);
  });

  afterEach(() => {
    vi.restoreAllMocks();
    setApiToken(null);
  });

  it("verifies an emailed code", async () => {
    await verifyOTP("admin@example.test", "999888");
    expect(callAt(0).url).toBe("/api/v1/auth/verify-otp");
    expect(bodyAt(0)).toEqual({ email: "admin@example.test", token: "999888" });
  });

  it("passes the passkey session id in the query and the assertion in the body", async () => {
    await finishPasskeyLogin("session id/with?chars", { id: "credential" });
    const { url, init } = callAt(0);
    expect(url).toBe("/api/v1/auth/passkey/finish-login?session_id=session%20id%2Fwith%3Fchars");
    expect(init.method).toBe("POST");
    expect(bodyAt(0)).toEqual({ id: "credential" });
  });
});

describe("logout", () => {
  afterEach(() => {
    vi.restoreAllMocks();
    setApiToken(null);
  });

  it("clears the stored token", async () => {
    globalThis.fetch = vi.fn().mockImplementation(async () => jsonResponse({ token: "session-token" }));
    await login("admin@example.test", "hunter2");

    logout();

    await enableMFA("123456");
    expect((callAt(1).init.headers as Headers).has("Authorization")).toBe(false);
  });
});
