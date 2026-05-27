import { apiFetch, buildApiUrl, getApiBaseUrl, setApiToken } from "@/lib/api";
import type { AuthConfigResponse, LoginResponse, MFASetup, MFAStatus, RouteAuthService, User } from "@/lib/types";

export function completeLogin(response: LoginResponse) {
  setApiToken(response.token || null);
}

export async function login(email: string, password: string) {
  const response = await apiFetch<LoginResponse>(
    "/api/v1/auth/login",
    {
      method: "POST",
      body: JSON.stringify({ email, password })
    },
    { auth: false }
  );

  completeLogin(response);
  return response;
}

export async function requestOTP(email: string) {
  return apiFetch<{ expires_at?: string; token?: string; message?: string }>(
    "/api/v1/auth/request-otp",
    {
      method: "POST",
      body: JSON.stringify({ email })
    },
    { auth: false }
  );
}

export async function verifyOTP(email: string, token: string) {
  const response = await apiFetch<LoginResponse>(
    "/api/v1/auth/verify-otp",
    {
      method: "POST",
      body: JSON.stringify({ email, token })
    },
    { auth: false }
  );
  completeLogin(response);
  return response;
}

export async function getAuthConfig() {
  return apiFetch<AuthConfigResponse>("/api/v1/auth/config", undefined, { auth: false });
}

export async function startOIDCLogin(next = "/services") {
  const base = getApiBaseUrl();
  const url = base
    ? new URL(`${base}/api/v1/auth/oidc/start`)
    : new URL(buildApiUrl("/api/v1/auth/oidc/start"), window.location.origin);
  url.searchParams.set("next", next);

  const response = await fetch(url.toString(), { cache: "no-store", credentials: "include" });
  if (!response.ok) {
    const payload = (await response.json().catch(() => null)) as { error?: { message?: string } } | null;
    throw new Error(payload?.error?.message || "Unable to start SSO login.");
  }

  const data = (await response.json()) as { url: string };
  if (!data.url) {
    throw new Error("OIDC provider URL is missing.");
  }
  window.location.assign(data.url);
}

export async function finishOIDCLogin(code: string, state: string) {
  const base = getApiBaseUrl();
  const url = base
    ? new URL(`${base}/api/v1/auth/oidc/callback`)
    : new URL(buildApiUrl("/api/v1/auth/oidc/callback"), window.location.origin);
  url.searchParams.set("code", code);
  url.searchParams.set("state", state);

  const response = await fetch(url.toString(), { cache: "no-store", credentials: "include" });
  if (!response.ok) {
    const payload = (await response.json().catch(() => null)) as { error?: { message?: string } } | null;
    throw new Error(payload?.error?.message || "Unable to complete SSO login.");
  }

  const data = (await response.json()) as LoginResponse & { next?: string };
  completeLogin(data);
  return data;
}

export async function getCurrentUser() {
  return apiFetch<User>("/api/v1/me", undefined, { handleUnauthorized: false });
}

export async function completeAccountSetup(email: string, password: string) {
  return apiFetch<User>("/api/v1/me/account-setup", {
    method: "POST",
    body: JSON.stringify({ email, password })
  });
}

export async function logoutRequest() {
  try {
    await apiFetch<{ ok: boolean }>("/api/v1/auth/logout", { method: "POST" });
  } catch {
    // local cleanup still happens below
  }
}

export function logout() {
  setApiToken(null);
}

export async function verifyMFA(mfaToken: string, code: string) {
  const response = await apiFetch<LoginResponse>(
    "/api/v1/auth/verify-mfa",
    {
      method: "POST",
      body: JSON.stringify({ mfa_token: mfaToken, code })
    },
    { auth: false }
  );
  completeLogin(response);
  return response;
}

export async function getMyMFAStatus() {
  return apiFetch<MFAStatus>("/api/v1/me/mfa");
}

export async function beginMFASetup() {
  return apiFetch<MFASetup>("/api/v1/me/mfa/setup", { method: "POST" });
}

export async function enableMFA(code: string) {
  return apiFetch<MFAStatus>("/api/v1/me/mfa/enable", {
    method: "POST",
    body: JSON.stringify({ code })
  });
}

export async function disableMFA(code: string) {
  return apiFetch<MFAStatus>("/api/v1/me/mfa/disable", {
    method: "POST",
    body: JSON.stringify({ code })
  });
}

export async function regenerateRecoveryCodes(code: string) {
  return apiFetch<{ recovery_codes: string[] }>("/api/v1/me/mfa/recovery-codes", {
    method: "POST",
    body: JSON.stringify({ code })
  });
}

export async function getRouteAuthService(serviceId: string | number) {
  return apiFetch<RouteAuthService>(`/api/v1/route-auth/service/${serviceId}`, undefined, { auth: false });
}

export async function verifyRoutePIN(serviceId: number, pin: string, returnTo?: string) {
  const query = returnTo ? `?returnTo=${encodeURIComponent(returnTo)}` : "";
  return apiFetch<{ ok: boolean; bridge_url?: string }>(
    `/api/v1/route-auth/pin${query}`,
    {
      method: "POST",
      body: JSON.stringify({ service_id: serviceId, pin })
    },
    { auth: false }
  );
}

export async function requestRouteEmailCode(serviceId: number, email: string) {
  return apiFetch<{ expires_at: string; code?: string }>(
    "/api/v1/route-auth/request-email-code",
    {
      method: "POST",
      body: JSON.stringify({ service_id: serviceId, email })
    },
    { auth: false }
  );
}

export async function verifyRouteEmailCode(serviceId: number, email: string, code: string, returnTo?: string) {
  const query = returnTo ? `?returnTo=${encodeURIComponent(returnTo)}` : "";
  return apiFetch<{ ok: boolean; bridge_url?: string }>(
    `/api/v1/route-auth/verify-email-code${query}`,
    {
      method: "POST",
      body: JSON.stringify({ service_id: serviceId, email, code })
    },
    { auth: false }
  );
}

export async function createSessionBridgeToken(host: string) {
  return apiFetch<{ token: string }>(
    "/api/v1/route-auth/session-bridge-token",
    {
      method: "POST",
      body: JSON.stringify({ host })
    }
  );
}
