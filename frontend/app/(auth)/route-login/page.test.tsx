import { MantineProvider } from "@mantine/core";
import { render, screen, waitFor } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { ApiError } from "@/lib/api";
import { createSessionBridgeToken } from "@/lib/auth";
import RouteLoginPage from "./page";

const user = { id: 2, email: "viewer@example.com", role: "viewer", auth_provider: "local" };

vi.mock("next/navigation", () => ({
  useSearchParams: () => new URLSearchParams("serviceId=1&returnTo=https%3A%2F%2Ftest.example.com%2F")
}));

vi.mock("@/components/providers", () => ({
  useAuth: () => ({ isAuthenticated: true, user, isLoading: false })
}));

vi.mock("@/lib/auth", () => ({
  createSessionBridgeToken: vi.fn(),
  getAuthConfig: vi.fn().mockResolvedValue({ oidc_enabled: false, ui: {} }),
  getRouteAuthService: vi.fn().mockResolvedValue({ id: 1, name: "test", domain_name: "test.example.com", access_method: "session" }),
  requestRouteEmailCode: vi.fn(),
  startOIDCLogin: vi.fn(),
  verifyRouteEmailCode: vi.fn(),
  verifyRoutePIN: vi.fn()
}));

describe("RouteLoginPage", () => {
  beforeEach(() => {
    window.matchMedia = vi.fn().mockReturnValue({ matches: false, addEventListener: vi.fn(), removeEventListener: vi.fn() });
    vi.mocked(createSessionBridgeToken).mockReset();
  });

  it("does not retry the session bridge after it was rejected", async () => {
    vi.mocked(createSessionBridgeToken).mockRejectedValue(
      new ApiError("complete account setup or enroll mfa before accessing this endpoint", 403, "bootstrap_required")
    );

    render(
      <MantineProvider>
        <RouteLoginPage />
      </MantineProvider>
    );

    expect(await screen.findByText(/complete account setup/)).toBeInTheDocument();
    await new Promise((resolve) => setTimeout(resolve, 50));
    await waitFor(() => expect(createSessionBridgeToken).toHaveBeenCalledTimes(1));
  });
});
