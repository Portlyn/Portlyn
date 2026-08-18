import { expect, test, type Page } from "@playwright/test";

import { ADMIN_EMAIL, liveOnly, liveReason, signInExpectingSuccess } from "./helpers";

test.describe.configure({ mode: "serial" });

async function addVirtualAuthenticator(page: Page) {
  const client = await page.context().newCDPSession(page);
  await client.send("WebAuthn.enable");
  const { authenticatorId } = await client.send("WebAuthn.addVirtualAuthenticator", {
    options: {
      protocol: "ctap2",
      transport: "internal",
      hasResidentKey: true,
      hasUserVerification: true,
      isUserVerified: true,
      automaticPresenceSimulation: true
    }
  });
  return { client, authenticatorId };
}

test.describe("passkeys", () => {
  test.skip(liveOnly, liveReason);
  test.setTimeout(90_000);

  test("shows the passkey section on the security page", async ({ page }) => {
    await signInExpectingSuccess(page);
    await page.goto("/security");
    await expect(page.getByText("Add a passkey")).toBeVisible();
    await expect(page.getByRole("button", { name: /register passkey/i })).toBeVisible();
  });

  test("registers a passkey and uses it to sign in", async ({ page }) => {
    const { client, authenticatorId } = await addVirtualAuthenticator(page);

    try {
      await signInExpectingSuccess(page);
      await page.goto("/security");

      await page.getByLabel("Label").fill("e2e-virtual-key");
      await page.getByRole("button", { name: /register passkey/i }).click();
      await expect(page.getByText("e2e-virtual-key")).toBeVisible({ timeout: 20_000 });

      await page.context().clearCookies();
      await page.goto("/login");
      await page.getByLabel("Email", { exact: true }).fill(ADMIN_EMAIL);
      await page.getByRole("button", { name: /sign in with passkey/i }).click();
      await expect(page).toHaveURL(/\/services/, { timeout: 20_000 });
    } finally {
      await client.send("WebAuthn.removeVirtualAuthenticator", { authenticatorId }).catch(() => undefined);
    }
  });
});
