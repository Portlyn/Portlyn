import { expect, test, type Page } from "@playwright/test";

import { ADMIN_EMAIL, ADMIN_PASSWORD, liveOnly, liveReason, signInExpectingSuccess } from "./helpers";
import { unusedTotp } from "./totp";

test.describe.configure({ mode: "serial" });

async function startSetupAndReadSecret(page: Page): Promise<string> {
  await page.getByRole("button", { name: "Set up authenticator" }).click();
  const secret = page.locator("code").filter({ hasText: /^[A-Z2-7]{16,}$/ });
  await expect(secret).toBeVisible({ timeout: 15_000 });
  return (await secret.innerText()).trim();
}

async function disableMfa(page: Page, secret: string, used: Set<string>) {
  await page.goto("/security");
  const field = page.getByLabel("Current code");
  if (!(await field.isVisible({ timeout: 10_000 }).catch(() => false))) {
    return;
  }
  await field.fill(await unusedTotp(secret, used));
  await page.getByRole("button", { name: "Disable MFA" }).click();
  await expect(page.getByText("disabled", { exact: true })).toBeVisible({ timeout: 15_000 });
}

test.describe("totp second factor", () => {
  test.skip(liveOnly, liveReason);
  test.setTimeout(120_000);

  test("can be enabled, used to log in, and turned off again", async ({ page }) => {
    const used = new Set<string>();

    await signInExpectingSuccess(page);
    await page.goto("/security");
    await expect(page.getByText("Authenticator app (TOTP)")).toBeVisible();

    const secret = await startSetupAndReadSecret(page);
    expect(secret).toMatch(/^[A-Z2-7]+$/);

    try {
      await page.getByLabel("Code", { exact: true }).fill(await unusedTotp(secret, used));
      await page.getByRole("button", { name: "Enable", exact: true }).click();
      await expect(page.getByText("enabled", { exact: true })).toBeVisible({ timeout: 15_000 });
      await expect(page.getByText(/store these now/i)).toBeVisible();

      await page.context().clearCookies();
      await page.goto("/login");
      await page.getByLabel("Email", { exact: true }).fill(ADMIN_EMAIL);
      await page.getByLabel("Password", { exact: true }).fill(ADMIN_PASSWORD);
      await page.getByRole("button", { name: "Login", exact: true }).click();

      await expect(page.getByText(/6-digit code from your authenticator/i)).toBeVisible({ timeout: 15_000 });

      const code = await unusedTotp(secret, used);
      for (let i = 0; i < code.length; i++) {
        await page.locator("input[inputmode='numeric']").nth(i).fill(code[i]);
      }
      await expect(page).toHaveURL(/\/services/, { timeout: 15_000 });
    } finally {
      await disableMfa(page, secret, used).catch((err) => console.warn("mfa cleanup failed:", err));
    }
  });

  test("does not enable mfa for a wrong code", async ({ page }) => {
    const used = new Set<string>();

    await signInExpectingSuccess(page);
    await page.goto("/security");

    const secret = await startSetupAndReadSecret(page);

    try {
      await page.getByLabel("Code", { exact: true }).fill("000000");
      await page.getByRole("button", { name: "Enable", exact: true }).click();
      await expect(page.getByText("enabled", { exact: true })).toHaveCount(0);
    } finally {
      await disableMfa(page, secret, used).catch(() => undefined);
    }
  });
});
