import { expect, test } from "@playwright/test";

const ADMIN_EMAIL = process.env.PORTLYN_TEST_ADMIN_EMAIL || "admin@example.test";
const ADMIN_PASSWORD = process.env.PORTLYN_TEST_ADMIN_PASSWORD || "ChangeMeStrongerPasswordPlease!";

test.describe("portlyn smoke", () => {
  test("login form is reachable and rejects empty submissions", async ({ page }) => {
    await page.goto("/login");
    await expect(page.getByRole("heading", { name: /portlyn/i })).toBeVisible();
    await page.getByRole("button", { name: /sign in|login/i }).click();
    // empty form should not redirect off /login
    await expect(page).toHaveURL(/\/login/);
  });

  test("admin can sign in and reach the services list", async ({ page }) => {
    test.skip(!process.env.PORTLYN_E2E_LIVE, "set PORTLYN_E2E_LIVE=1 to run against a live instance");

    await page.goto("/login");
    await page.getByLabel(/email/i).fill(ADMIN_EMAIL);
    await page.getByLabel(/password/i).fill(ADMIN_PASSWORD);
    await page.getByRole("button", { name: /sign in|login/i }).click();
    await expect(page).toHaveURL(/\/services/);
    await expect(page.getByRole("heading", { name: /services/i })).toBeVisible({ timeout: 10_000 });
  });

  test("admin sees passkeys page", async ({ page }) => {
    test.skip(!process.env.PORTLYN_E2E_LIVE, "set PORTLYN_E2E_LIVE=1 to run against a live instance");

    await page.goto("/login");
    await page.getByLabel(/email/i).fill(ADMIN_EMAIL);
    await page.getByLabel(/password/i).fill(ADMIN_PASSWORD);
    await page.getByRole("button", { name: /sign in|login/i }).click();
    await page.goto("/passkeys");
    await expect(page.getByRole("heading", { name: /passkeys/i })).toBeVisible();
    await expect(page.getByRole("button", { name: /register passkey/i })).toBeVisible();
  });
});
