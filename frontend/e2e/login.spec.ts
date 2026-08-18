import { expect, test } from "@playwright/test";

import { ADMIN_EMAIL, liveOnly, liveReason, signIn, signInExpectingSuccess } from "./helpers";

test.describe("login page", () => {
  test("renders the password form", async ({ page }) => {
    await page.goto("/login");
    await expect(page.getByLabel("Email", { exact: true })).toBeVisible();
    await expect(page.getByLabel("Password", { exact: true })).toBeVisible();
    await expect(page.getByRole("button", { name: "Login", exact: true })).toBeVisible();
  });

  test("stays on /login when the form is empty", async ({ page }) => {
    await page.goto("/login");
    await page.getByRole("button", { name: "Login", exact: true }).click();
    await expect(page).toHaveURL(/\/login/);
  });

  test("offers passkey sign in", async ({ page }) => {
    await page.goto("/login");
    await expect(page.getByRole("button", { name: /sign in with passkey/i })).toBeVisible();
  });
});

test.describe("authentication", () => {
  test.skip(liveOnly, liveReason);

  test("admin can sign in and lands on the services page", async ({ page }) => {
    await signInExpectingSuccess(page);
    await expect(page.getByRole("button", { name: "New Service" })).toBeVisible();
  });

  test("rejects a wrong password without leaving the login page", async ({ page }) => {
    await signIn(page, ADMIN_EMAIL, "definitely-not-the-password");
    await expect(page).toHaveURL(/\/login/);
    await expect(page.getByRole("button", { name: "New Service" })).toHaveCount(0);
  });

  test("rejects an unknown account", async ({ page }) => {
    await signIn(page, "nobody@example.test", "definitely-not-the-password");
    await expect(page).toHaveURL(/\/login/);
  });

  test("keeps the session across a reload", async ({ page }) => {
    await signInExpectingSuccess(page);
    await page.reload();
    await expect(page).toHaveURL(/\/services/);
    await expect(page.getByRole("button", { name: "New Service" })).toBeVisible();
  });

  test("sends an unauthenticated visitor to the login page", async ({ page }) => {
    await page.goto("/services");
    await expect(page).toHaveURL(/\/login/, { timeout: 15_000 });
  });
});
