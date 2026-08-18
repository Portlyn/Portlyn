import { expect, test, type Page } from "@playwright/test";

import { liveOnly, liveReason, signInExpectingSuccess } from "./helpers";

test.describe.configure({ mode: "serial" });

const DOMAIN = "e2e-suite.example.test";

async function createDomainIfMissing(page: Page) {
  await page.goto("/domains");
  if (await page.getByText(DOMAIN).isVisible().catch(() => false)) {
    return;
  }
  await page.getByRole("button", { name: "New Domain" }).click();
  await page.getByLabel("Hostname").fill(DOMAIN);
  await page.getByRole("button", { name: "Create Domain" }).click();
  await expect(page.getByText(DOMAIN)).toBeVisible({ timeout: 15_000 });
}

test.describe("domains and routing", () => {
  test.skip(liveOnly, liveReason);
  test.setTimeout(90_000);

  test("creates a domain and keeps it after a reload", async ({ page }) => {
    await signInExpectingSuccess(page);
    await createDomainIfMissing(page);

    await page.reload();
    await expect(page.getByText(DOMAIN)).toBeVisible({ timeout: 15_000 });
  });

  test("persists an ip allowlist change", async ({ page }) => {
    await signInExpectingSuccess(page);
    await createDomainIfMissing(page);

    await page.getByRole("button", { name: `Edit ${DOMAIN}` }).click();
    await page.getByLabel("IP allowlist").fill("203.0.113.0/24");
    await page.getByRole("button", { name: "Save Changes" }).click();
    await expect(page.getByRole("button", { name: "Save Changes" })).toHaveCount(0, { timeout: 15_000 });

    await page.reload();
    await page.getByRole("button", { name: `Edit ${DOMAIN}` }).click();
    await expect(page.getByLabel("IP allowlist")).toHaveValue("203.0.113.0/24");
  });

  test("opens the service wizard once a domain exists", async ({ page }) => {
    await signInExpectingSuccess(page);
    await createDomainIfMissing(page);

    await page.goto("/services");
    const newService = page.getByRole("button", { name: "New Service" });
    await expect(newService).toBeEnabled({ timeout: 15_000 });
    await newService.click();
    await expect(page.getByText("Create service")).toBeVisible();
    await expect(page.getByText("Application")).toBeVisible();
  });

  test("deletes the domain again", async ({ page }) => {
    await signInExpectingSuccess(page);
    await createDomainIfMissing(page);

    await page.getByRole("button", { name: `Delete ${DOMAIN}` }).click();
    await page.getByRole("button", { name: "Delete", exact: true }).click();
    await expect(page.getByText(DOMAIN)).toHaveCount(0, { timeout: 15_000 });
  });
});
