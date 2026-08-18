import { chromium, expect, type FullConfig } from "@playwright/test";

import {
  ADMIN_EMAIL,
  ADMIN_PASSWORD,
  dismissSetupWizard,
  fillLoginForm,
  INITIAL_PASSWORD,
  setupWizardTitle
} from "./helpers";

async function globalSetup(config: FullConfig) {
  if (!process.env.PORTLYN_E2E_LIVE) {
    return;
  }

  const baseURL = config.projects[0]?.use?.baseURL || process.env.PLAYWRIGHT_BASE_URL || "http://localhost:3000";
  const browser = await chromium.launch();
  const page = await browser.newPage({ baseURL, ignoreHTTPSErrors: true });

  try {
    await page.goto("/login");
    await fillLoginForm(page, ADMIN_EMAIL, ADMIN_PASSWORD);
    const alreadySetUp = await page
      .waitForURL(/\/services/, { timeout: 8_000 })
      .then(() => true)
      .catch(() => false);

    if (alreadySetUp) {
      await dismissSetupWizard(page);
      return;
    }

    await page.goto("/login");
    await fillLoginForm(page, ADMIN_EMAIL, INITIAL_PASSWORD);
    await page.waitForURL(/\/services/, { timeout: 15_000 });

    const wizard = setupWizardTitle(page);
    await expect(wizard).toBeVisible({ timeout: 15_000 });

    const newPassword = page.getByLabel("New password");
    if (await newPassword.isVisible().catch(() => false)) {
      await newPassword.fill(ADMIN_PASSWORD);
      await page.getByLabel("Confirm password").fill(ADMIN_PASSWORD);
      await page.getByRole("button", { name: "Save and continue" }).click();
      await expect(newPassword).toBeHidden({ timeout: 15_000 });
    }

    await dismissSetupWizard(page);
    await expect(wizard).toBeHidden({ timeout: 15_000 });
  } finally {
    await browser.close();
  }
}

export default globalSetup;
