import { expect, type Page } from "@playwright/test";

export const ADMIN_EMAIL = process.env.PORTLYN_TEST_ADMIN_EMAIL || "admin@example.test";

export const INITIAL_PASSWORD = process.env.PORTLYN_TEST_ADMIN_PASSWORD || "ChangeMeStrongerPasswordPlease!";

export const ADMIN_PASSWORD = process.env.PORTLYN_TEST_ADMIN_PASSWORD_AFTER_SETUP || "E2eSuitePassword!2026";

export const liveOnly = !process.env.PORTLYN_E2E_LIVE;
export const liveReason = "set PORTLYN_E2E_LIVE=1 to run against a live instance";

export async function fillLoginForm(page: Page, email: string, password: string) {
  await page.getByLabel("Email", { exact: true }).fill(email);
  await page.getByLabel("Password", { exact: true }).fill(password);
  await page.getByRole("button", { name: "Login", exact: true }).click();
}

export async function signIn(page: Page, email = ADMIN_EMAIL, password = ADMIN_PASSWORD) {
  await page.goto("/login");
  await fillLoginForm(page, email, password);
}

export async function signInExpectingSuccess(page: Page) {
  await signIn(page);
  await expect(page).toHaveURL(/\/services/, { timeout: 15_000 });
  await dismissSetupWizard(page);
}

export function setupWizardTitle(page: Page) {
  return page.getByText("Finish setting up Portlyn");
}

export async function dismissSetupWizard(page: Page) {
  const wizard = setupWizardTitle(page);
  if (!(await wizard.isVisible().catch(() => false))) {
    return;
  }
  const skip = page.getByRole("button", { name: "Skip for now" });
  if (await skip.isVisible().catch(() => false)) {
    await skip.click();
    await expect(wizard).toBeHidden({ timeout: 15_000 });
  }
}
