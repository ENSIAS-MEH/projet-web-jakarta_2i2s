/**
 * smoke.spec — Part V §3.7 multi-browser smoke
 * Runs on chromium, firefox, webkit (all three default projects).
 * Flows: login + public dashboard — the minimal "is it alive on this engine?" check.
 * Heavier flows (scan, incident, review) are chromium-only to keep total runtime sane.
 */
import { test, expect } from '@playwright/test';
import { registerAndLogin } from './helpers';

test.describe('Multi-browser smoke', () => {
  test('public dashboard loads without login', async ({ page }) => {
    await page.goto('/dashboard/public');
    await expect(page).toHaveURL(/\/dashboard\/public/);
    // Must not redirect to login
    await expect(page).not.toHaveURL(/\/login/);
    // Main landmark exists
    await expect(page.locator('#main, main')).toBeVisible();
  });

  test('login and reach authed dashboard', async ({ page }) => {
    const user = await registerAndLogin(page);
    await expect(page).toHaveURL(/\/dashboard/);
    // Confirm username is in the page (nav + welcome text both show it)
    await expect(page.getByText(user.username, { exact: false }).first()).toBeVisible();
  });
});
