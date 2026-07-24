/**
 * dashboard.spec — Part V §3.7 (multi-browser)
 * Flows:
 *   1. /dashboard/public accessible anonymously (no auth required).
 *   2. /dashboard (authed) loads after login.
 */
import { test, expect } from '@playwright/test';
import { registerAndLogin } from './helpers';

test.describe('Dashboard', () => {
  test('public dashboard accessible anonymously', async ({ page }) => {
    // No login required — Part V §3 public access
    await page.goto('/dashboard/public');
    await expect(page).toHaveURL(/\/dashboard\/public/);
    await expect(page).toHaveTitle(/dashboard|community|public|SecBret/i);

    // Page must have a main landmark (§2.2)
    await expect(page.locator('#main, main')).toBeVisible();

    // Should not redirect to login
    await expect(page).not.toHaveURL(/\/login/);
  });

  test('authenticated dashboard loads after login', async ({ page }) => {
    await registerAndLogin(page);
    await expect(page).toHaveURL(/\/dashboard/);
    await expect(page.locator('#main, main')).toBeVisible();

    // Page title should reference dashboard
    await expect(page).toHaveTitle(/dashboard|SecBret/i);
  });
});
