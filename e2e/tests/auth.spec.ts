/**
 * auth.spec — Part V §1 (error-to-UI) + §2 (a11y basics) + §3.7 (multi-browser)
 * Flows: register → login → dashboard → logout; wrong-password error rendering.
 *
 * Tagged: all browsers (chromium/firefox/webkit run this via the default project filter).
 */
import { test, expect } from '@playwright/test';
import { freshUser } from './helpers';

test.describe('Auth flows', () => {
  test('register → login → dashboard → logout', async ({ page }) => {
    const user = freshUser();

    // ── Register ──────────────────────────────────────────────────────────
    await page.goto('/register');
    await expect(page).toHaveTitle(/Register|Sign up|Create account/i);

    await page.fill('#username', user.username);
    await page.fill('#email', user.email);
    await page.fill('#password', user.password);
    await page.click('#main button[type="submit"]');

    // After registration: either lands on dashboard or login with ?registered=true
    await page.waitForURL(/\/(login|dashboard)/, { timeout: 20_000 });

    if (page.url().includes('/login')) {
      // ── Login ──────────────────────────────────────────────────────────
      await page.fill('#username', user.username);
      await page.fill('#password', user.password);
      await page.click('#main button[type="submit"]');
      await page.waitForURL(/\/dashboard/, { timeout: 20_000 });
    }

    // ── Dashboard ──────────────────────────────────────────────────────────
    await expect(page).toHaveURL(/\/dashboard/);
    // Username appears somewhere on the page (nav or welcome heading)
    await expect(page.getByText(user.username, { exact: false }).first()).toBeVisible();

    // ── Logout ─────────────────────────────────────────────────────────────
    // Find the logout form/button — Bootstrap nav
    // Per HTML: <form action="/logout"><button>Sign out</button></form>
    const logoutEl = page.locator('form[action="/logout"] button[type="submit"]');
    await logoutEl.click();
    await page.waitForURL(/\/(login|$|\?)/, { timeout: 10_000 });
    // Should not be on dashboard
    await expect(page).not.toHaveURL(/\/dashboard(?!\/public)/);
  });

  test('wrong password shows error message', async ({ page }) => {
    const user = freshUser();

    // Register first
    await page.goto('/register');
    await page.fill('#username', user.username);
    await page.fill('#email', user.email);
    await page.fill('#password', user.password);
    await page.click('#main button[type="submit"]');
    await page.waitForURL(/\/(login|dashboard)/, { timeout: 20_000 });

    // Now go to login with wrong password
    await page.goto('/login');
    await page.fill('#username', user.username);
    await page.fill('#password', 'WrongPassword!999');
    await page.click('#main button[type="submit"]');

    // Should stay on login page with error
    await expect(page).toHaveURL(/\/login/);

    // Per Part V §1.1: 401 → re-render form with error; §1.5: role="alert"
    const errorRegion = page.locator('[role="alert"], .alert-danger, .text-danger').first();
    await expect(errorRegion).toBeVisible({ timeout: 5_000 });
    // Error text should mention invalid credentials (not expose internals)
    await expect(errorRegion).toContainText(/invalid|incorrect|password|username/i);
  });

  test('login page has skip link as first focusable element', async ({ page }) => {
    await page.goto('/login');
    // The login form autofocuses #username, and Chromium's sequential-focus
    // starting point follows it even after blur — so "Tab once from load" is
    // not deterministic. Instead assert the Part V §2.2 requirements directly:
    // the skip link is the first focusable element in DOM order, targets #main,
    // and becomes visible when focused.
    const firstFocusable = await page.evaluate(() => {
      const el = document.querySelector(
        'a[href], button, input, select, textarea, [tabindex]:not([tabindex="-1"])'
      );
      return el ? el.getAttribute('href') : null;
    });
    expect(firstFocusable, 'First focusable element must be the #main skip link').toBe('#main');

    const skip = page.locator('a.skip-link');
    await skip.focus();
    await expect(skip, 'Skip link must be visible when focused').toBeVisible();
  });
});
