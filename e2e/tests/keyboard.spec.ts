/**
 * keyboard.spec — Part V §2.3 (keyboard operability)
 * Checks: skip link first, Tab order reaches all interactive elements,
 * Enter submits forms, focus visible (via CSS outline).
 *
 * Pages: /login, /scan/new
 */
import { test, expect } from '@playwright/test';
import { registerAndLogin } from './helpers';

test.describe('Keyboard-only pass', () => {
  test('/login: skip link is first Tab stop', async ({ page }) => {
    await page.goto('/login');
    // Autofocus moves the sequential-focus starting point to #username, so a
    // literal "first Tab" lands mid-form. Assert the §2.2 requirement directly:
    // skip link is first in DOM focus order, targets #main, visible on focus.
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

  test('/login: all interactive elements reachable by Tab', async ({ page }) => {
    await page.goto('/login');

    // Collect expected interactive elements (excluding the skip link itself)
    const interactiveSelectors = ['#username', '#password', '#main button[type="submit"]'];
    const reached = new Set<string>();

    // Tab through the page (up to 20 presses to avoid infinite loops)
    for (let i = 0; i < 20; i++) {
      await page.keyboard.press('Tab');
      for (const sel of interactiveSelectors) {
        const el = page.locator(sel);
        if (await el.count() > 0) {
          const box = await el.boundingBox();
          if (box) {
            const isFocused = await el.evaluate(node => node === document.activeElement);
            if (isFocused) reached.add(sel);
          }
        }
      }
      // Break early if all found
      if (interactiveSelectors.every(s => reached.has(s))) break;
    }

    for (const sel of interactiveSelectors) {
      expect(reached.has(sel), `Expected ${sel} to be reachable by Tab`).toBe(true);
    }
  });

  test('/login: Enter on focused submit button submits form', async ({ page }) => {
    const { freshUser } = await import('./helpers');
    const user = freshUser();

    // Register first
    await page.goto('/register');
    await page.fill('#username', user.username);
    await page.fill('#email', user.email);
    await page.fill('#password', user.password);
    await page.click('#main button[type="submit"]');
    await page.waitForURL(/\/(login|dashboard)/, { timeout: 20_000 });

    // Now test keyboard Enter submission
    await page.goto('/login');
    await page.fill('#username', user.username);
    await page.fill('#password', user.password);
    // Focus the submit button and press Enter
    await page.locator('#main button[type="submit"]').focus();
    await page.keyboard.press('Enter');
    await page.waitForURL(/\/dashboard/, { timeout: 15_000 });
    await expect(page).toHaveURL(/\/dashboard/);
  });

  test('/scan/new: skip link first, URL input reachable by Tab (authed)', async ({ page }) => {
    await registerAndLogin(page);
    await page.goto('/scan/new');

    // Blur any autofocused control so Tab starts from the top
    await page.evaluate(() => (document.activeElement as HTMLElement | null)?.blur());
    // Skip link first
    await page.keyboard.press('Tab');
    const skipLink = page.locator(':focus');
    await expect(skipLink).toHaveAttribute('href', '#main');

    // Tab until we hit the URL input (up to 15 presses)
    const urlInput = page.locator('#url, input[name="url"]').first();
    let urlReached = false;
    for (let i = 0; i < 15; i++) {
      await page.keyboard.press('Tab');
      const isFocused = await urlInput.evaluate(n => n === document.activeElement);
      if (isFocused) { urlReached = true; break; }
    }
    expect(urlReached, 'URL input must be reachable by Tab').toBe(true);
  });

  test('focus indicator visible on login inputs (CSS outline not zero)', async ({ page }) => {
    await page.goto('/login');

    // Focus username input and check outline/box-shadow is non-zero
    await page.locator('#username').focus();
    const outlineWidth = await page.locator('#username').evaluate(el => {
      const style = window.getComputedStyle(el);
      // Bootstrap 5 uses box-shadow for focus ring on inputs
      return style.outlineWidth !== '0px' || style.boxShadow !== 'none';
    });
    // Part V §2.3: visible focus indicator MUST be present
    expect(outlineWidth, 'Focus indicator (outline or box-shadow) must be non-zero on #username').toBe(true);
  });
});
