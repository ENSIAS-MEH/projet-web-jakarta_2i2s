/**
 * responsive.spec — Part V §3.1–3.4 (responsive strategy)
 * Asserts no horizontal overflow at each of the 5 viewport widths.
 * Runs via the `responsive-*` playwright projects (chromium only, per config).
 *
 * Pages checked: /login, /dashboard/public, /scan/new (authed)
 *
 * Tolerance: scrollWidth <= viewportWidth + 1px (sub-pixel rounding)
 */
import { test, expect } from '@playwright/test';
import { registerAndLogin } from './helpers';

const OVERFLOW_TOLERANCE = 1; // px; sub-pixel rounding allowance

async function assertNoHorizontalOverflow(page: import('@playwright/test').Page, url: string) {
  await page.goto(url);
  const { scrollWidth, viewportWidth } = await page.evaluate(() => ({
    scrollWidth: document.documentElement.scrollWidth,
    viewportWidth: window.innerWidth,
  }));
  expect(
    scrollWidth,
    `Horizontal overflow on ${url} at ${viewportWidth}px: scrollWidth=${scrollWidth}px`
  ).toBeLessThanOrEqual(viewportWidth + OVERFLOW_TOLERANCE);
}

test.describe('Responsive: no horizontal overflow', () => {
  test('no overflow on /login', async ({ page }) => {
    await assertNoHorizontalOverflow(page, '/login');
  });

  test('no overflow on /dashboard/public', async ({ page }) => {
    await assertNoHorizontalOverflow(page, '/dashboard/public');
  });

  test('no overflow on /register', async ({ page }) => {
    await assertNoHorizontalOverflow(page, '/register');
  });

  test('no overflow on /scan/new (authed)', async ({ page }) => {
    await registerAndLogin(page);
    await assertNoHorizontalOverflow(page, '/scan/new');
  });
});
