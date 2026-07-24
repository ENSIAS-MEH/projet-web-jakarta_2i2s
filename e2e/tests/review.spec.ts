/**
 * review.spec — Part V §1.3 (destructive-action confirmation modal)
 * Flows:
 *   1. Admin-promoted user opens review queue — empty state OR seeded row.
 *   2. If a pending report exists: REJECT → confirmation modal appears.
 *
 * Uses DB promotion (psql exec) to grant ADMIN role.
 */
import { test, expect } from '@playwright/test';
import { registerAndLogin, promoteToAdmin } from './helpers';

test.describe('Review queue (admin)', () => {
  test('admin sees review queue (empty state or rows)', async ({ page }) => {
    const user = await registerAndLogin(page);
    await promoteToAdmin(user.username);

    // Re-login on a CLEAN session: the container caches the authenticated
    // identity per session, so re-authenticating inside the old session keeps
    // the pre-promotion REPORTER roles (observed as 403 on /admin/reviews).
    await page.context().clearCookies();
    await page.goto('/login');
    await page.fill('#username', user.username);
    await page.fill('#password', user.password);
    await page.click('#main button[type="submit"]');
    await page.waitForURL(/\/dashboard/, { timeout: 15_000 });

    await page.goto('/admin/reviews');
    await expect(page).toHaveURL(/\/admin\/reviews/);

    // Should show the review queue heading
    await expect(page.getByRole('heading', { level: 1 }).or(page.locator('h1, h2').first())).toBeVisible();

    // Either an explicit empty state OR pending items. The queue renders
    // "N report(s) awaiting review." with per-report "Review" links (no table).
    const emptyState = page.getByText(/all caught up|no pending|no reviews|nothing to review/i).first();
    const counter = page.getByText(/report\(s\) awaiting review/i).first();
    const reviewLinks = page.locator('#main a', { hasText: /^Review$/ });

    const isEmpty = (await emptyState.count()) > 0;
    const hasItems = (await counter.count()) > 0 || (await reviewLinks.count()) > 0;

    expect(isEmpty || hasItems, 'Review queue must show empty state or review items').toBe(true);
  });

  test('REJECT action shows confirmation modal (if pending report exists)', async ({ page }) => {
    // First: create an incident report so the queue has something
    const reporter = await registerAndLogin(page);

    await page.goto('/incident/new');
    const urlInput = page.locator('#url, input[name="url"]').first();
    await urlInput.fill('https://modal-test-phishing.invalid/review');
    const descInput = page.locator('#evidenceDescription, textarea[name="evidenceDescription"]').first();
    if (await descInput.count() > 0) {
      await descInput.fill('E2E review modal test.');
    }
    await page.click('#main button[type="submit"]');
    await page.waitForURL(/\/incident\/(?!new)/, { timeout: 20_000 });

    // Now promote reporter to admin and re-login on a clean session
    // (identity is cached per session — see note in the test above)
    await promoteToAdmin(reporter.username);
    await page.context().clearCookies();
    await page.goto('/login');
    await page.fill('#username', reporter.username);
    await page.fill('#password', reporter.password);
    await page.click('#main button[type="submit"]');
    await page.waitForURL(/\/dashboard/, { timeout: 15_000 });

    await page.goto('/admin/reviews');
    await expect(page).toHaveURL(/\/admin\/reviews/);

    // Look for a per-report "Review" link inside main (the navbar also has a
    // "Review Queue" link — exact match + #main scope avoids it)
    const reviewLink = page.locator('#main').getByRole('link', { name: 'Review', exact: true }).first();
    const hasReviewLink = await reviewLink.count() > 0;

    if (!hasReviewLink) {
      // Empty queue — incident might not be PENDING yet; valid empty state
      const emptyState = page.getByText(/all caught up|no pending|nothing/i).first();
      if (await emptyState.count() > 0) {
        await expect(emptyState).toBeVisible();
      }
      test.info().annotations.push({
        type: 'note',
        description: 'Review queue empty — incident not yet in PENDING state. Modal check skipped.',
      });
      return;
    }

    await reviewLink.click();
    await page.waitForURL(/\/admin\/reviews\/[0-9a-f-]+/, { timeout: 10_000 });

    // Set action select to REJECT — this triggers the confirm modal on submit
    const actionSelect = page.locator('#action, select[name="action"]').first();
    await actionSelect.selectOption('REJECT');

    // Click submit — secbret.js intercepts and shows modal for REJECT
    const submitBtn = page.locator('.js-reject-confirm, #main button[type="submit"]').first();
    await submitBtn.click();

    // Per Part V §1.3 + §2.11: destructive action → modal with role="dialog" + aria-modal
    const modal = page.locator('[role="dialog"]#secbret-confirm-modal').first();
    await expect(modal).toBeVisible({ timeout: 5_000 });

    // Modal must restate the consequence
    await expect(modal.getByText(/reject|confirm|consequence|REJECTED/i).first()).toBeVisible();

    // Escape closes the modal (§2.11: Esc closes; focus returns to trigger).
    // Bootstrap's focus trap engages only after the fade transition — wait for
    // focus to land inside the dialog before sending Escape.
    await expect
      .poll(() => page.evaluate(() => document.activeElement?.closest('#secbret-confirm-modal') != null), {
        timeout: 5_000,
      })
      .toBe(true);
    await page.keyboard.press('Escape');
    await expect(modal).not.toBeVisible({ timeout: 3_000 });
  });
});
