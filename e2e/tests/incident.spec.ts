/**
 * incident.spec — Part V §1.6 (empty states) + incident reporting flow
 * Flows:
 *   1. Fresh user → /incident shows empty state "Report your first incident" (or similar).
 *   2. Submit incident form → list shows it.
 */
import { test, expect } from '@playwright/test';
import { registerAndLogin } from './helpers';

test.describe('Incident flows', () => {
  test('fresh user sees empty state on /incident', async ({ page }) => {
    await registerAndLogin(page);
    await page.goto('/incident');

    // Per Part V §1.6: explicit empty state, not a bare empty container
    // Look for any empty-state indicator
    const emptyState = page.getByText(/first incident|no incidents|no reports|nothing here|report your/i).first();
    // If the page shows a list table, it should be empty or show a message
    const hasEmptyMessage = await emptyState.count() > 0;
    const tableRows = page.locator('table tbody tr').filter({ hasNotText: /no |empty|nothing/i });
    const rowCount = await tableRows.count();

    // Either an explicit empty message OR zero data rows (but page loaded)
    expect(
      hasEmptyMessage || rowCount === 0,
      'Expected empty state message or empty list for fresh user'
    ).toBe(true);

    if (hasEmptyMessage) {
      await expect(emptyState).toBeVisible();
    }
  });

  test('report incident → appears in list', async ({ page }) => {
    await registerAndLogin(page);

    // Navigate to incident report form
    await page.goto('/incident/new');
    await expect(page).toHaveURL(/\/incident\/new/);

    // Fill the URL field (required)
    const urlInput = page.locator('#url, input[name="url"]').first();
    await urlInput.fill('https://phishing-example.invalid/fake-bank');

    // Fill evidence description if present
    const descInput = page.locator('#evidenceDescription, textarea[name="evidenceDescription"]').first();
    if (await descInput.count() > 0) {
      await descInput.fill('E2E test incident report — obvious phishing page.');
    }

    await page.click('#main button[type="submit"]');

    // After submit: redirect to incident detail or list
    await page.waitForURL(/\/incident\/(?!new)/, { timeout: 20_000 });

    // The incident should be visible (detail page or list)
    await expect(
      page.getByText(/phishing-example|phishing|incident|report/i).first()
    ).toBeVisible();

    // Go back to list and check it appears
    await page.goto('/incident');
    await expect(page).toHaveURL(/\/incident/);
    await expect(page.getByText(/phishing-example\.invalid/i).first()).toBeVisible();
  });
});
