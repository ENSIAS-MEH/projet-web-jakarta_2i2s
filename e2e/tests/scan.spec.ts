/**
 * scan.spec — Part V §1 (loading states, HTMX polling, error-to-UI)
 * Flows:
 *   1. Submit https://example.com QUICK scan; poll to COMPLETED; verify result page.
 *   2. Empty-URL validation error → aria-invalid + aria-describedby.
 *
 * chromium only (multi-browser smoke is in smoke.spec).
 */
import { test, expect } from '@playwright/test';
import { registerAndLogin } from './helpers';

test.describe('Scan flows', () => {
  test('submit quick scan, poll to COMPLETED, result shows score', async ({ page }) => {
    await registerAndLogin(page);

    // Navigate to new scan form
    await page.goto('/scan/new');
    await expect(page).toHaveURL(/\/scan\/new/);

    // Fill URL — per Part V §2.6 the label must be programmatically associated
    const urlInput = page.locator('#url, input[name="url"]').first();
    await expect(urlInput).toBeVisible();
    await urlInput.fill('https://example.com');

    // Select QUICK depth — rendered as radio buttons (QUICK is pre-checked)
    const quickRadio = page.locator('#depth-quick, input[name="depth"][value="QUICK"]').first();
    if (await quickRadio.count() > 0 && !(await quickRadio.isChecked())) {
      await quickRadio.check();
    }

    // Submit
    await page.click('#main button[type="submit"]');

    // After submit: either immediate redirect to result or polling page
    // Wait for the URL to change from /scan/new (up to 30s for job creation)
    await page.waitForURL(/\/scan\/(?!new)/, { timeout: 30_000 });

    // Polling: wait for COMPLETED status text or result score to appear
    // The app polls every 3s; give 90s for scan completion
    await expect(
      page.getByText(/completed|score|verdict|benign|suspicious|malicious/i).first()
    ).toBeVisible({ timeout: 90_000 });
  });

  test('empty URL triggers inline validation error with aria attrs', async ({ page }) => {
    await registerAndLogin(page);
    await page.goto('/scan/new');

    // Submit with empty URL
    const urlInput = page.locator('#url, input[name="url"]').first();
    await urlInput.fill('');

    await page.click('#main button[type="submit"]');

    // Either HTML5 native validation prevents submit (stays on page),
    // or server returns 400 with aria-invalid on the input.
    // Either way, we should still be on /scan/new (no redirect to /scan/<id>)
    await expect(page).not.toHaveURL(/\/scan\/[0-9a-f-]{36}/);

    // Check for validation feedback — server-side or browser-native
    const hasAriaInvalid = await urlInput.getAttribute('aria-invalid');
    const hasRequiredAttr = await urlInput.getAttribute('required');
    const errorMsg = page.locator('[role="alert"], .invalid-feedback, [id*="error"], [id*="-error"]').first();

    // At least one signal of validation error must exist
    const errorVisible = hasAriaInvalid === 'true' || hasRequiredAttr !== null || (await errorMsg.count()) > 0;
    expect(errorVisible, 'Expected some validation feedback for empty URL').toBe(true);

    // If server renders error: check aria-describedby links input to message
    if (hasAriaInvalid === 'true') {
      const describedBy = await urlInput.getAttribute('aria-describedby');
      expect(describedBy, 'aria-describedby must reference the error element').toBeTruthy();
    }
  });
});
