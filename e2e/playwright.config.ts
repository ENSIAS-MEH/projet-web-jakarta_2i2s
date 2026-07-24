import { defineConfig, devices } from '@playwright/test';

// Viewports for responsive checks
export const VIEWPORTS = [
  { name: '320', width: 320, height: 568 },
  { name: '375', width: 375, height: 667 },
  { name: '768', width: 768, height: 1024 },
  { name: '1024', width: 1024, height: 768 },
  { name: '1440', width: 1440, height: 900 },
] as const;

export default defineConfig({
  testDir: './tests',
  timeout: 60_000,
  expect: { timeout: 10_000 },
  fullyParallel: false, // sequential: rate-limit budget protection
  retries: 1,
  reporter: [['list'], ['html', { open: 'never' }]],
  use: {
    baseURL: 'http://localhost:8080',
    trace: 'on-first-retry',
    screenshot: 'only-on-failure',
    // No video by default — keeps artifacts small
  },

  projects: [
    // ── chromium: all specs except responsive (responsive has its own projects) ─
    {
      name: 'chromium',
      testIgnore: '**/responsive.spec.ts',
      use: { ...devices['Desktop Chrome'], viewport: { width: 1280, height: 720 } },
    },
    // ── firefox/webkit: smoke only (multi-browser; heavier specs are chromium-only) ─
    {
      name: 'firefox',
      testMatch: ['**/smoke.spec.ts', '**/dashboard.spec.ts'],
      use: { ...devices['Desktop Firefox'], viewport: { width: 1280, height: 720 } },
    },
    {
      name: 'webkit',
      testMatch: ['**/smoke.spec.ts', '**/dashboard.spec.ts'],
      use: { ...devices['Desktop Safari'], viewport: { width: 1280, height: 720 } },
    },

    // ── Responsive checks (chromium only, 5 viewports) ─────────────────────
    ...VIEWPORTS.map(vp => ({
      name: `responsive-${vp.name}`,
      testMatch: ['**/responsive.spec.ts'],
      use: { ...devices['Desktop Chrome'], viewport: { width: vp.width, height: vp.height } },
    })),
  ],
});
