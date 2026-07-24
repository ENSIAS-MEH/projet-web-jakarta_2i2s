import { Page, expect } from '@playwright/test';
import * as crypto from 'crypto';

export const BASE = 'http://localhost:8080';

/** Generate a unique username to avoid rate-limit collisions across runs. */
export function freshUser() {
  const tag = crypto.randomBytes(4).toString('hex');
  return {
    username: `e2e${tag}`,
    email: `e2e${tag}@test.invalid`,
    password: 'TestPassphrase!2025',
  };
}

/**
 * Register + login a fresh user; returns the user credentials.
 * Each test that calls this gets a brand-new account → no rate-limit sharing.
 */
export async function registerAndLogin(page: Page) {
  const user = freshUser();

  // Register
  await page.goto('/register');
  await page.fill('#username', user.username);
  await page.fill('#email', user.email);
  await page.fill('#password', user.password);
  await page.click('#main button[type="submit"]');

  // After register → redirect to /login?registered=true or /dashboard
  // Wait for either login page (with registered message) or dashboard
  await page.waitForURL(/\/(login|dashboard)/, { timeout: 15_000 });

  // If redirected to login, sign in
  if (page.url().includes('/login')) {
    await page.fill('#username', user.username);
    await page.fill('#password', user.password);
    await page.click('#main button[type="submit"]');
    await page.waitForURL(/\/dashboard/, { timeout: 15_000 });
  }

  return user;
}

/**
 * Login an existing user (admin promoted via DB).
 */
export async function loginAs(page: Page, username: string, password: string) {
  await page.goto('/login');
  await page.fill('#username', username);
  await page.fill('#password', password);
  await page.click('#main button[type="submit"]');
  await page.waitForURL(/\/dashboard/, { timeout: 15_000 });
}

/** Promote a user to ADMIN via psql. Only works in local dev. */
export async function promoteToAdmin(username: string) {
  const { execSync } = await import('child_process');
  // Use docker exec directly (container name is stable in local dev)
  // M-12: pass the username as a psql variable (:'user') instead of
  // interpolating it straight into the SQL string, removing the injection footgun.
  execSync(
    `docker exec -i aaa_specs-postgres-1 psql -U secbret -d secbret ` +
      `-v user="${username}" -c "UPDATE secbret_user SET role='ADMIN' WHERE username=:'user'"`,
    { stdio: 'pipe' }
  );
}
