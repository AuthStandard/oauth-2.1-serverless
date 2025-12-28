/**
 * HPF-01: Password Login
 *
 * Tests the basic password login flow - user submits credentials
 * via the login form and gets authenticated.
 */

import { test, expect } from '@playwright/test';
import {
  generatePKCE,
  generateState,
  buildAuthorizationUrl,
  login,
  extractCodeFromUrl,
  TEST_CLIENTS,
  TEST_USERS,
} from '../../support/browser';

test.describe('HPF-01: Password Login', () => {
  test('should successfully login with valid credentials', async ({ page }) => {
    const pkce = generatePKCE();
    const state = generateState();
    const client = TEST_CLIENTS.public;
    const user = TEST_USERS.standard;

    // Navigate to authorize endpoint
    const authUrl = buildAuthorizationUrl({
      clientId: client.client_id,
      redirectUri: client.redirect_uris[0],
      scope: 'openid profile email',
      state,
      codeChallenge: pkce.challenge,
      codeChallengeMethod: 'S256',
    });

    await page.goto(authUrl);

    // Should be redirected to login page
    await expect(page).toHaveURL(/\/auth\/login|\/login/);

    // Login form should be visible
    await expect(page.locator('input[name="email"], input[type="email"]')).toBeVisible();
    await expect(page.locator('input[name="password"], input[type="password"]')).toBeVisible();

    // Submit valid credentials
    await login(page, user.email, user.password);

    // Should redirect back to client with authorization code
    await page.waitForURL(url => url.href.startsWith(client.redirect_uris[0]), {
      timeout: 30000,
    });

    const code = extractCodeFromUrl(page.url());
    expect(code).toBeTruthy();
  });

  test('should preserve authorization parameters through login', async ({ page }) => {
    const pkce = generatePKCE();
    const state = 'my-unique-state-12345';
    const client = TEST_CLIENTS.public;
    const user = TEST_USERS.standard;

    const authUrl = buildAuthorizationUrl({
      clientId: client.client_id,
      redirectUri: client.redirect_uris[0],
      scope: 'openid profile',
      state,
      codeChallenge: pkce.challenge,
      codeChallengeMethod: 'S256',
    });

    await page.goto(authUrl);
    await login(page, user.email, user.password);

    await page.waitForURL(url => url.href.startsWith(client.redirect_uris[0]), {
      timeout: 30000,
    });

    // State should be preserved
    const finalUrl = new URL(page.url());
    expect(finalUrl.searchParams.get('state')).toBe(state);
  });

  test('should complete login flow successfully', async ({ page }) => {
    const pkce = generatePKCE();
    const state = generateState();
    const client = TEST_CLIENTS.public;
    const user = TEST_USERS.standard;

    const authUrl = buildAuthorizationUrl({
      clientId: client.client_id,
      redirectUri: client.redirect_uris[0],
      scope: 'openid',
      state,
      codeChallenge: pkce.challenge,
      codeChallengeMethod: 'S256',
    });

    await page.goto(authUrl);
    await login(page, user.email, user.password);

    await page.waitForURL(url => url.href.startsWith(client.redirect_uris[0]), {
      timeout: 30000,
    });

    // Verify authorization code was issued
    const code = extractCodeFromUrl(page.url());
    expect(code).toBeTruthy();

    // Verify session cookie was set (for prompt=none support)
    const cookies = await page.context().cookies();
    const sessionCookie = cookies.find(c => c.name === '__Host-sid' || c.name.includes('sid'));
    expect(sessionCookie).toBeTruthy();
    expect(sessionCookie!.httpOnly).toBe(true);
    expect(sessionCookie!.secure).toBe(true);
  });

  test('should handle login for different users', async ({ page }) => {
    const client = TEST_CLIENTS.public;

    // Test with standard user
    const pkce1 = generatePKCE();
    const state1 = generateState();

    await page.goto(buildAuthorizationUrl({
      clientId: client.client_id,
      redirectUri: client.redirect_uris[0],
      scope: 'openid',
      state: state1,
      codeChallenge: pkce1.challenge,
      codeChallengeMethod: 'S256',
    }));

    await login(page, TEST_USERS.standard.email, TEST_USERS.standard.password);

    await page.waitForURL(url => url.href.startsWith(client.redirect_uris[0]), {
      timeout: 30000,
    });

    expect(extractCodeFromUrl(page.url())).toBeTruthy();

    // Clear cookies and test with admin user
    await page.context().clearCookies();

    const pkce2 = generatePKCE();
    const state2 = generateState();

    await page.goto(buildAuthorizationUrl({
      clientId: client.client_id,
      redirectUri: client.redirect_uris[0],
      scope: 'openid',
      state: state2,
      codeChallenge: pkce2.challenge,
      codeChallengeMethod: 'S256',
    }));

    await login(page, TEST_USERS.admin.email, TEST_USERS.admin.password);

    await page.waitForURL(url => url.href.startsWith(client.redirect_uris[0]), {
      timeout: 30000,
    });

    expect(extractCodeFromUrl(page.url())).toBeTruthy();
  });
});
