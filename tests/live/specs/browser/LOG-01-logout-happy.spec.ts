/**
 * LOG-01: Logout Happy Path
 *
 * Tests the RP-initiated logout flow per OpenID Connect RP-Initiated Logout 1.0.
 * The user should be logged out and the session should be terminated.
 */

import { test, expect } from '@playwright/test';
import {
  generatePKCE,
  generateState,
  completeAuthorizationFlow,
  exchangeCodeForTokens,
  buildLogoutUrl,
  buildAuthorizationUrl,
  extractErrorFromUrl,
  TEST_CLIENTS,
  TEST_USERS,
} from '../../support/browser';

test.describe('LOG-01: Logout Happy Path', () => {
  test('should logout user with valid id_token_hint', async ({ page }) => {
    const pkce = generatePKCE();
    const state = generateState();
    const client = TEST_CLIENTS.confidential;
    const user = TEST_USERS.standard;

    // First, login and get tokens
    const { code } = await completeAuthorizationFlow(page, {
      client,
      user,
      pkce,
      state,
      scope: 'openid profile email',
    });

    const tokens = await exchangeCodeForTokens({
      code,
      clientId: client.client_id,
      clientSecret: client.client_secret,
      redirectUri: client.redirect_uris[0],
      codeVerifier: pkce.verifier,
    });

    expect(tokens.id_token).toBeTruthy();

    // Navigate to logout endpoint with id_token_hint
    const logoutUrl = buildLogoutUrl({
      idTokenHint: tokens.id_token,
    });

    await page.goto(logoutUrl);

    // Should show logout confirmation or redirect
    // Wait for the page to settle
    await page.waitForLoadState('networkidle');

    // Verify session is terminated by trying prompt=none
    const silentAuthUrl = buildAuthorizationUrl({
      clientId: client.client_id,
      redirectUri: client.redirect_uris[0],
      scope: 'openid',
      state: generateState(),
      codeChallenge: generatePKCE().challenge,
      codeChallengeMethod: 'S256',
      prompt: 'none',
    });

    await page.goto(silentAuthUrl);

    // Wait for redirect
    await page.waitForURL(url => {
      return url.href.startsWith(client.redirect_uris[0]) ||
             url.href.includes('error=');
    }, { timeout: 10000 });

    // Should get login_required error since session is gone
    const error = extractErrorFromUrl(page.url());
    expect(error).toBeTruthy();
    expect(error!.error).toBe('login_required');
  });

  test('should clear session cookies on logout', async ({ page, context }) => {
    const pkce = generatePKCE();
    const state = generateState();
    const client = TEST_CLIENTS.confidential;
    const user = TEST_USERS.standard;

    // Login
    const { code } = await completeAuthorizationFlow(page, {
      client,
      user,
      pkce,
      state,
    });

    const tokens = await exchangeCodeForTokens({
      code,
      clientId: client.client_id,
      clientSecret: client.client_secret,
      redirectUri: client.redirect_uris[0],
      codeVerifier: pkce.verifier,
    });

    // Get cookies before logout
    const cookiesBefore = await context.cookies();
    const sessionCookiesBefore = cookiesBefore.filter(c =>
      c.name.toLowerCase().includes('session') ||
      c.name.toLowerCase().includes('sid')
    );

    // Logout
    const logoutUrl = buildLogoutUrl({
      idTokenHint: tokens.id_token,
    });

    await page.goto(logoutUrl);
    await page.waitForLoadState('networkidle');

    // Get cookies after logout
    const cookiesAfter = await context.cookies();
    const sessionCookiesAfter = cookiesAfter.filter(c =>
      c.name.toLowerCase().includes('session') ||
      c.name.toLowerCase().includes('sid')
    );

    // Session cookies should be cleared or changed
    if (sessionCookiesBefore.length > 0) {
      // Either no session cookies, or they have different values
      const beforeValues = sessionCookiesBefore.map(c => c.value).sort();
      const afterValues = sessionCookiesAfter.map(c => c.value).sort();
      expect(afterValues).not.toEqual(beforeValues);
    }
  });
});
