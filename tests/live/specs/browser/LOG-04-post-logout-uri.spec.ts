/**
 * LOG-04: Post Logout Redirect URI
 *
 * Tests that the logout endpoint correctly redirects to the
 * post_logout_redirect_uri when provided and whitelisted.
 */

import { test, expect } from '@playwright/test';
import {
  generatePKCE,
  generateState,
  completeAuthorizationFlow,
  exchangeCodeForTokens,
  buildLogoutUrl,
  TEST_CLIENTS,
  TEST_USERS,
} from '../../support/browser';

test.describe('LOG-04: Post Logout Redirect URI', () => {
  test('should redirect to post_logout_redirect_uri after logout', async ({ page }) => {
    const pkce = generatePKCE();
    const state = generateState();
    const client = TEST_CLIENTS.confidential;
    const user = TEST_USERS.standard;

    // Login and get tokens
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

    // The test-app has postLogoutRedirectUris configured in seed.json
    const postLogoutUri = 'https://example.com/logout';
    const logoutState = generateState();

    const logoutUrl = buildLogoutUrl({
      idTokenHint: tokens.id_token,
      postLogoutRedirectUri: postLogoutUri,
      state: logoutState,
    });

    await page.goto(logoutUrl);

    // Wait for redirect to post_logout_redirect_uri
    await page.waitForURL(url => url.href.startsWith(postLogoutUri), {
      timeout: 30000,
    });

    const finalUrl = new URL(page.url());

    // Verify we're at the post logout URI
    expect(finalUrl.origin + finalUrl.pathname).toBe(postLogoutUri);

    // State should be preserved in the redirect
    expect(finalUrl.searchParams.get('state')).toBe(logoutState);
  });

  test('should include state in post logout redirect', async ({ page }) => {
    const pkce = generatePKCE();
    const state = generateState();
    const client = TEST_CLIENTS.confidential;
    const user = TEST_USERS.standard;

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

    const postLogoutUri = 'https://example.com/logout';
    const logoutState = 'my-custom-state-12345';

    const logoutUrl = buildLogoutUrl({
      idTokenHint: tokens.id_token,
      postLogoutRedirectUri: postLogoutUri,
      state: logoutState,
    });

    await page.goto(logoutUrl);

    await page.waitForURL(url => url.href.startsWith(postLogoutUri), {
      timeout: 30000,
    });

    const finalUrl = new URL(page.url());
    expect(finalUrl.searchParams.get('state')).toBe(logoutState);
  });
});
