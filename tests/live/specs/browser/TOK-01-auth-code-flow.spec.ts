/**
 * TOK-01: Authorization Code Flow (Happy Path)
 *
 * Tests the complete OAuth 2.1 authorization code flow:
 * 1. Navigate to /authorize with PKCE
 * 2. Login with username/password
 * 3. Receive authorization code via redirect
 * 4. Exchange code for tokens
 * 5. Validate token response
 */

import { test, expect } from '@playwright/test';
import {
  generatePKCE,
  generateState,
  buildAuthorizationUrl,
  login,
  extractCodeFromUrl,
  extractStateFromUrl,
  exchangeCodeForTokens,
  TEST_CLIENTS,
  TEST_USERS,
} from '../../support/browser';

test.describe('TOK-01: Authorization Code Flow', () => {
  test('should complete full auth code flow with PKCE', async ({ page }) => {
    // Arrange
    const { verifier, challenge } = generatePKCE();
    const state = generateState();
    const client = TEST_CLIENTS.public;
    const user = TEST_USERS.standard;

    const authUrl = buildAuthorizationUrl({
      clientId: client.client_id,
      redirectUri: client.redirect_uris[0],
      scope: 'openid profile email',
      state,
      codeChallenge: challenge,
      codeChallengeMethod: 'S256',
    });

    // Act - Navigate to authorize endpoint
    await page.goto(authUrl);

    // Should redirect to login page
    await expect(page).toHaveURL(/\/auth\/login|\/login/);

    // Login with test user
    await login(page, user.email, user.password);

    // Wait for redirect back to client with code
    await page.waitForURL(url => url.href.startsWith(client.redirect_uris[0]), {
      timeout: 30000,
    });

    const redirectUrl = page.url();

    // Extract code and state from redirect
    const code = extractCodeFromUrl(redirectUrl);
    const returnedState = extractStateFromUrl(redirectUrl);

    // Assert - Code received and state matches
    expect(code).toBeTruthy();
    expect(returnedState).toBe(state);

    // Exchange code for tokens
    const tokens = await exchangeCodeForTokens({
      code: code!,
      clientId: client.client_id,
      redirectUri: client.redirect_uris[0],
      codeVerifier: verifier,
    });

    // Assert - Valid token response
    expect(tokens.access_token).toBeTruthy();
    expect(tokens.token_type.toLowerCase()).toBe('bearer');
    expect(tokens.expires_in).toBeGreaterThan(0);
    expect(tokens.id_token).toBeTruthy(); // OIDC flow should include id_token
  });

  test('should include refresh token for confidential client', async ({ page }) => {
    // Arrange
    const { verifier, challenge } = generatePKCE();
    const state = generateState();
    const client = TEST_CLIENTS.confidential;
    const user = TEST_USERS.standard;

    const authUrl = buildAuthorizationUrl({
      clientId: client.client_id,
      redirectUri: client.redirect_uris[0],
      scope: 'openid profile email offline_access',
      state,
      codeChallenge: challenge,
      codeChallengeMethod: 'S256',
    });

    // Act
    await page.goto(authUrl);
    await login(page, user.email, user.password);

    await page.waitForURL(url => url.href.startsWith(client.redirect_uris[0]), {
      timeout: 30000,
    });

    const code = extractCodeFromUrl(page.url());
    expect(code).toBeTruthy();

    const tokens = await exchangeCodeForTokens({
      code: code!,
      clientId: client.client_id,
      clientSecret: client.client_secret,
      redirectUri: client.redirect_uris[0],
      codeVerifier: verifier,
    });

    // Assert - Confidential client with offline_access gets refresh token
    expect(tokens.access_token).toBeTruthy();
    expect(tokens.refresh_token).toBeTruthy();
    expect(tokens.id_token).toBeTruthy();
  });
});
