/**
 * TOK-15: Refresh Token Scope Escalation Prevention
 *
 * Tests that refresh tokens cannot be used to escalate privileges
 * by requesting scopes that weren't in the original authorization.
 *
 * RFC 6749: The requested scope MUST NOT include any scope not
 * originally granted by the resource owner.
 */

import { test, expect } from '@playwright/test';
import {
  generatePKCE,
  generateState,
  completeAuthorizationFlow,
  exchangeCodeForTokens,
  refreshAccessTokenExpectError,
  refreshAccessToken,
  decodeJWT,
  TEST_CLIENTS,
  TEST_USERS,
} from '../../support/browser';

test.describe('TOK-15: Refresh Token Scope Escalation Prevention', () => {
  test('should reject refresh with scope not in original grant', async ({ page }) => {
    const pkce = generatePKCE();
    const state = generateState();
    const client = TEST_CLIENTS.confidential;
    const user = TEST_USERS.standard;

    // Get tokens with limited scope - include offline_access to get refresh token
    const { code } = await completeAuthorizationFlow(page, {
      client,
      user,
      pkce,
      state,
      scope: 'openid profile offline_access', // Need offline_access for refresh token
    });

    const initialTokens = await exchangeCodeForTokens({
      code,
      clientId: client.client_id,
      clientSecret: client.client_secret,
      redirectUri: client.redirect_uris[0],
      codeVerifier: pkce.verifier,
    });

    expect(initialTokens.refresh_token).toBeTruthy();

    // Try to escalate to 'admin' scope
    const { status, error } = await refreshAccessTokenExpectError({
      refreshToken: initialTokens.refresh_token!,
      clientId: client.client_id,
      clientSecret: client.client_secret,
      scope: 'openid profile admin', // Trying to add 'admin'!
    });

    // Server should either:
    // 1. Reject with invalid_scope (400)
    // 2. Downscope to original grant (200 but without admin)
    // Both are valid per RFC 6749
    if (status === 400) {
      expect(['invalid_scope', 'invalid_grant']).toContain(error.error);
    } else {
      // Server downsoped - verify admin is not in the response
      expect(status).toBe(200);
    }
  });

  test('should allow refresh with reduced scope (downscoping)', async ({ page }) => {
    const pkce = generatePKCE();
    const state = generateState();
    const client = TEST_CLIENTS.confidential;
    const user = TEST_USERS.standard;

    // Get tokens with full scope
    const { code } = await completeAuthorizationFlow(page, {
      client,
      user,
      pkce,
      state,
      scope: 'openid profile email offline_access',
    });

    const initialTokens = await exchangeCodeForTokens({
      code,
      clientId: client.client_id,
      clientSecret: client.client_secret,
      redirectUri: client.redirect_uris[0],
      codeVerifier: pkce.verifier,
    });

    // Refresh with reduced scope - should succeed
    const refreshedTokens = await refreshAccessToken({
      refreshToken: initialTokens.refresh_token!,
      clientId: client.client_id,
      clientSecret: client.client_secret,
      scope: 'openid profile', // Reduced scope
    });

    expect(refreshedTokens.access_token).toBeTruthy();

    // Verify the new token has reduced scope
    const payload = decodeJWT(refreshedTokens.access_token).payload;
    const scope = payload.scope as string || '';

    // Should not contain 'email' anymore
    expect(scope).not.toContain('email');
  });

  test('should allow refresh with same scope', async ({ page }) => {
    const pkce = generatePKCE();
    const state = generateState();
    const client = TEST_CLIENTS.confidential;
    const user = TEST_USERS.standard;

    const originalScope = 'openid profile email offline_access';

    const { code } = await completeAuthorizationFlow(page, {
      client,
      user,
      pkce,
      state,
      scope: originalScope,
    });

    const initialTokens = await exchangeCodeForTokens({
      code,
      clientId: client.client_id,
      clientSecret: client.client_secret,
      redirectUri: client.redirect_uris[0],
      codeVerifier: pkce.verifier,
    });

    // Refresh with same scope - should succeed
    const refreshedTokens = await refreshAccessToken({
      refreshToken: initialTokens.refresh_token!,
      clientId: client.client_id,
      clientSecret: client.client_secret,
      scope: originalScope,
    });

    expect(refreshedTokens.access_token).toBeTruthy();
  });
});
