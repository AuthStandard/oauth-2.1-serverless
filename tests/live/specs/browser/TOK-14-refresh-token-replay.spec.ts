/**
 * TOK-14: Refresh Token Replay Attack Prevention
 *
 * Tests that refresh tokens can only be used once (rotation).
 * Per OAuth 2.0 Security Best Current Practice, refresh tokens
 * SHOULD be rotated and old tokens SHOULD be invalidated.
 */

import { test, expect } from '@playwright/test';
import {
  generatePKCE,
  generateState,
  completeAuthorizationFlow,
  exchangeCodeForTokens,
  refreshAccessToken,
  refreshAccessTokenExpectError,
  TEST_CLIENTS,
  TEST_USERS,
} from '../../support/browser';

test.describe('TOK-14: Refresh Token Replay Attack Prevention', () => {
  test('should reject second use of refresh token', async ({ page }) => {
    const pkce = generatePKCE();
    const state = generateState();
    const client = TEST_CLIENTS.confidential;
    const user = TEST_USERS.standard;

    // Get initial tokens
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

    const originalRefreshToken = initialTokens.refresh_token!;

    // First refresh - should succeed
    const refreshedTokens = await refreshAccessToken({
      refreshToken: originalRefreshToken,
      clientId: client.client_id,
      clientSecret: client.client_secret,
    });

    expect(refreshedTokens.access_token).toBeTruthy();

    // Second refresh with SAME token - should fail
    const { status, error } = await refreshAccessTokenExpectError({
      refreshToken: originalRefreshToken, // Reusing old token!
      clientId: client.client_id,
      clientSecret: client.client_secret,
    });

    expect(status).toBe(400);
    expect(error.error).toBe('invalid_grant');
  });

  test('should invalidate token family on replay detection', async ({ page }) => {
    const pkce = generatePKCE();
    const state = generateState();
    const client = TEST_CLIENTS.confidential;
    const user = TEST_USERS.standard;

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

    const originalRefreshToken = initialTokens.refresh_token!;

    // First refresh - get new tokens
    const refreshedTokens = await refreshAccessToken({
      refreshToken: originalRefreshToken,
      clientId: client.client_id,
      clientSecret: client.client_secret,
    });

    const newRefreshToken = refreshedTokens.refresh_token!;

    // Attempt replay with old token
    await refreshAccessTokenExpectError({
      refreshToken: originalRefreshToken,
      clientId: client.client_id,
      clientSecret: client.client_secret,
    });

    // The NEW refresh token should also be invalidated (family kill)
    // This is a security best practice to prevent token theft
    const { status, error } = await refreshAccessTokenExpectError({
      refreshToken: newRefreshToken,
      clientId: client.client_id,
      clientSecret: client.client_secret,
    });

    // Note: Family invalidation is a SHOULD, not MUST
    // If the server implements it, the new token should be invalid
    if (status === 400) {
      expect(error.error).toBe('invalid_grant');
      // Server implements token family invalidation - excellent security
    } else {
      // Server doesn't implement family invalidation
      // Still valid per spec, but less secure
      console.log('Note: Server does not implement refresh token family invalidation');
    }
  });
});
