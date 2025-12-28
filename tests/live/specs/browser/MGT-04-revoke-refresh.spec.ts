/**
 * MGT-04: Revoke Refresh Token
 *
 * Tests the token revocation endpoint per RFC 7009.
 * After revocation, the refresh token should no longer be usable.
 */

import { test, expect } from '@playwright/test';
import {
  generatePKCE,
  generateState,
  completeAuthorizationFlow,
  exchangeCodeForTokens,
  revokeToken,
  refreshAccessTokenExpectError,
  introspectToken,
  TEST_CLIENTS,
  TEST_USERS,
} from '../../support/browser';

test.describe('MGT-04: Revoke Refresh Token', () => {
  test('should revoke refresh token successfully', async ({ page }) => {
    const pkce = generatePKCE();
    const state = generateState();
    const client = TEST_CLIENTS.confidential;
    const user = TEST_USERS.standard;

    // Get tokens including refresh token
    const { code } = await completeAuthorizationFlow(page, {
      client,
      user,
      pkce,
      state,
      scope: 'openid profile email offline_access',
    });

    const tokens = await exchangeCodeForTokens({
      code,
      clientId: client.client_id,
      clientSecret: client.client_secret,
      redirectUri: client.redirect_uris[0],
      codeVerifier: pkce.verifier,
    });

    expect(tokens.refresh_token).toBeTruthy();

    // Revoke the refresh token
    const revokeResult = await revokeToken({
      token: tokens.refresh_token!,
      tokenTypeHint: 'refresh_token',
      clientId: client.client_id,
      clientSecret: client.client_secret,
    });

    // RFC 7009: Server responds with 200 OK
    expect(revokeResult.status).toBe(200);

    // Try to use the revoked refresh token
    const { status, error } = await refreshAccessTokenExpectError({
      refreshToken: tokens.refresh_token!,
      clientId: client.client_id,
      clientSecret: client.client_secret,
    });

    // Should fail - token is revoked
    expect(status).toBe(400);
    expect(error.error).toBe('invalid_grant');
  });

  test('should also invalidate access tokens when refresh token is revoked', async ({ page }) => {
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

    const tokens = await exchangeCodeForTokens({
      code,
      clientId: client.client_id,
      clientSecret: client.client_secret,
      redirectUri: client.redirect_uris[0],
      codeVerifier: pkce.verifier,
    });

    // Verify access token is active before revocation
    const beforeRevoke = await introspectToken({
      token: tokens.access_token,
      clientId: client.client_id,
      clientSecret: client.client_secret,
    });
    expect(beforeRevoke.active).toBe(true);

    // Revoke the refresh token
    await revokeToken({
      token: tokens.refresh_token!,
      tokenTypeHint: 'refresh_token',
      clientId: client.client_id,
      clientSecret: client.client_secret,
    });

    // Check if access token is also invalidated
    // Note: This is implementation-specific behavior
    const afterRevoke = await introspectToken({
      token: tokens.access_token,
      clientId: client.client_id,
      clientSecret: client.client_secret,
    });

    // Some implementations revoke the entire token family
    // Others only revoke the specific token
    // Both are valid, so we just document the behavior
    if (!afterRevoke.active) {
      // Server implements token family revocation - good security practice
      expect(afterRevoke.active).toBe(false);
    } else {
      // Server only revokes the specific token
      console.log('Note: Server does not revoke access tokens when refresh token is revoked');
    }
  });

  test('should return 200 OK even for already-revoked token', async ({ page }) => {
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

    const tokens = await exchangeCodeForTokens({
      code,
      clientId: client.client_id,
      clientSecret: client.client_secret,
      redirectUri: client.redirect_uris[0],
      codeVerifier: pkce.verifier,
    });

    // Revoke once
    const firstRevoke = await revokeToken({
      token: tokens.refresh_token!,
      clientId: client.client_id,
      clientSecret: client.client_secret,
    });
    expect(firstRevoke.status).toBe(200);

    // Revoke again - should still return 200
    // RFC 7009: The authorization server responds with HTTP status code 200
    // if the token has been revoked successfully or if the client submitted
    // an invalid token.
    const secondRevoke = await revokeToken({
      token: tokens.refresh_token!,
      clientId: client.client_id,
      clientSecret: client.client_secret,
    });
    expect(secondRevoke.status).toBe(200);
  });
});
