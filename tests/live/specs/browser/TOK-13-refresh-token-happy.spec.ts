/**
 * TOK-13: Refresh Token Happy Path
 *
 * Tests the refresh token grant flow for obtaining new access tokens.
 *
 * RFC 6749: If valid and authorized, the authorization server issues
 * an access token. If the request is valid and authorized, the
 * authorization server issues a new refresh token (rotation).
 */

import { test, expect } from '@playwright/test';
import {
  generatePKCE,
  generateState,
  completeAuthorizationFlow,
  exchangeCodeForTokens,
  refreshAccessToken,
  introspectToken,
  decodeJWT,
  TEST_CLIENTS,
  TEST_USERS,
} from '../../support/browser';

test.describe('TOK-13: Refresh Token Happy Path', () => {
  test('should issue new access token using refresh token', async ({ page }) => {
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

    expect(initialTokens.refresh_token).toBeTruthy();

    // Use refresh token to get new access token
    const refreshedTokens = await refreshAccessToken({
      refreshToken: initialTokens.refresh_token!,
      clientId: client.client_id,
      clientSecret: client.client_secret,
    });

    // Verify new tokens
    expect(refreshedTokens.access_token).toBeTruthy();
    expect(refreshedTokens.access_token).not.toBe(initialTokens.access_token);
    expect(refreshedTokens.token_type.toLowerCase()).toBe('bearer');
    expect(refreshedTokens.expires_in).toBeGreaterThan(0);
  });

  test('should rotate refresh token on use', async ({ page }) => {
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

    const refreshedTokens = await refreshAccessToken({
      refreshToken: initialTokens.refresh_token!,
      clientId: client.client_id,
      clientSecret: client.client_secret,
    });

    // Should get a new refresh token (rotation)
    expect(refreshedTokens.refresh_token).toBeTruthy();
    expect(refreshedTokens.refresh_token).not.toBe(initialTokens.refresh_token);
  });

  test('should preserve user identity across refresh', async ({ page }) => {
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

    const refreshedTokens = await refreshAccessToken({
      refreshToken: initialTokens.refresh_token!,
      clientId: client.client_id,
      clientSecret: client.client_secret,
    });

    // Decode both access tokens and verify same subject
    const initialPayload = decodeJWT(initialTokens.access_token).payload;
    const refreshedPayload = decodeJWT(refreshedTokens.access_token).payload;

    expect(refreshedPayload.sub).toBe(initialPayload.sub);
  });

  test('should issue valid access token that passes introspection', async ({ page }) => {
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

    const refreshedTokens = await refreshAccessToken({
      refreshToken: initialTokens.refresh_token!,
      clientId: client.client_id,
      clientSecret: client.client_secret,
    });

    // Introspect the new access token
    const introspection = await introspectToken({
      token: refreshedTokens.access_token,
      clientId: client.client_id,
      clientSecret: client.client_secret,
    });

    expect(introspection.active).toBe(true);
  });
});
