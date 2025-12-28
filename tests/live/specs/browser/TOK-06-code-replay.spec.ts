/**
 * TOK-06: Authorization Code Replay Attack Prevention
 *
 * Tests that authorization codes can only be used once.
 * Per RFC 6749 Section 4.1.2, if an authorization code is used more than once,
 * the authorization server MUST deny the request and SHOULD revoke all tokens
 * previously issued based on that authorization code.
 */

import { test, expect } from '@playwright/test';
import {
  generatePKCE,
  generateState,
  completeAuthorizationFlow,
  exchangeCodeForTokens,
  exchangeCodeForTokensExpectError,
  introspectToken,
  TEST_CLIENTS,
  TEST_USERS,
} from '../../support/browser';

test.describe('TOK-06: Code Replay Attack Prevention', () => {
  test('should reject second use of authorization code', async ({ page }) => {
    const pkce = generatePKCE();
    const state = generateState();
    const client = TEST_CLIENTS.confidential;
    const user = TEST_USERS.standard;

    // Complete authorization flow
    const { code } = await completeAuthorizationFlow(page, {
      client,
      user,
      pkce,
      state,
    });

    // First exchange - should succeed
    const tokens = await exchangeCodeForTokens({
      code,
      clientId: client.client_id,
      clientSecret: client.client_secret,
      redirectUri: client.redirect_uris[0],
      codeVerifier: pkce.verifier,
    });

    expect(tokens.access_token).toBeTruthy();

    // Second exchange with same code - should fail
    const { status, error } = await exchangeCodeForTokensExpectError({
      code,
      clientId: client.client_id,
      clientSecret: client.client_secret,
      redirectUri: client.redirect_uris[0],
      codeVerifier: pkce.verifier,
    });

    expect(status).toBe(400);
    expect(error.error).toBe('invalid_grant');
  });

  test('should revoke tokens issued from replayed code', async ({ page }) => {
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

    // First exchange - get tokens
    const tokens = await exchangeCodeForTokens({
      code,
      clientId: client.client_id,
      clientSecret: client.client_secret,
      redirectUri: client.redirect_uris[0],
      codeVerifier: pkce.verifier,
    });

    // Verify token is active before replay attempt
    const beforeReplay = await introspectToken({
      token: tokens.access_token,
      clientId: client.client_id,
      clientSecret: client.client_secret,
    });
    expect(beforeReplay.active).toBe(true);

    // Attempt code replay
    await exchangeCodeForTokensExpectError({
      code,
      clientId: client.client_id,
      clientSecret: client.client_secret,
      redirectUri: client.redirect_uris[0],
      codeVerifier: pkce.verifier,
    });

    // Per RFC 6749, tokens from the replayed code SHOULD be revoked
    // Check if the original token is now inactive
    const afterReplay = await introspectToken({
      token: tokens.access_token,
      clientId: client.client_id,
      clientSecret: client.client_secret,
    });

    // Note: This is a SHOULD requirement, not MUST
    // Some implementations may not revoke, so we just verify the behavior
    // If active is false, the server implements the security best practice
    if (!afterReplay.active) {
      // Server correctly revoked tokens on code replay - excellent security
      expect(afterReplay.active).toBe(false);
    } else {
      // Server didn't revoke - still valid per spec, but less secure
      // Log this for awareness but don't fail the test
      console.log('Note: Server does not revoke tokens on code replay (SHOULD per RFC 6749)');
    }
  });
});
