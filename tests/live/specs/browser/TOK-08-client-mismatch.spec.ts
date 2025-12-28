/**
 * TOK-08: Client Mismatch
 *
 * Tests that the token endpoint rejects authorization code exchange
 * when a different client tries to use another client's code.
 *
 * RFC 6749: The authorization server MUST ensure that the authorization code
 * was issued to the authenticated confidential client, or if the client is
 * public, ensure that the code was issued to "client_id" in the request.
 */

import { test, expect } from '@playwright/test';
import {
  generatePKCE,
  generateState,
  completeAuthorizationFlow,
  exchangeCodeForTokensExpectError,
  TEST_CLIENTS,
  TEST_USERS,
} from '../../support/browser';

test.describe('TOK-08: Client Mismatch', () => {
  test('should reject code exchange when different client_id is used', async ({ page }) => {
    const pkce = generatePKCE();
    const state = generateState();
    const originalClient = TEST_CLIENTS.public;
    const attackerClient = TEST_CLIENTS.confidential;
    const user = TEST_USERS.standard;

    // Complete authorization flow with original client
    const { code } = await completeAuthorizationFlow(page, {
      client: originalClient,
      user,
      pkce,
      state,
    });

    // Try to exchange code with DIFFERENT client
    const { status, error } = await exchangeCodeForTokensExpectError({
      code,
      clientId: attackerClient.client_id, // Wrong client!
      clientSecret: attackerClient.client_secret,
      redirectUri: originalClient.redirect_uris[0],
      codeVerifier: pkce.verifier,
    });

    // Should fail - code was issued to different client
    expect(status).toBe(400);
    expect(error.error).toBe('invalid_grant');
  });

  test('should reject code exchange when confidential client uses public client code', async ({ page }) => {
    const pkce = generatePKCE();
    const state = generateState();
    const publicClient = TEST_CLIENTS.public;
    const confidentialClient = TEST_CLIENTS.confidential;
    const user = TEST_USERS.standard;

    // Get code for public client
    const { code } = await completeAuthorizationFlow(page, {
      client: publicClient,
      user,
      pkce,
      state,
    });

    // Confidential client tries to steal the code
    const { status, error } = await exchangeCodeForTokensExpectError({
      code,
      clientId: confidentialClient.client_id,
      clientSecret: confidentialClient.client_secret,
      redirectUri: publicClient.redirect_uris[0],
      codeVerifier: pkce.verifier,
    });

    expect(status).toBe(400);
    expect(error.error).toBe('invalid_grant');
  });
});
