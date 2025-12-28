/**
 * TOK-04: Wrong PKCE Verifier
 *
 * Tests that the token endpoint rejects authorization code exchange
 * when the code_verifier doesn't match the original code_challenge.
 *
 * RFC 7636: The server MUST verify that the code_verifier transforms
 * to the code_challenge using the code_challenge_method.
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

test.describe('TOK-04: Wrong PKCE Verifier', () => {
  test('should reject token exchange with incorrect code_verifier', async ({ page }) => {
    // Generate two different PKCE pairs
    const originalPkce = generatePKCE();
    const wrongPkce = generatePKCE();
    const state = generateState();
    const client = TEST_CLIENTS.public;
    const user = TEST_USERS.standard;

    // Complete authorization flow with original PKCE challenge
    const { code } = await completeAuthorizationFlow(page, {
      client,
      user,
      pkce: originalPkce,
      state,
    });

    // Try to exchange code with WRONG verifier
    const { status, error } = await exchangeCodeForTokensExpectError({
      code,
      clientId: client.client_id,
      redirectUri: client.redirect_uris[0],
      codeVerifier: wrongPkce.verifier, // Wrong verifier!
    });

    // Should fail with invalid_grant
    expect(status).toBe(400);
    expect(error.error).toBe('invalid_grant');
  });

  test('should reject token exchange with tampered code_verifier', async ({ page }) => {
    const pkce = generatePKCE();
    const state = generateState();
    const client = TEST_CLIENTS.public;
    const user = TEST_USERS.standard;

    const { code } = await completeAuthorizationFlow(page, {
      client,
      user,
      pkce,
      state,
    });

    // Tamper with the verifier by changing one character
    const tamperedVerifier = pkce.verifier.slice(0, -1) + 'X';

    const { status, error } = await exchangeCodeForTokensExpectError({
      code,
      clientId: client.client_id,
      redirectUri: client.redirect_uris[0],
      codeVerifier: tamperedVerifier,
    });

    expect(status).toBe(400);
    expect(error.error).toBe('invalid_grant');
  });
});
