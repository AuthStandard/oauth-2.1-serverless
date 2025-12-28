/**
 * TOK-05: Missing PKCE Verifier
 *
 * Tests that the token endpoint rejects authorization code exchange
 * when code_verifier is missing but code_challenge was provided.
 *
 * RFC 7636: If the authorization request included a code_challenge,
 * the token request MUST include a code_verifier.
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

test.describe('TOK-05: Missing PKCE Verifier', () => {
  test('should reject token exchange without code_verifier', async ({ page }) => {
    const pkce = generatePKCE();
    const state = generateState();
    const client = TEST_CLIENTS.public;
    const user = TEST_USERS.standard;

    // Complete authorization flow with PKCE challenge
    const { code } = await completeAuthorizationFlow(page, {
      client,
      user,
      pkce,
      state,
    });

    // Try to exchange code WITHOUT verifier
    const { status, error } = await exchangeCodeForTokensExpectError({
      code,
      clientId: client.client_id,
      redirectUri: client.redirect_uris[0],
      // codeVerifier intentionally omitted
    });

    // Should fail - PKCE was required
    expect(status).toBe(400);
    expect(['invalid_grant', 'invalid_request']).toContain(error.error);
  });

  test('should reject token exchange with empty code_verifier', async ({ page }) => {
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

    // Try to exchange code with empty verifier
    const { status, error } = await exchangeCodeForTokensExpectError({
      code,
      clientId: client.client_id,
      redirectUri: client.redirect_uris[0],
      codeVerifier: '',
    });

    expect(status).toBe(400);
    expect(['invalid_grant', 'invalid_request']).toContain(error.error);
  });
});
