/**
 * TOK-09: Redirect URI Mismatch
 *
 * Tests that the token endpoint rejects authorization code exchange
 * when the redirect_uri doesn't match the one used in the authorization request.
 *
 * RFC 6749: If the "redirect_uri" parameter was included in the initial
 * authorization request, the value MUST be identical to the value included
 * in the authorization request.
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

test.describe('TOK-09: Redirect URI Mismatch', () => {
  test('should reject code exchange with different redirect_uri', async ({ page }) => {
    const pkce = generatePKCE();
    const state = generateState();
    const client = TEST_CLIENTS.public;
    const user = TEST_USERS.standard;

    // Complete authorization flow with first redirect URI
    const { code } = await completeAuthorizationFlow(page, {
      client,
      user,
      pkce,
      state,
    });

    // Try to exchange code with DIFFERENT redirect URI
    const { status, error } = await exchangeCodeForTokensExpectError({
      code,
      clientId: client.client_id,
      redirectUri: 'https://evil.com/callback', // Different URI!
      codeVerifier: pkce.verifier,
    });

    // Should fail - redirect_uri must match
    expect(status).toBe(400);
    expect(error.error).toBe('invalid_grant');
  });

  test('should reject code exchange with modified redirect_uri path', async ({ page }) => {
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

    // Try with same domain but different path
    const originalUri = client.redirect_uris[0];
    const modifiedUri = originalUri + '/extra';

    const { status, error } = await exchangeCodeForTokensExpectError({
      code,
      clientId: client.client_id,
      redirectUri: modifiedUri,
      codeVerifier: pkce.verifier,
    });

    expect(status).toBe(400);
    expect(error.error).toBe('invalid_grant');
  });

  test('should reject code exchange with query params added to redirect_uri', async ({ page }) => {
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

    // Try with query params added
    const originalUri = client.redirect_uris[0];
    const modifiedUri = originalUri + '?extra=param';

    const { status, error } = await exchangeCodeForTokensExpectError({
      code,
      clientId: client.client_id,
      redirectUri: modifiedUri,
      codeVerifier: pkce.verifier,
    });

    expect(status).toBe(400);
    expect(error.error).toBe('invalid_grant');
  });
});
