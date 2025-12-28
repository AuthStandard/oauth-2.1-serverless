/**
 * TOK-12: Public Client with Secret
 *
 * Tests the behavior when a public client sends a client_secret.
 *
 * RFC 8252 (OAuth 2.0 for Native Apps): Public clients MUST NOT use
 * client secrets. The server should either ignore the secret or reject
 * the request (implementation-specific).
 */

import { test, expect } from '@playwright/test';
import {
  generatePKCE,
  generateState,
  completeAuthorizationFlow,
  exchangeCodeForTokens,
  config,
  ENDPOINTS,
  TEST_CLIENTS,
  TEST_USERS,
  type TokenResponse,
  type TokenErrorResponse,
} from '../../support/browser';

test.describe('TOK-12: Public Client with Secret', () => {
  test('should handle public client sending a secret', async ({ page }) => {
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

    // Public client sends a fake secret
    // Server should either ignore it (200) or reject it (400)
    const body = new URLSearchParams();
    body.set('grant_type', 'authorization_code');
    body.set('code', code);
    body.set('redirect_uri', client.redirect_uris[0]);
    body.set('client_id', client.client_id);
    body.set('code_verifier', pkce.verifier);

    // Add fake secret via Basic auth
    const fakeSecret = 'fake-secret-that-should-not-work';
    const credentials = Buffer.from(`${client.client_id}:${fakeSecret}`).toString('base64');

    const response = await fetch(`${config.apiBaseUrl}${ENDPOINTS.token}`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        'Authorization': `Basic ${credentials}`,
      },
      body: body.toString(),
    });

    // Per RFC 8252, server can either:
    // 1. Ignore the secret and process normally (200)
    // 2. Reject because public clients shouldn't send secrets (400)
    // Both are valid implementations
    expect([200, 400]).toContain(response.status);

    if (response.status === 200) {
      // Server ignores secret - verify we got valid tokens
      const tokens = await response.json() as TokenResponse;
      expect(tokens.access_token).toBeTruthy();
    } else {
      // Server rejects - verify error response
      const error = await response.json() as TokenErrorResponse;
      expect(error.error).toBeTruthy();
    }
  });

  test('should succeed for public client without secret', async ({ page }) => {
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

    // Public client without secret - should always work
    const tokens = await exchangeCodeForTokens({
      code,
      clientId: client.client_id,
      redirectUri: client.redirect_uris[0],
      codeVerifier: pkce.verifier,
      // No clientSecret
    });

    expect(tokens.access_token).toBeTruthy();
    expect(tokens.token_type.toLowerCase()).toBe('bearer');
  });
});
