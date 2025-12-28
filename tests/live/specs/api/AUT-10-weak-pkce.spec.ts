/**
 * AUT-10: Weak PKCE Rejection
 *
 * Validates that the authorization server rejects the 'plain'
 * code_challenge_method and only accepts 'S256'.
 *
 * The plain method provides no security benefit as the verifier
 * is transmitted in the clear. S256 is mandatory per OAuth 2.1.
 */

import { describe, it, expect } from 'vitest';
import { httpClient } from '../../support/api';
import { ENDPOINTS } from '../../setup';
import { TEST_CLIENTS, generateState, generateCodeVerifier } from '../../fixtures';

describe('AUT-10: Weak PKCE Rejection', () => {
  it('should reject code_challenge_method=plain', async () => {
    const state = generateState();
    const verifier = generateCodeVerifier();

    const params = new URLSearchParams({
      client_id: TEST_CLIENTS.confidential.client_id,
      response_type: 'code',
      redirect_uri: TEST_CLIENTS.confidential.redirect_uri,
      code_challenge: verifier, // For plain, challenge = verifier
      code_challenge_method: 'plain',
      state,
      scope: 'openid',
    });

    const response = await httpClient.get(`${ENDPOINTS.authorize}?${params}`, {
      followRedirects: false,
    });

    // Should reject plain method
    expect([400, 302, 303]).toContain(response.status);

    if (response.status >= 300 && response.status < 400) {
      const location = response.headers.get('location');
      expect(location).toContain('error=');
    } else {
      expect(response.status).toBe(400);
    }
  });

  it('should reject unknown code_challenge_method', async () => {
    const state = generateState();

    const params = new URLSearchParams({
      client_id: TEST_CLIENTS.confidential.client_id,
      response_type: 'code',
      redirect_uri: TEST_CLIENTS.confidential.redirect_uri,
      code_challenge: 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM',
      code_challenge_method: 'SHA512', // Invalid method
      state,
      scope: 'openid',
    });

    const response = await httpClient.get(`${ENDPOINTS.authorize}?${params}`, {
      followRedirects: false,
    });

    expect([400, 302, 303]).toContain(response.status);
  });
});
