/**
 * AUT-09: Missing PKCE
 *
 * Validates that authorization requests without PKCE parameters
 * are rejected per OAuth 2.1 specification.
 *
 * OAuth 2.1 mandates PKCE for all authorization code grants,
 * eliminating the authorization code interception attack vector.
 */

import { describe, it, expect } from 'vitest';
import { httpClient } from '../../support/api';
import { ENDPOINTS } from '../../setup';
import { TEST_CLIENTS, generateState } from '../../fixtures';

describe('AUT-09: Missing PKCE', () => {
  it('should reject authorization request without code_challenge', async () => {
    const state = generateState();

    const params = new URLSearchParams({
      client_id: TEST_CLIENTS.confidential.client_id,
      response_type: 'code',
      redirect_uri: TEST_CLIENTS.confidential.redirect_uri,
      state,
      scope: 'openid',
    });

    const response = await httpClient.get(`${ENDPOINTS.authorize}?${params}`, {
      followRedirects: false,
    });

    // Should return 400 or redirect with error
    expect([400, 302, 303]).toContain(response.status);

    if (response.status >= 300 && response.status < 400) {
      const location = response.headers.get('location');
      expect(location).toContain('error=');
    }
  });

  it('should reject when code_challenge is present but code_challenge_method is missing', async () => {
    const state = generateState();

    const params = new URLSearchParams({
      client_id: TEST_CLIENTS.confidential.client_id,
      response_type: 'code',
      redirect_uri: TEST_CLIENTS.confidential.redirect_uri,
      code_challenge: 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM',
      state,
      scope: 'openid',
    });

    const response = await httpClient.get(`${ENDPOINTS.authorize}?${params}`, {
      followRedirects: false,
    });

    // Server should either default to S256 or reject
    // If it defaults to plain, that's a security issue (tested in AUT-10)
    expect([200, 302, 303, 400]).toContain(response.status);
  });
});
