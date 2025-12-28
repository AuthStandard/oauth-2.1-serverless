/**
 * AUT-08: Implicit Flow Rejection
 *
 * Validates that the implicit grant (response_type=token) is rejected
 * per OAuth 2.1 specification which removes the implicit grant entirely.
 *
 * The implicit grant was deprecated due to security concerns around
 * token exposure in browser history and referrer headers.
 */

import { describe, it, expect } from 'vitest';
import { httpClient, type OAuth2Error } from '../../support/api';
import { ENDPOINTS } from '../../setup';
import { TEST_CLIENTS, generateState } from '../../fixtures';

describe('AUT-08: Implicit Flow Rejection', () => {
  it('should reject response_type=token with unsupported_response_type', async () => {
    const state = generateState();

    const params = new URLSearchParams({
      client_id: TEST_CLIENTS.confidential.client_id,
      response_type: 'token',
      redirect_uri: TEST_CLIENTS.confidential.redirect_uri,
      state,
    });

    const response = await httpClient.get<OAuth2Error | string>(`${ENDPOINTS.authorize}?${params}`, {
      followRedirects: false,
    });

    // Should return error - either as redirect with error or as 400
    expect([400, 302, 303]).toContain(response.status);

    if (response.status >= 300 && response.status < 400) {
      // If redirecting, error should be in the redirect URI
      const location = response.headers.get('location');
      expect(location).toContain('error=unsupported_response_type');
    }
  });

  it('should reject response_type=id_token (implicit OIDC)', async () => {
    const state = generateState();

    const params = new URLSearchParams({
      client_id: TEST_CLIENTS.confidential.client_id,
      response_type: 'id_token',
      redirect_uri: TEST_CLIENTS.confidential.redirect_uri,
      state,
      nonce: 'test-nonce',
    });

    const response = await httpClient.get(`${ENDPOINTS.authorize}?${params}`, {
      followRedirects: false,
    });

    expect([400, 302, 303]).toContain(response.status);

    if (response.status >= 300 && response.status < 400) {
      const location = response.headers.get('location');
      expect(location).toContain('error=unsupported_response_type');
    }
  });
});
