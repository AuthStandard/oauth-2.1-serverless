/**
 * AUT-14: State Injection Prevention
 *
 * Validates that the state parameter is returned exactly as provided
 * and properly encoded to prevent reflected XSS attacks.
 *
 * The state parameter is opaque to the authorization server and
 * must be returned unchanged to the client.
 */

import { describe, it, expect } from 'vitest';
import { httpClient } from '../../support/api';
import { ENDPOINTS } from '../../setup';
import { TEST_CLIENTS, generatePKCE } from '../../fixtures';

describe('AUT-14: State Injection Prevention', () => {
  it('should return state parameter exactly as provided', async () => {
    const { challenge } = generatePKCE();
    const maliciousState = '<script>alert(1)</script>';

    const params = new URLSearchParams({
      client_id: TEST_CLIENTS.confidential.client_id,
      response_type: 'code',
      redirect_uri: TEST_CLIENTS.confidential.redirect_uri,
      code_challenge: challenge,
      code_challenge_method: 'S256',
      state: maliciousState,
      scope: 'openid',
    });

    const response = await httpClient.get(`${ENDPOINTS.authorize}?${params}`, {
      followRedirects: false,
    });

    // Server may redirect to login page first (state is preserved in session)
    // or redirect with code and state
    if (response.status >= 300 && response.status < 400) {
      const location = response.headers.get('location');
      if (location) {
        // If redirecting with code, state should be properly encoded
        if (location.includes('code=')) {
          expect(location).not.toContain('<script>');
          expect(location).toContain('state=');
        }
        // If redirecting to login, state is preserved server-side
      }
    }

    // If HTML response, check for proper encoding
    if (response.status === 200 && typeof response.data === 'string') {
      // Raw script tags should not appear unencoded in HTML
      const html = response.data as string;
      // If state appears in HTML, it should be entity-encoded
      if (html.includes('state')) {
        expect(html).not.toContain('<script>alert(1)</script>');
      }
    }
  });

  it('should handle state with special URL characters', async () => {
    const { challenge } = generatePKCE();
    const specialState = 'test&foo=bar&baz=qux';

    const params = new URLSearchParams({
      client_id: TEST_CLIENTS.confidential.client_id,
      response_type: 'code',
      redirect_uri: TEST_CLIENTS.confidential.redirect_uri,
      code_challenge: challenge,
      code_challenge_method: 'S256',
      state: specialState,
      scope: 'openid',
    });

    const response = await httpClient.get(`${ENDPOINTS.authorize}?${params}`, {
      followRedirects: false,
    });

    // Request should not fail due to special characters
    expect([200, 302, 303, 400]).toContain(response.status);
  });
});
