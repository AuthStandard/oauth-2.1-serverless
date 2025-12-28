/**
 * AUT-16: Response Mode Fragment
 *
 * Validates that response_mode=fragment returns the authorization code
 * in the fragment component of the redirect URI.
 *
 * Fragment mode is useful for single-page applications where the
 * authorization response should not be sent to the server.
 */

import { describe, it, expect } from 'vitest';
import { httpClient } from '../../support/api';
import { ENDPOINTS } from '../../setup';
import { TEST_CLIENTS, generatePKCE, generateState } from '../../fixtures';

describe('AUT-16: Response Mode Fragment', () => {
  it('should accept response_mode=fragment parameter', async () => {
    const { challenge } = generatePKCE();
    const state = generateState();

    const params = new URLSearchParams({
      client_id: TEST_CLIENTS.confidential.client_id,
      response_type: 'code',
      redirect_uri: TEST_CLIENTS.confidential.redirect_uri,
      code_challenge: challenge,
      code_challenge_method: 'S256',
      state,
      scope: 'openid',
      response_mode: 'fragment',
    });

    const response = await httpClient.get(`${ENDPOINTS.authorize}?${params}`, {
      followRedirects: false,
    });

    // Should show login page or redirect - not reject the parameter
    expect([200, 302, 303]).toContain(response.status);

    // If redirecting with code, it should be in fragment (#)
    if (response.status >= 300 && response.status < 400) {
      const location = response.headers.get('location');
      if (location?.includes('code=')) {
        expect(location).toContain('#');
        expect(location).toMatch(/#.*code=/);
      }
    }
  });
});
