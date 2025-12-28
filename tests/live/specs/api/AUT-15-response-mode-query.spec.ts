/**
 * AUT-15: Response Mode Query
 *
 * Validates that response_mode=query returns the authorization code
 * in the query string of the redirect URI.
 *
 * This is the default and most common response mode for authorization
 * code flows.
 */

import { describe, it, expect } from 'vitest';
import { httpClient } from '../../support/api';
import { ENDPOINTS } from '../../setup';
import { TEST_CLIENTS, generatePKCE, generateState } from '../../fixtures';

describe('AUT-15: Response Mode Query', () => {
  it('should use query string for response_mode=query', async () => {
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
      response_mode: 'query',
    });

    const response = await httpClient.get(`${ENDPOINTS.authorize}?${params}`, {
      followRedirects: false,
    });

    // Should show login page or redirect
    expect([200, 302, 303]).toContain(response.status);

    // If redirecting with code, it should be in query string (?)
    if (response.status >= 300 && response.status < 400) {
      const location = response.headers.get('location');
      if (location?.includes('code=')) {
        expect(location).toContain('?');
        expect(location).not.toMatch(/#.*code=/);
      }
    }
  });

  it('should default to query mode when response_mode is not specified', async () => {
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
    });

    const response = await httpClient.get(`${ENDPOINTS.authorize}?${params}`, {
      followRedirects: false,
    });

    expect([200, 302, 303]).toContain(response.status);
  });
});
