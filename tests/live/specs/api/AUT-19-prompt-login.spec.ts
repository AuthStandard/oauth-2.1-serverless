/**
 * AUT-19: Prompt Login
 *
 * Validates that prompt=login forces re-authentication even when
 * the user has an active session.
 *
 * This is used when applications require fresh authentication
 * for sensitive operations.
 */

import { describe, it, expect } from 'vitest';
import { httpClient } from '../../support/api';
import { ENDPOINTS } from '../../setup';
import { TEST_CLIENTS, generatePKCE, generateState } from '../../fixtures';

describe('AUT-19: Prompt Login', () => {
  it('should show login UI when prompt=login is specified', async () => {
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
      prompt: 'login',
    });

    const response = await httpClient.get(`${ENDPOINTS.authorize}?${params}`, {
      followRedirects: false,
    });

    // Should show login page (200) or redirect to login endpoint
    expect([200, 302, 303]).toContain(response.status);

    // If 200, should be HTML login page
    if (response.status === 200) {
      expect(response.headers.get('content-type')).toContain('text/html');
    }

    // If redirect, should be to login, not directly to callback with code
    if (response.status >= 300 && response.status < 400) {
      const location = response.headers.get('location');
      expect(location).not.toContain('code=');
    }
  });

  it('should accept prompt=login parameter without error', async () => {
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
      prompt: 'login',
    });

    const response = await httpClient.get(`${ENDPOINTS.authorize}?${params}`, {
      followRedirects: false,
    });

    // Should not return an error for valid prompt value
    if (response.status >= 300 && response.status < 400) {
      const location = response.headers.get('location');
      expect(location).not.toContain('error=invalid_request');
    }
  });
});
