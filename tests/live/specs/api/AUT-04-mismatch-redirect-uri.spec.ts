/**
 * AUT-04: Mismatch Redirect URI
 *
 * Validates that authorization requests with a redirect_uri that doesn't
 * match any registered URI return a 400 Bad Request error page.
 *
 * This prevents token leakage attacks where an attacker could redirect
 * authorization codes to their own server.
 */

import { describe, it, expect } from 'vitest';
import { httpClient } from '../../support/api';
import { ENDPOINTS } from '../../setup';
import { TEST_CLIENTS, generatePKCE, generateState } from '../../fixtures';

describe('AUT-04: Mismatch Redirect URI', () => {
  it('should return 400 when redirect_uri does not match registered URI', async () => {
    const { challenge } = generatePKCE();
    const state = generateState();

    // test-app is registered with https://example.com/callback
    const params = new URLSearchParams({
      client_id: TEST_CLIENTS.confidential.client_id,
      response_type: 'code',
      redirect_uri: 'https://different-domain.com/callback',
      code_challenge: challenge,
      code_challenge_method: 'S256',
      state,
    });

    const response = await httpClient.get(`${ENDPOINTS.authorize}?${params}`, {
      followRedirects: false,
    });

    expect(response.status).toBe(400);
    expect(response.headers.get('location')).toBeNull();
  });

  it('should reject redirect_uri with different path', async () => {
    const { challenge } = generatePKCE();
    const state = generateState();

    // Registered: https://example.com/callback
    // Requested: https://example.com/different-path
    const params = new URLSearchParams({
      client_id: TEST_CLIENTS.confidential.client_id,
      response_type: 'code',
      redirect_uri: 'https://example.com/different-path',
      code_challenge: challenge,
      code_challenge_method: 'S256',
      state,
    });

    const response = await httpClient.get(`${ENDPOINTS.authorize}?${params}`, {
      followRedirects: false,
    });

    expect(response.status).toBe(400);
  });
});
