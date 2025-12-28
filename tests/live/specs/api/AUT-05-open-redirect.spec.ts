/**
 * AUT-05: Open Redirect Prevention
 *
 * Validates that the authorization server prevents open redirect attacks
 * by rejecting redirect URIs that are not pre-registered.
 *
 * Open redirect vulnerabilities can be exploited for phishing attacks
 * by making malicious URLs appear to originate from a trusted domain.
 */

import { describe, it, expect } from 'vitest';
import { httpClient } from '../../support/api';
import { ENDPOINTS } from '../../setup';
import { TEST_CLIENTS, generatePKCE, generateState } from '../../fixtures';

describe('AUT-05: Open Redirect Prevention', () => {
  it('should reject redirect to evil.com', async () => {
    const { challenge } = generatePKCE();
    const state = generateState();

    const params = new URLSearchParams({
      client_id: TEST_CLIENTS.confidential.client_id,
      response_type: 'code',
      redirect_uri: 'https://evil.com/steal-tokens',
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

  it('should reject redirect with URL encoding tricks', async () => {
    const { challenge } = generatePKCE();
    const state = generateState();

    // Attempt to bypass validation with URL encoding
    const params = new URLSearchParams({
      client_id: TEST_CLIENTS.confidential.client_id,
      response_type: 'code',
      redirect_uri: 'https://example.com%40evil.com/callback',
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
