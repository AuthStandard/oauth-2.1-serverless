/**
 * AUT-02: Unknown Client ID
 *
 * Validates that authorization requests with an unregistered client_id
 * return a 400 Bad Request error page. This prevents phishing attacks
 * where malicious actors could use fake client IDs to harvest credentials.
 *
 * Per RFC 6749, the authorization server MUST NOT redirect to an
 * unverified redirect URI.
 */

import { describe, it, expect } from 'vitest';
import { httpClient } from '../../support/api';
import { ENDPOINTS } from '../../setup';
import { INVALID_CLIENT_IDS, generatePKCE, generateState } from '../../fixtures';

describe('AUT-02: Unknown Client ID', () => {
  it('should return 400 Bad Request for nonexistent client_id', async () => {
    const { challenge } = generatePKCE();
    const state = generateState();

    const params = new URLSearchParams({
      client_id: INVALID_CLIENT_IDS.nonexistent,
      response_type: 'code',
      redirect_uri: 'https://example.com/callback',
      code_challenge: challenge,
      code_challenge_method: 'S256',
      state,
    });

    const response = await httpClient.get(`${ENDPOINTS.authorize}?${params}`, {
      followRedirects: false,
    });

    expect(response.status).toBe(400);
  });

  it('should not redirect when client_id is unknown', async () => {
    const { challenge } = generatePKCE();

    const params = new URLSearchParams({
      client_id: 'completely-fake-client-id-xyz',
      response_type: 'code',
      redirect_uri: 'https://attacker.com/steal',
      code_challenge: challenge,
      code_challenge_method: 'S256',
    });

    const response = await httpClient.get(`${ENDPOINTS.authorize}?${params}`, {
      followRedirects: false,
    });

    // Must show error page, not redirect to attacker's URI
    expect(response.status).toBe(400);
    expect(response.headers.get('location')).toBeNull();
  });
});
