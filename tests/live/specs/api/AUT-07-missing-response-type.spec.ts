/**
 * AUT-07: Missing Response Type
 *
 * Validates that authorization requests without a response_type parameter
 * return a 400 Bad Request error.
 *
 * Per RFC 6749 Section 4.1.1, the response_type parameter is REQUIRED.
 */

import { describe, it, expect } from 'vitest';
import { httpClient } from '../../support/api';
import { ENDPOINTS } from '../../setup';
import { TEST_CLIENTS, generatePKCE, generateState } from '../../fixtures';

describe('AUT-07: Missing Response Type', () => {
  it('should return 400 when response_type is missing', async () => {
    const { challenge } = generatePKCE();
    const state = generateState();

    const params = new URLSearchParams({
      client_id: TEST_CLIENTS.confidential.client_id,
      redirect_uri: TEST_CLIENTS.confidential.redirect_uri,
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
