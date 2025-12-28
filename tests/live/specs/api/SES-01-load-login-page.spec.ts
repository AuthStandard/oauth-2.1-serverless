/**
 * SES-01: Load Login Page
 *
 * Validates that the login page loads correctly and returns HTML content.
 */

import { describe, it, expect } from 'vitest';
import { httpClient } from '../../support/api';
import { ENDPOINTS } from '../../setup';
import { TEST_CLIENTS, generatePKCE, generateState } from '../../fixtures';

describe('SES-01: Load Login Page', () => {
  it('should return 200 OK with HTML content', async () => {
    const { challenge } = generatePKCE();
    const state = generateState();

    // Access authorize endpoint to trigger login page
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
      followRedirects: true,
    });

    expect(response.status).toBe(200);
    expect(response.headers.get('content-type')).toContain('text/html');
  });
});
