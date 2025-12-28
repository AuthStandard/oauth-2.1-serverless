/**
 * AUT-17: Prompt None (Logged Out)
 *
 * Validates that prompt=none returns login_required error when
 * the user is not authenticated.
 *
 * This enables silent authentication checks without user interaction.
 */

import { describe, it, expect } from 'vitest';
import { httpClient } from '../../support/api';
import { ENDPOINTS } from '../../setup';
import { TEST_CLIENTS, generatePKCE, generateState } from '../../fixtures';

describe('AUT-17: Prompt None (Logged Out)', () => {
  it('should return login_required error when user is not logged in', async () => {
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
      prompt: 'none',
    });

    // No session cookie - user is not logged in
    const response = await httpClient.get(`${ENDPOINTS.authorize}?${params}`, {
      followRedirects: false,
    });

    // Should redirect with error, not show login page
    expect([302, 303]).toContain(response.status);

    const location = response.headers.get('location');
    expect(location).toBeDefined();
    expect(location).toContain('error=login_required');
  });
});
