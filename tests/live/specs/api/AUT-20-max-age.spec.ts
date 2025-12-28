/**
 * AUT-20: Max Age Parameter
 *
 * Validates that the max_age parameter is accepted and processed.
 * When max_age is specified, the authorization server should require
 * re-authentication if the user's session is older than max_age seconds.
 *
 * SKIPPED: Full validation requires authenticated session state.
 */

import { describe, it, expect } from 'vitest';
import { httpClient } from '../../support/api';
import { ENDPOINTS } from '../../setup';
import { TEST_CLIENTS, generatePKCE, generateState } from '../../fixtures';

describe('AUT-20: Max Age Parameter', () => {
  it('should accept max_age parameter without error', async () => {
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
      max_age: '60',
    });

    const response = await httpClient.get(`${ENDPOINTS.authorize}?${params}`, {
      followRedirects: false,
    });

    // Should show login page or redirect - not reject the parameter
    expect([200, 302, 303]).toContain(response.status);

    // Should not return invalid_request error for max_age
    if (response.status >= 300 && response.status < 400) {
      const location = response.headers.get('location');
      if (location?.includes('error=')) {
        expect(location).not.toContain('error=invalid_request');
      }
    }
  });

  it.skip('should force re-authentication when session exceeds max_age', async () => {
    /**
     * SKIPPED: This test requires:
     * 1. An authenticated session with known auth_time
     * 2. Ability to set max_age < (now - auth_time)
     * 3. Verification that login UI is shown despite valid session
     *
     * Revisit: When browser automation is added to the test suite.
     */
  });
});
