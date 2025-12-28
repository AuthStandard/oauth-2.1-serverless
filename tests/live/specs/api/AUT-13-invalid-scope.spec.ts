/**
 * AUT-13: Invalid Scope Handling
 *
 * Validates that unknown scopes are ignored rather than causing
 * an error, per RFC 6749 Section 3.3.
 *
 * The authorization server MAY fully or partially ignore the scope
 * requested by the client and return the actual scope granted.
 */

import { describe, it, expect } from 'vitest';
import { httpClient } from '../../support/api';
import { ENDPOINTS } from '../../setup';
import { TEST_CLIENTS, generatePKCE, generateState } from '../../fixtures';

describe('AUT-13: Invalid Scope Handling', () => {
  it('should proceed with valid scopes when unknown scope is included', async () => {
    const { challenge } = generatePKCE();
    const state = generateState();

    const params = new URLSearchParams({
      client_id: TEST_CLIENTS.confidential.client_id,
      response_type: 'code',
      redirect_uri: TEST_CLIENTS.confidential.redirect_uri,
      code_challenge: challenge,
      code_challenge_method: 'S256',
      state,
      scope: 'openid unknown_scope_xyz',
    });

    const response = await httpClient.get(`${ENDPOINTS.authorize}?${params}`, {
      followRedirects: false,
    });

    // Should redirect to login or consent, not error
    // 200 = login page, 302/303 = redirect
    expect([200, 302, 303]).toContain(response.status);

    // If redirecting with error, it should NOT be invalid_scope
    if (response.status >= 300 && response.status < 400) {
      const location = response.headers.get('location');
      if (location?.includes('error=')) {
        expect(location).not.toContain('error=invalid_scope');
      }
    }
  });
});
