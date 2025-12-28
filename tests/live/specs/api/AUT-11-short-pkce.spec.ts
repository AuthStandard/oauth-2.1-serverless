/**
 * AUT-11: Short PKCE Challenge
 *
 * Validates that code_challenge values shorter than 43 characters
 * are rejected per RFC 7636 Section 4.1.
 *
 * The minimum length ensures sufficient entropy for security.
 */

import { describe, it, expect } from 'vitest';
import { httpClient } from '../../support/api';
import { ENDPOINTS } from '../../setup';
import { TEST_CLIENTS, generateState } from '../../fixtures';

describe('AUT-11: Short PKCE Challenge', () => {
  it('should reject code_challenge shorter than 43 characters', async () => {
    const state = generateState();

    // 42 characters - one short of minimum
    const shortChallenge = 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-c';

    const params = new URLSearchParams({
      client_id: TEST_CLIENTS.confidential.client_id,
      response_type: 'code',
      redirect_uri: TEST_CLIENTS.confidential.redirect_uri,
      code_challenge: shortChallenge,
      code_challenge_method: 'S256',
      state,
      scope: 'openid',
    });

    const response = await httpClient.get(`${ENDPOINTS.authorize}?${params}`, {
      followRedirects: false,
    });

    expect([400, 302, 303]).toContain(response.status);

    if (response.status >= 300 && response.status < 400) {
      const location = response.headers.get('location');
      expect(location).toContain('error=');
    }
  });

  it('should reject empty code_challenge', async () => {
    const state = generateState();

    const params = new URLSearchParams({
      client_id: TEST_CLIENTS.confidential.client_id,
      response_type: 'code',
      redirect_uri: TEST_CLIENTS.confidential.redirect_uri,
      code_challenge: '',
      code_challenge_method: 'S256',
      state,
    });

    const response = await httpClient.get(`${ENDPOINTS.authorize}?${params}`, {
      followRedirects: false,
    });

    expect([400, 302, 303]).toContain(response.status);
  });
});
