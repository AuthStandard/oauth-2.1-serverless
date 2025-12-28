/**
 * AUT-12: Long PKCE Challenge
 *
 * Validates that code_challenge values longer than 128 characters
 * are rejected per RFC 7636 Section 4.1.
 *
 * The maximum length prevents buffer overflow attacks and
 * ensures reasonable storage requirements.
 */

import { describe, it, expect } from 'vitest';
import { httpClient } from '../../support/api';
import { ENDPOINTS } from '../../setup';
import { TEST_CLIENTS, generateState } from '../../fixtures';

describe('AUT-12: Long PKCE Challenge', () => {
  it('should reject code_challenge longer than 128 characters', async () => {
    const state = generateState();

    // 129 characters - one over maximum
    const longChallenge = 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM'.repeat(3) + 'X';

    const params = new URLSearchParams({
      client_id: TEST_CLIENTS.confidential.client_id,
      response_type: 'code',
      redirect_uri: TEST_CLIENTS.confidential.redirect_uri,
      code_challenge: longChallenge,
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
});
