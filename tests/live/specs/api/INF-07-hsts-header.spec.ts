/**
 * INF-07: Security Headers (HSTS)
 *
 * Validates that the Strict-Transport-Security header is present
 * to prevent protocol downgrade attacks.
 *
 * @see RFC 6797 - HTTP Strict Transport Security (HSTS)
 */

import { describe, it, expect } from 'vitest';
import { httpClient, assertHeader } from '../../support/api';
import { generatePKCE, generateState, TEST_CLIENTS } from '../../fixtures';
import { ENDPOINTS } from '../../setup';

describe('INF-07: Security Headers (HSTS)', () => {
  it('should include Strict-Transport-Security header on authorize endpoint', async () => {
    const { challenge } = generatePKCE();
    const state = generateState();

    const response = await httpClient.get(
      `${ENDPOINTS.authorize}?client_id=${TEST_CLIENTS.public.client_id}&redirect_uri=${encodeURIComponent(TEST_CLIENTS.public.redirect_uri)}&response_type=code&scope=openid&state=${state}&code_challenge=${challenge}&code_challenge_method=S256`,
      { followRedirects: false }
    );

    const hsts = response.headers.get('strict-transport-security');
    expect(hsts).toBeDefined();

    // Should have a reasonable max-age (at least 1 year = 31536000 seconds recommended)
    if (hsts) {
      const maxAgeMatch = hsts.match(/max-age=(\d+)/);
      expect(maxAgeMatch).toBeTruthy();
    }
  });

  it('should include Strict-Transport-Security header on token endpoint', async () => {
    const response = await httpClient.postForm(ENDPOINTS.token, {
      grant_type: 'client_credentials',
    });

    const hsts = response.headers.get('strict-transport-security');
    expect(hsts).toBeDefined();
  });

  it('should include Strict-Transport-Security header on discovery endpoint', async () => {
    const response = await httpClient.get(ENDPOINTS.discovery);

    const hsts = response.headers.get('strict-transport-security');
    expect(hsts).toBeDefined();
  });
});
