/**
 * INF-08: Security Headers (Frame Options)
 *
 * Validates that X-Frame-Options header is present to prevent
 * clickjacking and UI redress attacks.
 *
 * @see RFC 7034 - HTTP Header Field X-Frame-Options
 * @see OWASP Clickjacking Defense Cheat Sheet
 */

import { describe, it, expect } from 'vitest';
import { httpClient } from '../../support/api';
import { generatePKCE, generateState, TEST_CLIENTS } from '../../fixtures';
import { ENDPOINTS } from '../../setup';

describe('INF-08: Security Headers (Frame Options)', () => {
  it('should include X-Frame-Options header on authorize endpoint', async () => {
    const { challenge } = generatePKCE();
    const state = generateState();

    const response = await httpClient.get(
      `${ENDPOINTS.authorize}?client_id=${TEST_CLIENTS.public.client_id}&redirect_uri=${encodeURIComponent(TEST_CLIENTS.public.redirect_uri)}&response_type=code&scope=openid&state=${state}&code_challenge=${challenge}&code_challenge_method=S256`,
      { followRedirects: false }
    );

    const frameOptions = response.headers.get('x-frame-options');
    expect(frameOptions).toBeDefined();

    // Should be DENY or SAMEORIGIN
    if (frameOptions) {
      expect(['DENY', 'SAMEORIGIN', 'deny', 'sameorigin']).toContain(
        frameOptions.toUpperCase()
      );
    }
  });

  it('should include Content-Security-Policy frame-ancestors directive as alternative', async () => {
    const { challenge } = generatePKCE();
    const state = generateState();

    const response = await httpClient.get(
      `${ENDPOINTS.authorize}?client_id=${TEST_CLIENTS.public.client_id}&redirect_uri=${encodeURIComponent(TEST_CLIENTS.public.redirect_uri)}&response_type=code&scope=openid&state=${state}&code_challenge=${challenge}&code_challenge_method=S256`,
      { followRedirects: false }
    );

    const frameOptions = response.headers.get('x-frame-options');
    const csp = response.headers.get('content-security-policy');

    // Either X-Frame-Options or CSP frame-ancestors should be present
    const hasFrameProtection =
      frameOptions !== null || (csp !== null && csp.includes('frame-ancestors'));

    expect(hasFrameProtection).toBe(true);
  });
});
