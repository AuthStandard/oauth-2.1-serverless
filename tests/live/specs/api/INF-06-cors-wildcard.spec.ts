/**
 * INF-06: CORS Wildcard Block
 *
 * Validates that the token endpoint does not allow wildcard CORS origins,
 * which would enable browser-based attacks from any domain.
 *
 * @see OWASP CORS Security
 */

import { describe, it, expect } from 'vitest';
import { httpClient, assertHeaderNot } from '../../support/api';
import { ENDPOINTS } from '../../setup';

describe('INF-06: CORS Wildcard Block', () => {
  it('should not return Access-Control-Allow-Origin: * for evil origin', async () => {
    const response = await httpClient.options(ENDPOINTS.token, {
      headers: {
        Origin: 'https://evil.com',
        'Access-Control-Request-Method': 'POST',
      },
    });

    const allowOrigin = response.headers.get('access-control-allow-origin');

    // Should NOT be wildcard
    if (allowOrigin) {
      expect(allowOrigin).not.toBe('*');
      // Should NOT reflect the evil origin
      expect(allowOrigin).not.toBe('https://evil.com');
    }
  });

  it('should not return Access-Control-Allow-Origin: * for introspect endpoint', async () => {
    const response = await httpClient.options(ENDPOINTS.introspect, {
      headers: {
        Origin: 'https://attacker.example.com',
        'Access-Control-Request-Method': 'POST',
      },
    });

    const allowOrigin = response.headers.get('access-control-allow-origin');

    if (allowOrigin) {
      expect(allowOrigin).not.toBe('*');
      expect(allowOrigin).not.toBe('https://attacker.example.com');
    }
  });

  it('should not return Access-Control-Allow-Origin: * for revoke endpoint', async () => {
    const response = await httpClient.options(ENDPOINTS.revoke, {
      headers: {
        Origin: 'https://malicious-site.com',
        'Access-Control-Request-Method': 'POST',
      },
    });

    const allowOrigin = response.headers.get('access-control-allow-origin');

    if (allowOrigin) {
      expect(allowOrigin).not.toBe('*');
      expect(allowOrigin).not.toBe('https://malicious-site.com');
    }
  });
});
