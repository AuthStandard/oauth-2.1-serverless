/**
 * INF-02: JWKS Caching Headers
 *
 * Validates that the JWKS endpoint returns appropriate caching headers
 * to prevent KMS throttling and DoS attacks.
 *
 * Without proper caching, every token validation would hit the JWKS endpoint,
 * potentially causing KMS throttling (if keys are fetched from KMS) and
 * enabling denial-of-service through cache-busting attacks.
 *
 * @see RFC 7517 - JSON Web Key (JWK)
 */

import { describe, it, expect } from 'vitest';
import { httpClient, type JWKSDocument, assertHeader } from '../../support/api';
import { ENDPOINTS } from '../../setup';

describe('INF-02: JWKS Caching Headers', () => {
  it('should return 200 OK with valid JWKS document', async () => {
    const response = await httpClient.get<JWKSDocument>(ENDPOINTS.keys);

    expect(response.status).toBe(200);
    expect(response.headers.get('content-type')).toContain('application/json');
    expect(response.data.keys).toBeDefined();
    expect(Array.isArray(response.data.keys)).toBe(true);
  });

  it('should include Cache-Control header with public directive', async () => {
    const response = await httpClient.get<JWKSDocument>(ENDPOINTS.keys);

    const cacheControl = response.headers.get('cache-control');
    expect(cacheControl).toBeDefined();

    // Should be publicly cacheable
    expect(cacheControl?.toLowerCase()).toContain('public');
  });

  it('should include Cache-Control header with max-age directive', async () => {
    const response = await httpClient.get<JWKSDocument>(ENDPOINTS.keys);

    const cacheControl = response.headers.get('cache-control');
    expect(cacheControl).toBeDefined();

    // Should have a max-age value
    const maxAgeMatch = cacheControl?.match(/max-age=(\d+)/);
    expect(maxAgeMatch).toBeTruthy();

    if (maxAgeMatch) {
      const maxAge = parseInt(maxAgeMatch[1], 10);
      // Should be at least 5 minutes (300 seconds) to be effective
      expect(maxAge).toBeGreaterThanOrEqual(300);
    }
  });

  it('should allow caching by intermediaries (no private directive)', async () => {
    const response = await httpClient.get<JWKSDocument>(ENDPOINTS.keys);

    const cacheControl = response.headers.get('cache-control')?.toLowerCase() || '';

    // JWKS should be publicly cacheable, not private
    // Private would prevent CDN/proxy caching
    expect(cacheControl).not.toContain('private');
    expect(cacheControl).not.toContain('no-store');
    expect(cacheControl).not.toContain('no-cache');
  });
});
