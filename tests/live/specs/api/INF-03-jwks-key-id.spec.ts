/**
 * INF-03: JWKS Key ID Rotation
 *
 * Validates that the JWKS endpoint returns keys with Key IDs (kid),
 * which is essential for key rotation support.
 *
 * Without kid, clients cannot determine which key to use for verification
 * when multiple keys exist (during rotation), leading to verification failures
 * or security vulnerabilities.
 *
 * @see RFC 7517 Section 4.5 - "kid" (Key ID) Parameter
 */

import { describe, it, expect } from 'vitest';
import { httpClient, type JWKSDocument } from '../../support/api';
import { ENDPOINTS } from '../../setup';

describe('INF-03: JWKS Key ID Rotation', () => {
  it('should return at least one key in the JWKS', async () => {
    const response = await httpClient.get<JWKSDocument>(ENDPOINTS.keys);

    expect(response.status).toBe(200);
    expect(response.data.keys).toBeDefined();
    expect(response.data.keys.length).toBeGreaterThan(0);
  });

  it('should include kid (Key ID) in all keys', async () => {
    const response = await httpClient.get<JWKSDocument>(ENDPOINTS.keys);

    for (const key of response.data.keys) {
      expect(key.kid).toBeDefined();
      expect(typeof key.kid).toBe('string');
      expect(key.kid.length).toBeGreaterThan(0);
    }
  });

  it('should have unique kid values for each key', async () => {
    const response = await httpClient.get<JWKSDocument>(ENDPOINTS.keys);

    const kids = response.data.keys.map((key) => key.kid);
    const uniqueKids = new Set(kids);

    expect(uniqueKids.size).toBe(kids.length);
  });

  it('should include required key parameters for signature verification', async () => {
    const response = await httpClient.get<JWKSDocument>(ENDPOINTS.keys);

    for (const key of response.data.keys) {
      // Key type is required
      expect(key.kty).toBeDefined();

      // For RSA keys (most common for OAuth)
      if (key.kty === 'RSA') {
        expect(key.n).toBeDefined(); // modulus
        expect(key.e).toBeDefined(); // exponent
      }

      // For EC keys
      if (key.kty === 'EC') {
        expect(key.crv).toBeDefined(); // curve
        expect(key.x).toBeDefined();
        expect(key.y).toBeDefined();
      }

      // Key use should indicate signature
      if (key.use) {
        expect(key.use).toBe('sig');
      }

      // Algorithm should be specified
      if (key.alg) {
        // Should be a secure algorithm (not HS256 for public JWKS)
        expect(['RS256', 'RS384', 'RS512', 'ES256', 'ES384', 'ES512', 'PS256', 'PS384', 'PS512']).toContain(
          key.alg
        );
      }
    }
  });
});
