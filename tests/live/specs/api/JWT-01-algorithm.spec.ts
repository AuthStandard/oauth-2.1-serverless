/**
 * JWT-01: Algorithm Verification
 *
 * Validates that JWTs use secure asymmetric algorithms (RS256/ES256)
 * and not vulnerable algorithms like HS256 or none.
 */

import { describe, it, expect } from 'vitest';
import { httpClient, buildBasicAuth, decodeJWT, type TokenResponse } from '../../support/api';
import { ENDPOINTS } from '../../setup';
import { TEST_CLIENTS } from '../../fixtures';

describe('JWT-01: Algorithm Verification', () => {
  it('should use RS256 or ES256 algorithm', async () => {
    const response = await httpClient.postForm<TokenResponse>(ENDPOINTS.token, {
      grant_type: 'client_credentials',
    }, {
      headers: {
        Authorization: buildBasicAuth(
          TEST_CLIENTS.adminCli.client_id,
          TEST_CLIENTS.adminCli.client_secret
        ),
      },
    });

    expect(response.status).toBe(200);

    const { header } = decodeJWT(response.data.access_token);

    // Must use asymmetric algorithm
    expect(['RS256', 'RS384', 'RS512', 'ES256', 'ES384', 'ES512', 'PS256', 'PS384', 'PS512']).toContain(header.alg);

    // Must NOT use vulnerable algorithms
    expect(header.alg).not.toBe('HS256');
    expect(header.alg).not.toBe('HS384');
    expect(header.alg).not.toBe('HS512');
    expect(header.alg).not.toBe('none');
  });

  it('should include kid in JWT header', async () => {
    const response = await httpClient.postForm<TokenResponse>(ENDPOINTS.token, {
      grant_type: 'client_credentials',
    }, {
      headers: {
        Authorization: buildBasicAuth(
          TEST_CLIENTS.adminCli.client_id,
          TEST_CLIENTS.adminCli.client_secret
        ),
      },
    });

    expect(response.status).toBe(200);

    const { header } = decodeJWT(response.data.access_token);

    // kid is required for key rotation support
    expect(header.kid).toBeDefined();
    expect(typeof header.kid).toBe('string');
  });
});
