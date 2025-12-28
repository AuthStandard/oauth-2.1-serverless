/**
 * JWT-04: Expiry Claim Verification
 *
 * Validates that JWTs have a reasonable expiration time in the future.
 */

import { describe, it, expect } from 'vitest';
import { httpClient, buildBasicAuth, decodeJWT, type TokenResponse } from '../../support/api';
import { ENDPOINTS } from '../../setup';
import { TEST_CLIENTS } from '../../fixtures';

describe('JWT-04: Expiry Claim Verification', () => {
  it('should have exp claim in the future', async () => {
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

    const { payload } = decodeJWT(response.data.access_token);
    const now = Math.floor(Date.now() / 1000);

    // exp must be present
    expect(payload.exp).toBeDefined();
    expect(typeof payload.exp).toBe('number');

    // exp must be in the future
    expect(payload.exp).toBeGreaterThan(now);

    // exp should be reasonable (not more than 24 hours for access tokens)
    const maxExpiry = now + (24 * 60 * 60);
    expect(payload.exp).toBeLessThanOrEqual(maxExpiry);
  });

  it('should have iat claim at or before current time', async () => {
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

    const { payload } = decodeJWT(response.data.access_token);
    const now = Math.floor(Date.now() / 1000);

    // iat should be present
    if (payload.iat) {
      // iat should be at or before current time (with small tolerance for clock skew)
      expect(payload.iat).toBeLessThanOrEqual(now + 60);
    }
  });
});
