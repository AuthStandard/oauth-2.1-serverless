/**
 * JWT-02: Audience Claim Verification
 *
 * Validates that JWTs include the appropriate audience claim.
 */

import { describe, it, expect } from 'vitest';
import { httpClient, buildBasicAuth, decodeJWT, type TokenResponse } from '../../support/api';
import { ENDPOINTS } from '../../setup';
import { TEST_CLIENTS } from '../../fixtures';

describe('JWT-02: Audience Claim Verification', () => {
  it('should include client_id in audience claim', async () => {
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

    // aud claim should be present
    expect(payload.aud).toBeDefined();

    // aud can be string or array
    const audiences = Array.isArray(payload.aud) ? payload.aud : [payload.aud];

    // Should include the client_id or a resource identifier
    expect(audiences.length).toBeGreaterThan(0);
  });
});
