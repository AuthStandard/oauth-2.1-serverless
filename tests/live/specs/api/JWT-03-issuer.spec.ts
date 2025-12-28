/**
 * JWT-03: Issuer Claim Verification
 *
 * Validates that the JWT issuer matches the discovery document issuer.
 */

import { describe, it, expect } from 'vitest';
import { httpClient, buildBasicAuth, decodeJWT, type TokenResponse, type OIDCDiscoveryDocument } from '../../support/api';
import { ENDPOINTS } from '../../setup';
import { TEST_CLIENTS } from '../../fixtures';

describe('JWT-03: Issuer Claim Verification', () => {
  it('should have issuer matching discovery document', async () => {
    // Get discovery document
    const discoveryResponse = await httpClient.get<OIDCDiscoveryDocument>(ENDPOINTS.discovery);
    expect(discoveryResponse.status).toBe(200);
    const expectedIssuer = discoveryResponse.data.issuer;

    // Get a token
    const tokenResponse = await httpClient.postForm<TokenResponse>(ENDPOINTS.token, {
      grant_type: 'client_credentials',
    }, {
      headers: {
        Authorization: buildBasicAuth(
          TEST_CLIENTS.adminCli.client_id,
          TEST_CLIENTS.adminCli.client_secret
        ),
      },
    });

    expect(tokenResponse.status).toBe(200);

    const { payload } = decodeJWT(tokenResponse.data.access_token);

    // Issuer must match exactly
    expect(payload.iss).toBe(expectedIssuer);
  });
});
