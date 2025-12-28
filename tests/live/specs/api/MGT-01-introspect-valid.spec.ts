/**
 * MGT-01: Introspect Valid Token
 *
 * Validates that token introspection returns active=true for
 * valid, non-expired tokens.
 *
 * Per RFC 7662, the introspection endpoint allows resource servers
 * to query the authorization server about the state of a token.
 */

import { describe, it, expect } from 'vitest';
import { httpClient, buildBasicAuth, type IntrospectionResponse, type TokenResponse } from '../../support/api';
import { ENDPOINTS } from '../../setup';
import { TEST_CLIENTS } from '../../fixtures';

describe('MGT-01: Introspect Valid Token', () => {
  it('should return active=true for valid access token', async () => {
    // First, get a valid access token via client_credentials
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
    const accessToken = tokenResponse.data.access_token;

    // Introspect the token
    const introspectResponse = await httpClient.postForm<IntrospectionResponse>(
      ENDPOINTS.introspect,
      { token: accessToken },
      {
        headers: {
          Authorization: buildBasicAuth(
            TEST_CLIENTS.adminCli.client_id,
            TEST_CLIENTS.adminCli.client_secret
          ),
        },
      }
    );

    expect(introspectResponse.status).toBe(200);
    expect(introspectResponse.data.active).toBe(true);
  });

  it('should return token metadata for valid token', async () => {
    const tokenResponse = await httpClient.postForm<TokenResponse>(ENDPOINTS.token, {
      grant_type: 'client_credentials',
      scope: 'openid',
    }, {
      headers: {
        Authorization: buildBasicAuth(
          TEST_CLIENTS.adminCli.client_id,
          TEST_CLIENTS.adminCli.client_secret
        ),
      },
    });

    expect(tokenResponse.status).toBe(200);

    const introspectResponse = await httpClient.postForm<IntrospectionResponse>(
      ENDPOINTS.introspect,
      { token: tokenResponse.data.access_token },
      {
        headers: {
          Authorization: buildBasicAuth(
            TEST_CLIENTS.adminCli.client_id,
            TEST_CLIENTS.adminCli.client_secret
          ),
        },
      }
    );

    expect(introspectResponse.status).toBe(200);
    expect(introspectResponse.data.active).toBe(true);

    // Should include standard claims
    if (introspectResponse.data.client_id) {
      expect(introspectResponse.data.client_id).toBe(TEST_CLIENTS.adminCli.client_id);
    }
    if (introspectResponse.data.exp) {
      expect(introspectResponse.data.exp).toBeGreaterThan(Math.floor(Date.now() / 1000));
    }
  });
});
