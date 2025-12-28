/**
 * TOK-16: Client Credentials Happy Path
 *
 * Validates that the client_credentials grant works correctly
 * for machine-to-machine authentication.
 *
 * Per RFC 6749 Section 4.4, the client credentials grant is used
 * when the client is acting on its own behalf.
 */

import { describe, it, expect } from 'vitest';
import { httpClient, assertTokenResponse, buildBasicAuth, assertValidJWT } from '../../support/api';
import { ENDPOINTS } from '../../setup';
import { TEST_CLIENTS } from '../../fixtures';

describe('TOK-16: Client Credentials Happy Path', () => {
  it('should return access token for valid client credentials', async () => {
    const response = await httpClient.postForm(ENDPOINTS.token, {
      grant_type: 'client_credentials',
    }, {
      headers: {
        Authorization: buildBasicAuth(
          TEST_CLIENTS.adminCli.client_id,
          TEST_CLIENTS.adminCli.client_secret
        ),
      },
    });

    const tokenResponse = assertTokenResponse(response);

    // Verify access token is a valid JWT
    assertValidJWT(tokenResponse.access_token);

    // Client credentials should NOT return a refresh token
    expect(tokenResponse.refresh_token).toBeUndefined();

    // Token type should be Bearer
    expect(tokenResponse.token_type.toLowerCase()).toBe('bearer');
  });

  it('should return access token with requested scope', async () => {
    const response = await httpClient.postForm(ENDPOINTS.token, {
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

    const tokenResponse = assertTokenResponse(response);
    assertValidJWT(tokenResponse.access_token);
  });
});
