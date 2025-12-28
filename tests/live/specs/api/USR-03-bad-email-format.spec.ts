/**
 * USR-03: Bad Email Format Validation
 *
 * Validates that invalid email formats are rejected.
 */

import { describe, it, expect, beforeAll } from 'vitest';
import { httpClient, buildBasicAuth, type TokenResponse } from '../../support/api';
import { ENDPOINTS } from '../../setup';
import { TEST_CLIENTS } from '../../fixtures';

describe('USR-03: Bad Email Format Validation', () => {
  let accessToken: string;

  beforeAll(async () => {
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
    accessToken = tokenResponse.data.access_token;
  });

  it('should return 400 for invalid email format', async () => {
    const response = await httpClient.postJson(ENDPOINTS.scimUsers, {
      schemas: ['urn:ietf:params:scim:schemas:core:2.0:User'],
      userName: 'bob', // Invalid - no domain
      emails: [{ value: 'bob', primary: true }],
      active: true,
    }, {
      headers: {
        Authorization: `Bearer ${accessToken}`,
      },
    });

    expect(response.status).toBe(400);
  });

  it('should return 400 for missing email', async () => {
    const response = await httpClient.postJson(ENDPOINTS.scimUsers, {
      schemas: ['urn:ietf:params:scim:schemas:core:2.0:User'],
      userName: 'test-no-email',
      active: true,
    }, {
      headers: {
        Authorization: `Bearer ${accessToken}`,
      },
    });

    expect(response.status).toBe(400);
  });
});
