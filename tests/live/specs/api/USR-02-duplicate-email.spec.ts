/**
 * USR-02: Duplicate Email Prevention
 *
 * Validates that creating a user with an existing email returns 409 Conflict.
 */

import { describe, it, expect, beforeAll } from 'vitest';
import { httpClient, buildBasicAuth, type TokenResponse } from '../../support/api';
import { ENDPOINTS } from '../../setup';
import { TEST_CLIENTS, TEST_USERS } from '../../fixtures';

describe('USR-02: Duplicate Email Prevention', () => {
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

  it('should return 409 Conflict for duplicate email', async () => {
    // Try to create a user with an email that already exists (from seed data)
    const response = await httpClient.postJson(ENDPOINTS.scimUsers, {
      schemas: ['urn:ietf:params:scim:schemas:core:2.0:User'],
      userName: TEST_USERS.standard.email,
      emails: [{ value: TEST_USERS.standard.email, primary: true }],
      active: true,
    }, {
      headers: {
        Authorization: `Bearer ${accessToken}`,
      },
    });

    expect(response.status).toBe(409);
  });
});
