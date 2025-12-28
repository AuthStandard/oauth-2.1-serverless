/**
 * USR-01: Create User via SCIM
 *
 * Validates that users can be provisioned via SCIM 2.0 API.
 * Per RFC 7643 and RFC 7644.
 */

import { describe, it, expect, beforeAll } from 'vitest';
import { httpClient, buildBasicAuth, type TokenResponse } from '../../support/api';
import { ENDPOINTS } from '../../setup';
import { TEST_CLIENTS } from '../../fixtures';

describe('USR-01: Create User via SCIM', () => {
  let accessToken: string;

  beforeAll(async () => {
    // Get access token for SCIM operations
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

  it('should create user with valid SCIM payload', async () => {
    const uniqueEmail = `scim-test-${Date.now()}@example.com`;

    const response = await httpClient.postJson<{
      id: string;
      userName: string;
      emails: Array<{ value: string; primary: boolean }>;
      schemas: string[];
    }>(ENDPOINTS.scimUsers, {
      schemas: ['urn:ietf:params:scim:schemas:core:2.0:User'],
      userName: uniqueEmail,
      emails: [{ value: uniqueEmail, primary: true }],
      name: {
        givenName: 'SCIM',
        familyName: 'Test',
      },
      active: true,
    }, {
      headers: {
        Authorization: `Bearer ${accessToken}`,
      },
    });

    expect(response.status).toBe(201);
    expect(response.data.id).toBeDefined();
    expect(response.data.userName).toBe(uniqueEmail);
  });

  it('should return SCIM schema in response', async () => {
    const uniqueEmail = `scim-schema-${Date.now()}@example.com`;

    const response = await httpClient.postJson<{
      schemas: string[];
      meta: { resourceType: string };
    }>(ENDPOINTS.scimUsers, {
      schemas: ['urn:ietf:params:scim:schemas:core:2.0:User'],
      userName: uniqueEmail,
      emails: [{ value: uniqueEmail, primary: true }],
      active: true,
    }, {
      headers: {
        Authorization: `Bearer ${accessToken}`,
      },
    });

    expect(response.status).toBe(201);
    expect(response.data.schemas).toContain('urn:ietf:params:scim:schemas:core:2.0:User');
  });
});
