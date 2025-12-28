/**
 * USR-08: Create Group via SCIM
 *
 * Validates that groups can be created via SCIM 2.0 API.
 */

import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { httpClient, buildBasicAuth, type TokenResponse } from '../../support/api';
import { ENDPOINTS } from '../../setup';
import { TEST_CLIENTS } from '../../fixtures';

describe('USR-08: Create Group via SCIM', () => {
  let accessToken: string;
  const createdGroupIds: string[] = [];

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

  afterAll(async () => {
    // Cleanup created groups
    for (const groupId of createdGroupIds) {
      try {
        await httpClient.delete(`${ENDPOINTS.scimGroups}/${groupId}`, {
          headers: {
            Authorization: `Bearer ${accessToken}`,
          },
        });
      } catch {
        // Ignore cleanup errors
      }
    }
  });

  it('should create group with valid payload', async () => {
    const groupName = `test-group-${Date.now()}`;

    const response = await httpClient.postJson<{
      id: string;
      displayName: string;
      schemas: string[];
    }>(ENDPOINTS.scimGroups, {
      schemas: ['urn:ietf:params:scim:schemas:core:2.0:Group'],
      displayName: groupName,
    }, {
      headers: {
        Authorization: `Bearer ${accessToken}`,
      },
    });

    expect(response.status).toBe(201);
    expect(response.data.id).toBeDefined();
    expect(response.data.displayName).toBe(groupName);

    createdGroupIds.push(response.data.id);
  });

  it('should return SCIM schema in group response', async () => {
    const groupName = `schema-test-group-${Date.now()}`;

    const response = await httpClient.postJson<{
      id: string;
      schemas: string[];
    }>(ENDPOINTS.scimGroups, {
      schemas: ['urn:ietf:params:scim:schemas:core:2.0:Group'],
      displayName: groupName,
    }, {
      headers: {
        Authorization: `Bearer ${accessToken}`,
      },
    });

    expect(response.status).toBe(201);
    expect(response.data.schemas).toContain('urn:ietf:params:scim:schemas:core:2.0:Group');

    if (response.data.id) {
      createdGroupIds.push(response.data.id);
    }
  });
});
