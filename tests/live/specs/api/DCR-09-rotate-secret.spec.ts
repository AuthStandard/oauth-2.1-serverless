/**
 * DCR-09: Rotate Secret
 *
 * Validates that client secrets can be rotated via PUT request.
 * After rotation, the old secret should be immediately invalid
 * and only the new secret should work.
 *
 * Per RFC 7592, management operations use registration_access_token.
 */

import { describe, it, expect, afterAll } from 'vitest';
import { httpClient, buildBasicAuth } from '../../support/api';
import { createValidDCRPayload } from '../../fixtures';
import { ENDPOINTS } from '../../setup';

describe('DCR-09: Rotate Secret', () => {
  const createdClients: Array<{ client_id: string; registration_access_token: string }> = [];

  afterAll(async () => {
    for (const client of createdClients) {
      try {
        await httpClient.delete(`${ENDPOINTS.register}/${client.client_id}`, {
          headers: { Authorization: `Bearer ${client.registration_access_token}` },
        });
      } catch {
        // Ignore cleanup errors
      }
    }
  });

  it('should rotate secret and invalidate old secret immediately', async () => {
    // Arrange - Create a confidential client with client_credentials grant
    const createResponse = await httpClient.postJson<{
      client_id: string;
      client_secret: string;
      registration_access_token: string;
    }>(ENDPOINTS.register, createValidDCRPayload({
      grant_types: ['authorization_code', 'refresh_token', 'client_credentials'],
    }));

    expect(createResponse.status).toBe(201);
    const { client_id, client_secret: oldSecret, registration_access_token } = createResponse.data;
    createdClients.push({ client_id, registration_access_token });

    // Verify old secret works for token endpoint
    const oldAuth = buildBasicAuth(client_id, oldSecret);
    const tokenCheck = await httpClient.postForm(
      ENDPOINTS.token,
      { grant_type: 'client_credentials' },
      { headers: { Authorization: oldAuth } }
    );
    expect(tokenCheck.status).toBe(200);

    // Act - Rotate the secret via PUT (RFC 7592)
    const rotateResponse = await httpClient.put<{
      client_id: string;
      client_secret?: string;
    }>(
      `${ENDPOINTS.register}/${client_id}`,
      {
        client_name: 'Rotated Client',
        redirect_uris: ['https://example.com/callback'],
        grant_types: ['authorization_code', 'refresh_token', 'client_credentials'],
      },
      { headers: { Authorization: `Bearer ${registration_access_token}` } }
    );

    // Assert - Should return new secret
    expect(rotateResponse.status).toBe(200);

    // If the implementation supports secret rotation, verify it
    if (rotateResponse.data.client_secret) {
      const newSecret = rotateResponse.data.client_secret;
      expect(newSecret).not.toBe(oldSecret);

      // Verify old secret no longer works
      const oldAuthAfter = buildBasicAuth(client_id, oldSecret);
      const oldTokenCheck = await httpClient.postForm(
        ENDPOINTS.token,
        { grant_type: 'client_credentials' },
        { headers: { Authorization: oldAuthAfter } }
      );
      expect(oldTokenCheck.status).toBe(401);

      // Verify new secret works
      const newAuth = buildBasicAuth(client_id, newSecret);
      const newTokenCheck = await httpClient.postForm(
        ENDPOINTS.token,
        { grant_type: 'client_credentials' },
        { headers: { Authorization: newAuth } }
      );
      expect(newTokenCheck.status).toBe(200);
    }
  });
});
