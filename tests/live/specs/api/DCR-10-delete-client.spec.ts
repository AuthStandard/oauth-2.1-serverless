/**
 * DCR-10: Delete Client
 *
 * Validates that clients can be deleted and that subsequent
 * authentication attempts with the deleted client fail.
 * Per RFC 7592, deletion uses registration_access_token.
 */

import { describe, it, expect } from 'vitest';
import { httpClient, buildBasicAuth } from '../../support/api';
import { createValidDCRPayload } from '../../fixtures';
import { ENDPOINTS } from '../../setup';

describe('DCR-10: Delete Client', () => {
  it('should delete client and reject subsequent token requests', async () => {
    // Arrange - Create a client with client_credentials grant
    const createResponse = await httpClient.postJson<{
      client_id: string;
      client_secret: string;
      registration_access_token: string;
    }>(ENDPOINTS.register, createValidDCRPayload({
      grant_types: ['authorization_code', 'refresh_token', 'client_credentials'],
    }));

    expect(createResponse.status).toBe(201);
    const { client_id, client_secret, registration_access_token } = createResponse.data;

    // Verify client works for token endpoint
    const clientAuth = buildBasicAuth(client_id, client_secret);
    const tokenCheck = await httpClient.postForm(
      ENDPOINTS.token,
      { grant_type: 'client_credentials' },
      { headers: { Authorization: clientAuth } }
    );
    expect(tokenCheck.status).toBe(200);

    // Act - Delete the client using registration_access_token
    const deleteResponse = await httpClient.delete(`${ENDPOINTS.register}/${client_id}`, {
      headers: { Authorization: `Bearer ${registration_access_token}` },
    });

    // Assert - Should return 204 No Content
    expect(deleteResponse.status).toBe(204);

    // Verify client no longer exists (read should fail)
    const verifyDeleted = await httpClient.get(`${ENDPOINTS.register}/${client_id}`, {
      headers: { Authorization: `Bearer ${registration_access_token}` },
    });
    expect([401, 404]).toContain(verifyDeleted.status);

    // Verify token requests fail
    const tokenResponse = await httpClient.postForm(
      ENDPOINTS.token,
      { grant_type: 'client_credentials' },
      { headers: { Authorization: clientAuth } }
    );
    expect(tokenResponse.status).toBe(401);
  });

  it('should return 401 when deleting with invalid token', async () => {
    // Arrange - Create a client first
    const createResponse = await httpClient.postJson<{
      client_id: string;
      registration_access_token: string;
    }>(ENDPOINTS.register, createValidDCRPayload());

    expect(createResponse.status).toBe(201);
    const { client_id, registration_access_token } = createResponse.data;

    // Act - Try to delete with wrong token
    const response = await httpClient.delete(`${ENDPOINTS.register}/${client_id}`, {
      headers: { Authorization: 'Bearer wrong-token-12345' },
    });

    // Assert - Should be unauthorized
    expect(response.status).toBe(401);

    // Cleanup - Delete with correct token
    await httpClient.delete(`${ENDPOINTS.register}/${client_id}`, {
      headers: { Authorization: `Bearer ${registration_access_token}` },
    });
  });
});
