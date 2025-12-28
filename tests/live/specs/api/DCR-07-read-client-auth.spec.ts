/**
 * DCR-07: Read Client (Auth)
 *
 * Validates that reading client configuration requires authentication.
 * Per RFC 7592, this uses the registration_access_token (Bearer token),
 * not Basic Auth with client credentials.
 */

import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { httpClient } from '../../support/api';
import { createValidDCRPayload } from '../../fixtures';
import { ENDPOINTS } from '../../setup';

describe('DCR-07: Read Client (Auth)', () => {
  let testClient: {
    client_id: string;
    registration_access_token: string;
  };

  beforeAll(async () => {
    // Create a client to read
    const payload = createValidDCRPayload();
    const response = await httpClient.postJson<{
      client_id: string;
      registration_access_token: string;
    }>(ENDPOINTS.register, payload);

    expect(response.status).toBe(201);
    testClient = {
      client_id: response.data.client_id,
      registration_access_token: response.data.registration_access_token,
    };
  });

  afterAll(async () => {
    if (testClient?.registration_access_token) {
      try {
        await httpClient.delete(`${ENDPOINTS.register}/${testClient.client_id}`, {
          headers: { Authorization: `Bearer ${testClient.registration_access_token}` },
        });
      } catch {
        // Ignore cleanup errors
      }
    }
  });

  it('should return 401 Unauthorized when reading client without authentication', async () => {
    // Act - No Authorization header
    const response = await httpClient.get(`${ENDPOINTS.register}/${testClient.client_id}`);

    // Assert
    expect(response.status).toBe(401);
  });

  it('should return 401 Unauthorized with invalid Bearer token', async () => {
    // Arrange - Invalid token
    const response = await httpClient.get(`${ENDPOINTS.register}/${testClient.client_id}`, {
      headers: { Authorization: 'Bearer invalid-token-12345' },
    });

    // Assert
    expect(response.status).toBe(401);
  });

  it('should return client data with valid registration_access_token', async () => {
    // Act - Use the registration_access_token from creation
    const response = await httpClient.get<{ client_id: string }>(
      `${ENDPOINTS.register}/${testClient.client_id}`,
      {
        headers: { Authorization: `Bearer ${testClient.registration_access_token}` },
      }
    );

    // Assert
    expect(response.status).toBe(200);
    expect(response.data.client_id).toBe(testClient.client_id);
  });
});
