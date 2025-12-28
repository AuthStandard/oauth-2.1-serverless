/**
 * DCR-04: Bad Redirect URI (Local)
 *
 * Validates that http://localhost is allowed for public (native) clients
 * per RFC 8252 (OAuth 2.0 for Native Apps). This is an exception to the
 * HTTPS requirement for development/native app scenarios.
 */

import { describe, it, expect, afterAll } from 'vitest';
import { httpClient } from '../../support/api';
import { createValidDCRPayload } from '../../fixtures';
import { ENDPOINTS } from '../../setup';

describe('DCR-04: Bad Redirect URI (Local)', () => {
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

  it('should allow http://localhost for public clients (RFC 8252)', async () => {
    // Arrange - Public client with localhost redirect
    const payload = createValidDCRPayload({
      redirect_uris: ['http://localhost:8080/callback'],
      token_endpoint_auth_method: 'none', // Public client
    });

    // Act
    const response = await httpClient.postJson<{
      client_id: string;
      redirect_uris?: string[];
      registration_access_token: string;
    }>(ENDPOINTS.register, payload);

    // Assert - Should be allowed for native apps
    expect(response.status).toBe(201);
    expect(response.data.client_id).toBeDefined();
    expect(response.data.redirect_uris).toContain('http://localhost:8080/callback');

    createdClients.push({
      client_id: response.data.client_id,
      registration_access_token: response.data.registration_access_token,
    });
  });

  it('should allow http://127.0.0.1 for public clients', async () => {
    // Arrange
    const payload = createValidDCRPayload({
      redirect_uris: ['http://127.0.0.1:3000/callback'],
      token_endpoint_auth_method: 'none',
    });

    // Act
    const response = await httpClient.postJson<{
      client_id: string;
      registration_access_token: string;
    }>(ENDPOINTS.register, payload);

    // Assert
    expect(response.status).toBe(201);
    createdClients.push({
      client_id: response.data.client_id,
      registration_access_token: response.data.registration_access_token,
    });
  });
});
