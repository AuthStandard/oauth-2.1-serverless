/**
 * DCR-08: Read Client (Wrong)
 *
 * Validates tenant isolation - a client's registration_access_token
 * should not be able to read another client's configuration.
 * This prevents information disclosure between tenants.
 */

import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { httpClient } from '../../support/api';
import { createValidDCRPayload } from '../../fixtures';
import { ENDPOINTS } from '../../setup';

describe('DCR-08: Read Client (Wrong)', () => {
  let clientA: { client_id: string; registration_access_token: string };
  let clientB: { client_id: string; registration_access_token: string };

  beforeAll(async () => {
    // Create Client A
    const responseA = await httpClient.postJson<{
      client_id: string;
      registration_access_token: string;
    }>(ENDPOINTS.register, createValidDCRPayload({ client_name: 'Client A' }));
    expect(responseA.status).toBe(201);
    clientA = {
      client_id: responseA.data.client_id,
      registration_access_token: responseA.data.registration_access_token,
    };

    // Create Client B
    const responseB = await httpClient.postJson<{
      client_id: string;
      registration_access_token: string;
    }>(ENDPOINTS.register, createValidDCRPayload({ client_name: 'Client B' }));
    expect(responseB.status).toBe(201);
    clientB = {
      client_id: responseB.data.client_id,
      registration_access_token: responseB.data.registration_access_token,
    };
  });

  afterAll(async () => {
    for (const client of [clientA, clientB]) {
      if (client?.registration_access_token) {
        try {
          await httpClient.delete(`${ENDPOINTS.register}/${client.client_id}`, {
            headers: { Authorization: `Bearer ${client.registration_access_token}` },
          });
        } catch {
          // Ignore cleanup errors
        }
      }
    }
  });

  it('should return 401 when Client B token tries to read Client A config', async () => {
    // Arrange - Use Client B's token
    // Act - Try to read Client A's configuration
    const response = await httpClient.get(`${ENDPOINTS.register}/${clientA.client_id}`, {
      headers: { Authorization: `Bearer ${clientB.registration_access_token}` },
    });

    // Assert - Should be unauthorized (token doesn't match)
    // RFC 7592 uses 401 for invalid token, not 403
    expect(response.status).toBe(401);
  });

  it('should allow client to read its own configuration', async () => {
    // Arrange - Use Client A's token
    // Act - Read own configuration
    const response = await httpClient.get<{ client_id: string }>(
      `${ENDPOINTS.register}/${clientA.client_id}`,
      {
        headers: { Authorization: `Bearer ${clientA.registration_access_token}` },
      }
    );

    // Assert - Should succeed
    expect(response.status).toBe(200);
    expect(response.data.client_id).toBe(clientA.client_id);
  });
});
