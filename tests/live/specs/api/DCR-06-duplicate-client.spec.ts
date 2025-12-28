/**
 * DCR-06: Duplicate Client
 *
 * Validates that client IDs are UUIDs and collision probability is
 * effectively zero. This test verifies the system generates unique
 * identifiers for each registration.
 */

import { describe, it, expect, afterAll } from 'vitest';
import { httpClient } from '../../support/api';
import { createValidDCRPayload } from '../../fixtures';
import { ENDPOINTS } from '../../setup';

describe('DCR-06: Duplicate Client', () => {
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

  it('should generate unique client_id for each registration', async () => {
    // Arrange
    const registrations = 5;
    const clientIds = new Set<string>();

    // Act - Register multiple clients
    for (let i = 0; i < registrations; i++) {
      const payload = createValidDCRPayload({
        client_name: `Uniqueness Test Client ${i}`,
      });

      const response = await httpClient.postJson<{
        client_id: string;
        registration_access_token: string;
      }>(ENDPOINTS.register, payload);

      expect(response.status).toBe(201);
      clientIds.add(response.data.client_id);
      createdClients.push({
        client_id: response.data.client_id,
        registration_access_token: response.data.registration_access_token,
      });
    }

    // Assert - All client IDs should be unique
    expect(clientIds.size).toBe(registrations);
  });

  it('should generate client_id in UUID format', async () => {
    // Arrange
    const payload = createValidDCRPayload();

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

    // UUID v4 format: xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx
    const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
    expect(response.data.client_id).toMatch(uuidRegex);
  });
});
