/**
 * DCR-01: Valid Registration
 *
 * Validates that a properly formatted Dynamic Client Registration request
 * returns a 201 Created response with client_id and client_secret.
 * This is the happy path for RFC 7591 compliance.
 */

import { describe, it, expect, afterAll } from 'vitest';
import { httpClient } from '../../support/api';
import { createValidDCRPayload } from '../../fixtures';
import { ENDPOINTS } from '../../setup';

describe('DCR-01: Valid Registration', () => {
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

  it('should return 201 Created with client_id and client_secret for valid registration', async () => {
    // Arrange
    const payload = createValidDCRPayload();

    // Act
    const response = await httpClient.postJson<{
      client_id: string;
      client_secret?: string;
      registration_access_token: string;
      client_id_issued_at?: number;
      client_secret_expires_at?: number;
    }>(ENDPOINTS.register, payload);

    // Assert
    expect(response.status).toBe(201);
    expect(response.data.client_id).toBeDefined();
    expect(typeof response.data.client_id).toBe('string');
    expect(response.data.client_id.length).toBeGreaterThan(0);

    // Confidential clients should receive a client_secret
    expect(response.data.client_secret).toBeDefined();
    expect(typeof response.data.client_secret).toBe('string');
    expect(response.data.client_secret!.length).toBeGreaterThan(0);

    // Track for cleanup
    createdClients.push({
      client_id: response.data.client_id,
      registration_access_token: response.data.registration_access_token,
    });
  });

  it('should return registration metadata in response', async () => {
    // Arrange
    const payload = createValidDCRPayload({
      client_name: 'Metadata Test Client',
    });

    // Act
    const response = await httpClient.postJson<{
      client_id: string;
      client_name?: string;
      redirect_uris?: string[];
      grant_types?: string[];
      response_types?: string[];
      registration_access_token: string;
    }>(ENDPOINTS.register, payload);

    // Assert
    expect(response.status).toBe(201);
    expect(response.data.client_name).toBe('Metadata Test Client');
    expect(response.data.redirect_uris).toContain('https://example.com/callback');
    expect(response.data.grant_types).toContain('authorization_code');
    expect(response.data.response_types).toContain('code');

    createdClients.push({
      client_id: response.data.client_id,
      registration_access_token: response.data.registration_access_token,
    });
  });
});
