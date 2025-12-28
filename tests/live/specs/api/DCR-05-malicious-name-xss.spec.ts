/**
 * DCR-05: Malicious Name (XSS)
 *
 * Validates that client_name containing XSS payloads is rejected.
 * This prevents stored XSS attacks when client names are displayed
 * in consent screens or admin UIs.
 */

import { describe, it, expect, afterAll } from 'vitest';
import { httpClient, assertOAuth2Error } from '../../support/api';
import { createValidDCRPayload, MALICIOUS_VALUES } from '../../fixtures';
import { ENDPOINTS } from '../../setup';

describe('DCR-05: Malicious Name (XSS)', () => {
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

  it('should reject XSS script tags in client_name', async () => {
    // Arrange
    const payload = createValidDCRPayload({
      client_name: MALICIOUS_VALUES.xssScript, // <script>alert(1)</script>
    });

    // Act
    const response = await httpClient.postJson(ENDPOINTS.register, payload);

    // Assert - Server must reject malicious input
    expect(response.status).toBe(400);
    assertOAuth2Error(response, 'invalid_client_metadata');
  });

  it('should reject HTML img tags with event handlers', async () => {
    // Arrange - Event handler XSS
    const payload = createValidDCRPayload({
      client_name: 'Test<img src=x onerror=alert(1)>App',
    });

    // Act
    const response = await httpClient.postJson(ENDPOINTS.register, payload);

    // Assert - Server must reject malicious input
    expect(response.status).toBe(400);
    assertOAuth2Error(response, 'invalid_client_metadata');
  });

  it('should reject HTML anchor tags', async () => {
    // Arrange
    const payload = createValidDCRPayload({
      client_name: '<a href="javascript:alert(1)">Click me</a>',
    });

    // Act
    const response = await httpClient.postJson(ENDPOINTS.register, payload);

    // Assert
    expect(response.status).toBe(400);
    assertOAuth2Error(response, 'invalid_client_metadata');
  });

  it('should accept clean client names', async () => {
    // Arrange - Normal client name
    const payload = createValidDCRPayload({
      client_name: 'My Awesome App - v2.0',
    });

    // Act
    const response = await httpClient.postJson<{
      client_id: string;
      client_name: string;
      registration_access_token: string;
    }>(ENDPOINTS.register, payload);

    // Assert - Should succeed
    expect(response.status).toBe(201);
    expect(response.data.client_name).toBe('My Awesome App - v2.0');

    createdClients.push({
      client_id: response.data.client_id,
      registration_access_token: response.data.registration_access_token,
    });
  });
});
