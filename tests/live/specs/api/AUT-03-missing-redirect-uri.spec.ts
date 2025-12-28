/**
 * AUT-03: Missing Redirect URI
 *
 * Validates that when a client has multiple registered redirect URIs,
 * the authorization request must include a redirect_uri parameter.
 *
 * Per RFC 6749 Section 3.1.2.3, if multiple redirection URIs have been
 * registered, the client MUST include a redirection URI with the
 * authorization request.
 */

import { describe, it, expect, afterAll } from 'vitest';
import { httpClient } from '../../support/api';
import { ENDPOINTS } from '../../setup';
import { generatePKCE, generateState, createValidDCRPayload } from '../../fixtures';

describe('AUT-03: Missing Redirect URI', () => {
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

  it('should return 400 when redirect_uri is missing and client has multiple URIs', async () => {
    // Create a client with multiple redirect URIs
    const createResponse = await httpClient.postJson<{
      client_id: string;
      registration_access_token: string;
    }>(ENDPOINTS.register, createValidDCRPayload({
      redirect_uris: [
        'https://example.com/callback1',
        'https://example.com/callback2',
      ],
    }));

    expect(createResponse.status).toBe(201);
    createdClients.push({
      client_id: createResponse.data.client_id,
      registration_access_token: createResponse.data.registration_access_token,
    });

    const { challenge } = generatePKCE();
    const state = generateState();

    // Request without redirect_uri
    const params = new URLSearchParams({
      client_id: createResponse.data.client_id,
      response_type: 'code',
      code_challenge: challenge,
      code_challenge_method: 'S256',
      state,
    });

    const response = await httpClient.get(`${ENDPOINTS.authorize}?${params}`, {
      followRedirects: false,
    });

    expect(response.status).toBe(400);
  });
});
