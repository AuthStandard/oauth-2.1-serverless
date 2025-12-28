/**
 * AUT-06: Fuzzy URI Match Prevention
 *
 * Validates that redirect URI matching is exact per RFC 6749.
 * Adding query parameters to a registered URI should be rejected.
 *
 * Per OAuth 2.0 Security Best Current Practice, redirect URI comparison
 * must be performed using simple string comparison.
 */

import { describe, it, expect } from 'vitest';
import { httpClient } from '../../support/api';
import { ENDPOINTS } from '../../setup';
import { TEST_CLIENTS, generatePKCE, generateState } from '../../fixtures';

describe('AUT-06: Fuzzy URI Match Prevention', () => {
  it('should reject redirect_uri with added query parameters', async () => {
    const { challenge } = generatePKCE();
    const state = generateState();

    // Registered: https://example.com/callback
    // Requested: https://example.com/callback?foo=bar
    const params = new URLSearchParams({
      client_id: TEST_CLIENTS.confidential.client_id,
      response_type: 'code',
      redirect_uri: `${TEST_CLIENTS.confidential.redirect_uri}?foo=bar`,
      code_challenge: challenge,
      code_challenge_method: 'S256',
      state,
    });

    const response = await httpClient.get(`${ENDPOINTS.authorize}?${params}`, {
      followRedirects: false,
    });

    expect(response.status).toBe(400);
  });

  it('should reject redirect_uri with trailing slash difference', async () => {
    const { challenge } = generatePKCE();
    const state = generateState();

    // Registered: https://example.com/callback
    // Requested: https://example.com/callback/
    const params = new URLSearchParams({
      client_id: TEST_CLIENTS.confidential.client_id,
      response_type: 'code',
      redirect_uri: `${TEST_CLIENTS.confidential.redirect_uri}/`,
      code_challenge: challenge,
      code_challenge_method: 'S256',
      state,
    });

    const response = await httpClient.get(`${ENDPOINTS.authorize}?${params}`, {
      followRedirects: false,
    });

    expect(response.status).toBe(400);
  });

  it('should reject redirect_uri with fragment', async () => {
    const { challenge } = generatePKCE();
    const state = generateState();

    const params = new URLSearchParams({
      client_id: TEST_CLIENTS.confidential.client_id,
      response_type: 'code',
      redirect_uri: `${TEST_CLIENTS.confidential.redirect_uri}#fragment`,
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
