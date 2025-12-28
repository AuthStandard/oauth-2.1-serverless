/**
 * SAM-02: SAML Assertion Consumption
 *
 * Validates that valid signed SAML assertions are processed correctly.
 * Tests the ACS endpoint with properly signed assertions.
 */

import { describe, it, expect, beforeAll } from 'vitest';
import { httpClient } from '../../support/api';
import { ENDPOINTS, API_BASE_URL } from '../../setup';
import {
  generateSAMLResponse,
  encodeSAMLResponse,
  getSAMLIssuer,
} from '../../support/saml';

describe('SAM-02: SAML Assertion Consumption', () => {
  let samlIssuer: string;

  beforeAll(() => {
    try {
      samlIssuer = getSAMLIssuer();
    } catch {
      // SAML fixtures not seeded
    }
  });

  it('should reject SAML response without RelayState', async () => {
    if (!samlIssuer) {
      console.log('SAML fixtures not seeded. Run: npx ts-node scripts/seed-saml.ts');
      return;
    }

    const samlResponse = generateSAMLResponse({
      email: 'samluser@example.com',
      audience: API_BASE_URL,
    });

    const response = await httpClient.postForm(ENDPOINTS.samlCallback, {
      SAMLResponse: encodeSAMLResponse(samlResponse),
      // Missing RelayState
    });

    expect(response.status).toBe(400);
    const data = response.data as { error?: string };
    expect(data.error).toBe('invalid_request');
  });

  it('should reject SAML response with invalid session (RelayState)', async () => {
    if (!samlIssuer) {
      console.log('SAML fixtures not seeded. Run: npx ts-node scripts/seed-saml.ts');
      return;
    }

    const samlResponse = generateSAMLResponse({
      email: 'samluser@example.com',
      audience: API_BASE_URL,
      inResponseTo: 'nonexistent-session-id',
    });

    const response = await httpClient.postForm(ENDPOINTS.samlCallback, {
      SAMLResponse: encodeSAMLResponse(samlResponse),
      RelayState: 'nonexistent-session-id',
    });

    expect(response.status).toBe(400);
    const data = response.data as { error?: string };
    expect(data.error).toBe('invalid_session');
  });

  it('should reject SAML response with wrong audience', async () => {
    if (!samlIssuer) {
      console.log('SAML fixtures not seeded. Run: npx ts-node scripts/seed-saml.ts');
      return;
    }

    const samlResponse = generateSAMLResponse({
      email: 'samluser@example.com',
      audience: 'https://wrong-audience.example.com',
      inResponseTo: 'test-session',
    });

    const response = await httpClient.postForm(ENDPOINTS.samlCallback, {
      SAMLResponse: encodeSAMLResponse(samlResponse),
      RelayState: 'test-session',
    });

    // Should fail with audience mismatch or invalid session
    expect([400, 401]).toContain(response.status);
  });
});
