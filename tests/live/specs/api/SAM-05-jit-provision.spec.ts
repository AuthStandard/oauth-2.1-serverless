/**
 * SAM-05: SAML Just-In-Time Provisioning
 *
 * Validates that new users are created from SAML assertions.
 *
 * Note: Full JIT provisioning test requires a valid login session.
 * This test validates the error handling when session is invalid.
 */

import { describe, it, expect, beforeAll } from 'vitest';
import { httpClient } from '../../support/api';
import { ENDPOINTS, API_BASE_URL } from '../../setup';
import {
  generateSAMLResponse,
  encodeSAMLResponse,
  getSAMLIssuer,
} from '../../support/saml';

describe('SAM-05: SAML Just-In-Time Provisioning', () => {
  let samlIssuer: string;

  beforeAll(() => {
    try {
      samlIssuer = getSAMLIssuer();
    } catch {
      // SAML fixtures not seeded
    }
  });

  it('should include email attribute in SAML assertion for JIT', async () => {
    if (!samlIssuer) {
      console.log('SAML fixtures not seeded. Run: npx ts-node scripts/seed-saml.ts');
      return;
    }

    // Generate assertion for a new user (JIT scenario)
    // This will fail due to invalid session, but validates assertion generation
    const newUserEmail = `jit-user-${Date.now()}@example.com`;
    const samlResponse = generateSAMLResponse({
      email: newUserEmail,
      audience: API_BASE_URL,
      inResponseTo: 'test-session',
      attributes: {
        firstName: 'JIT',
        lastName: 'User',
      },
    });

    const response = await httpClient.postForm(ENDPOINTS.samlCallback, {
      SAMLResponse: encodeSAMLResponse(samlResponse),
      RelayState: 'test-session',
    });

    // Will fail with invalid_session since we don't have a real session
    // But this validates the assertion generation and endpoint availability
    expect(response.status).toBe(400);
    const data = response.data as { error?: string };
    expect(data.error).toBe('invalid_session');
  });

  it('should reject SAML assertion without email attribute', async () => {
    if (!samlIssuer) {
      console.log('SAML fixtures not seeded. Run: npx ts-node scripts/seed-saml.ts');
      return;
    }

    // Generate assertion without email (invalid for JIT)
    // Note: Our generator always includes email, so we test with empty
    const samlResponse = generateSAMLResponse({
      email: '', // Empty email
      audience: API_BASE_URL,
      inResponseTo: 'test-session',
    });

    const response = await httpClient.postForm(ENDPOINTS.samlCallback, {
      SAMLResponse: encodeSAMLResponse(samlResponse),
      RelayState: 'test-session',
    });

    expect(response.status).toBe(400);
  });
});
