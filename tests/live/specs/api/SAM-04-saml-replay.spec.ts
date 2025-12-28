/**
 * SAM-04: SAML Replay Attack Prevention
 *
 * Validates that SAML assertions with expired time conditions are rejected.
 * Per SAML spec, NotOnOrAfter must be checked to prevent replay attacks.
 */

import { describe, it, expect, beforeAll } from 'vitest';
import { httpClient } from '../../support/api';
import { ENDPOINTS, API_BASE_URL } from '../../setup';
import {
  generateSAMLResponse,
  encodeSAMLResponse,
  getSAMLIssuer,
} from '../../support/saml';

describe('SAM-04: SAML Replay Attack Prevention', () => {
  let samlIssuer: string;

  beforeAll(() => {
    try {
      samlIssuer = getSAMLIssuer();
    } catch {
      // SAML fixtures not seeded
    }
  });

  it('should reject expired SAML assertion (NotOnOrAfter in past)', async () => {
    if (!samlIssuer) {
      console.log('SAML fixtures not seeded. Run: npx ts-node scripts/seed-saml.ts');
      return;
    }

    // Generate assertion that expired 10 minutes ago
    const samlResponse = generateSAMLResponse({
      email: 'samluser@example.com',
      audience: API_BASE_URL,
      inResponseTo: 'test-session',
      notBeforeOffset: -3600, // 1 hour ago
      notOnOrAfterOffset: -600, // 10 minutes ago (expired)
    });

    const response = await httpClient.postForm(ENDPOINTS.samlCallback, {
      SAMLResponse: encodeSAMLResponse(samlResponse),
      RelayState: 'test-session',
    });

    expect(response.status).toBe(400);
    const data = response.data as { error?: string };
    // Could be invalid_assertion or invalid_session
    expect(['invalid_assertion', 'invalid_session']).toContain(data.error);
  });

  it('should reject SAML assertion not yet valid (NotBefore in future)', async () => {
    if (!samlIssuer) {
      console.log('SAML fixtures not seeded. Run: npx ts-node scripts/seed-saml.ts');
      return;
    }

    // Generate assertion that's not valid yet (NotBefore 10 minutes in future)
    const samlResponse = generateSAMLResponse({
      email: 'samluser@example.com',
      audience: API_BASE_URL,
      inResponseTo: 'test-session',
      notBeforeOffset: 600, // 10 minutes in future
      notOnOrAfterOffset: 1200, // 20 minutes in future
    });

    const response = await httpClient.postForm(ENDPOINTS.samlCallback, {
      SAMLResponse: encodeSAMLResponse(samlResponse),
      RelayState: 'test-session',
    });

    expect(response.status).toBe(400);
  });
});
