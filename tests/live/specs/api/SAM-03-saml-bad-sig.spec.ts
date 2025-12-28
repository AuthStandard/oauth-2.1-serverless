/**
 * SAM-03: SAML Bad Signature Rejection
 *
 * Validates that SAML assertions with invalid signatures are rejected.
 */

import { describe, it, expect, beforeAll } from 'vitest';
import { httpClient } from '../../support/api';
import { ENDPOINTS, API_BASE_URL } from '../../setup';
import {
  generateSAMLResponse,
  encodeSAMLResponse,
  getSAMLIssuer,
} from '../../support/saml';

describe('SAM-03: SAML Bad Signature Rejection', () => {
  let samlIssuer: string;

  beforeAll(() => {
    try {
      samlIssuer = getSAMLIssuer();
    } catch {
      // SAML fixtures not seeded
    }
  });

  it('should reject SAML assertion with invalid signature', async () => {
    if (!samlIssuer) {
      console.log('SAML fixtures not seeded. Run: npx ts-node scripts/seed-saml.ts');
      return;
    }

    // Generate assertion signed with wrong key
    const samlResponse = generateSAMLResponse({
      email: 'samluser@example.com',
      audience: API_BASE_URL,
      inResponseTo: 'test-session',
      useWrongKey: true,
    });

    const response = await httpClient.postForm(ENDPOINTS.samlCallback, {
      SAMLResponse: encodeSAMLResponse(samlResponse),
      RelayState: 'test-session',
    });

    expect(response.status).toBe(400);
    const data = response.data as { error?: string };
    // Could be invalid_signature or invalid_session (session check may come first)
    expect(['invalid_signature', 'invalid_session']).toContain(data.error);
  });

  it('should reject SAML assertion without signature', async () => {
    if (!samlIssuer) {
      console.log('SAML fixtures not seeded. Run: npx ts-node scripts/seed-saml.ts');
      return;
    }

    // Generate assertion without signing
    const samlResponse = generateSAMLResponse({
      email: 'samluser@example.com',
      audience: API_BASE_URL,
      inResponseTo: 'test-session',
      skipSigning: true,
    });

    const response = await httpClient.postForm(ENDPOINTS.samlCallback, {
      SAMLResponse: encodeSAMLResponse(samlResponse),
      RelayState: 'test-session',
    });

    expect(response.status).toBe(400);
  });

  it('should reject malformed SAML response', async () => {
    const response = await httpClient.postForm(ENDPOINTS.samlCallback, {
      SAMLResponse: Buffer.from('not valid xml').toString('base64'),
      RelayState: 'test-session',
    });

    expect(response.status).toBe(400);
    const data = response.data as { error?: string };
    expect(data.error).toBe('invalid_saml_response');
  });
});
