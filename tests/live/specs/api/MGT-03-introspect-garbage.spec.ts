/**
 * MGT-03: Introspect Garbage Token
 *
 * Validates that introspecting an invalid/random string returns
 * active=false without revealing whether the token ever existed.
 *
 * Per RFC 7662, the introspection endpoint MUST return active=false
 * for invalid tokens to prevent token enumeration attacks.
 */

import { describe, it, expect } from 'vitest';
import { httpClient, buildBasicAuth, type IntrospectionResponse } from '../../support/api';
import { ENDPOINTS } from '../../setup';
import { TEST_CLIENTS } from '../../fixtures';

describe('MGT-03: Introspect Garbage Token', () => {
  it('should return active=false for random string', async () => {
    const response = await httpClient.postForm<IntrospectionResponse>(
      ENDPOINTS.introspect,
      { token: 'this-is-not-a-valid-token-12345' },
      {
        headers: {
          Authorization: buildBasicAuth(
            TEST_CLIENTS.adminCli.client_id,
            TEST_CLIENTS.adminCli.client_secret
          ),
        },
      }
    );

    expect(response.status).toBe(200);
    expect(response.data.active).toBe(false);
  });

  it('should return active=false for malformed JWT', async () => {
    const response = await httpClient.postForm<IntrospectionResponse>(
      ENDPOINTS.introspect,
      { token: 'eyJhbGciOiJSUzI1NiJ9.invalid.signature' },
      {
        headers: {
          Authorization: buildBasicAuth(
            TEST_CLIENTS.adminCli.client_id,
            TEST_CLIENTS.adminCli.client_secret
          ),
        },
      }
    );

    expect(response.status).toBe(200);
    expect(response.data.active).toBe(false);
  });

  it('should handle empty token gracefully', async () => {
    const response = await httpClient.postForm<IntrospectionResponse>(
      ENDPOINTS.introspect,
      { token: '' },
      {
        headers: {
          Authorization: buildBasicAuth(
            TEST_CLIENTS.adminCli.client_id,
            TEST_CLIENTS.adminCli.client_secret
          ),
        },
      }
    );

    // Server may return 200 with active=false or 400 for missing token
    // Both are acceptable per RFC 7662
    expect([200, 400]).toContain(response.status);
    if (response.status === 200) {
      expect(response.data.active).toBe(false);
    }
  });
});
