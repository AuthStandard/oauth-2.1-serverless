/**
 * MGT-05: Revoke Garbage Token
 *
 * Validates that revoking an invalid/random string returns 200 OK
 * without revealing whether the token ever existed.
 *
 * Per RFC 7009, the revocation endpoint MUST return 200 OK even
 * for invalid tokens to prevent token enumeration attacks.
 */

import { describe, it, expect } from 'vitest';
import { httpClient, buildBasicAuth } from '../../support/api';
import { ENDPOINTS } from '../../setup';
import { TEST_CLIENTS } from '../../fixtures';

describe('MGT-05: Revoke Garbage Token', () => {
  it('should return 200 OK for random string', async () => {
    const response = await httpClient.postForm(
      ENDPOINTS.revoke,
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
  });

  it('should return 200 OK for malformed JWT', async () => {
    const response = await httpClient.postForm(
      ENDPOINTS.revoke,
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
  });

  it('should handle empty token gracefully', async () => {
    const response = await httpClient.postForm(
      ENDPOINTS.revoke,
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

    // Server may return 200 (silent success) or 400 for missing token
    // Both are acceptable behaviors
    expect([200, 400]).toContain(response.status);
  });
});
