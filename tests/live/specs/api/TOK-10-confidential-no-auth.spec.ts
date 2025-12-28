/**
 * TOK-10: Confidential Client Without Authentication
 *
 * Validates that confidential clients must authenticate at the
 * token endpoint. Requests without credentials should fail.
 *
 * Per RFC 6749 Section 2.3, confidential clients MUST authenticate
 * with the authorization server.
 */

import { describe, it, expect } from 'vitest';
import { httpClient, assertOAuth2Error } from '../../support/api';
import { ENDPOINTS } from '../../setup';
import { TEST_CLIENTS } from '../../fixtures';

describe('TOK-10: Confidential Client Without Authentication', () => {
  it('should reject request when no credentials provided', async () => {
    const response = await httpClient.postForm(ENDPOINTS.token, {
      grant_type: 'client_credentials',
      client_id: TEST_CLIENTS.confidential.client_id,
    });

    // Server may return 400 (invalid_request) or 401 (invalid_client)
    // Both indicate authentication is required
    expect([400, 401]).toContain(response.status);
  });

  it('should return error for unauthenticated client_credentials request', async () => {
    const response = await httpClient.postForm(ENDPOINTS.token, {
      grant_type: 'client_credentials',
      client_id: TEST_CLIENTS.adminCli.client_id,
    });

    // Server requires authentication for client_credentials
    expect([400, 401]).toContain(response.status);
  });
});
