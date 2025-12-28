/**
 * TOK-18: DPoP Header Missing
 *
 * Per RFC 9449, DPoP is optional unless the client is configured to require it.
 * Since our test clients don't have dpopRequired, requests without DPoP should succeed.
 *
 * This test validates that the server accepts requests without DPoP headers
 * for clients that don't require DPoP binding.
 */

import { describe, it, expect } from 'vitest';
import { httpClient, buildBasicAuth, assertTokenResponse } from '../../support/api';
import { ENDPOINTS } from '../../setup';
import { TEST_CLIENTS } from '../../fixtures';

describe('TOK-18: DPoP Header Missing', () => {
  it('should accept request without DPoP header for non-DPoP client', async () => {
    // Standard client_credentials request without DPoP
    const response = await httpClient.postForm(ENDPOINTS.token, {
      grant_type: 'client_credentials',
    }, {
      headers: {
        Authorization: buildBasicAuth(
          TEST_CLIENTS.adminCli.client_id,
          TEST_CLIENTS.adminCli.client_secret
        ),
      },
    });

    // Should succeed - DPoP is optional for this client
    const tokenResponse = assertTokenResponse(response);

    // Token type should be Bearer (not DPoP) since no DPoP was used
    expect(tokenResponse.token_type.toLowerCase()).toBe('bearer');
  });

  it.skip('should reject request without DPoP header for DPoP-required client', async () => {
    /**
     * SKIPPED: Requires a client configured with dpopRequired: true
     *
     * To enable this test:
     * 1. Add a client with dpopRequired: true to seed.json
     * 2. Update fixtures to include the DPoP-required client
     */
  });
});
