/**
 * TOK-11: Confidential Client Bad Authentication
 *
 * Validates that confidential clients with incorrect credentials
 * are rejected with invalid_client error.
 */

import { describe, it, expect } from 'vitest';
import { httpClient, assertOAuth2Error, buildBasicAuth } from '../../support/api';
import { ENDPOINTS } from '../../setup';
import { TEST_CLIENTS } from '../../fixtures';

describe('TOK-11: Confidential Client Bad Authentication', () => {
  it('should return invalid_client for wrong secret', async () => {
    const response = await httpClient.postForm(ENDPOINTS.token, {
      grant_type: 'client_credentials',
    }, {
      headers: {
        Authorization: buildBasicAuth(
          TEST_CLIENTS.adminCli.client_id,
          'wrong-secret-12345'
        ),
      },
    });

    assertOAuth2Error(response, 'invalid_client', { expectedStatus: 401 });
  });

  it('should reject malformed Basic auth', async () => {
    const response = await httpClient.postForm(ENDPOINTS.token, {
      grant_type: 'client_credentials',
    }, {
      headers: {
        Authorization: 'Basic not-valid-base64!!!',
      },
    });

    // Server may return 400 or 401 for malformed auth
    expect([400, 401]).toContain(response.status);
  });

  it('should reject empty secret', async () => {
    const response = await httpClient.postForm(ENDPOINTS.token, {
      grant_type: 'client_credentials',
    }, {
      headers: {
        Authorization: buildBasicAuth(TEST_CLIENTS.adminCli.client_id, ''),
      },
    });

    // Server may return 400 (invalid_request) or 401 (invalid_client)
    expect([400, 401]).toContain(response.status);
  });
});
