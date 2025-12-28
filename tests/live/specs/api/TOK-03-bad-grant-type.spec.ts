/**
 * TOK-03: Bad Grant Type
 *
 * Validates that unsupported grant types (like password grant)
 * return unsupported_grant_type error.
 *
 * OAuth 2.1 removes the password grant entirely due to security concerns.
 */

import { describe, it, expect } from 'vitest';
import { httpClient, assertOAuth2Error, buildBasicAuth } from '../../support/api';
import { ENDPOINTS } from '../../setup';
import { TEST_CLIENTS } from '../../fixtures';

describe('TOK-03: Bad Grant Type', () => {
  it('should reject password grant type', async () => {
    const response = await httpClient.postForm(ENDPOINTS.token, {
      grant_type: 'password',
      username: 'user@example.com',
      password: 'password123',
    }, {
      headers: {
        Authorization: buildBasicAuth(
          TEST_CLIENTS.confidential.client_id,
          TEST_CLIENTS.confidential.client_secret
        ),
      },
    });

    assertOAuth2Error(response, 'unsupported_grant_type');
  });

  it('should reject unknown grant type', async () => {
    const response = await httpClient.postForm(ENDPOINTS.token, {
      grant_type: 'custom_grant',
    }, {
      headers: {
        Authorization: buildBasicAuth(
          TEST_CLIENTS.confidential.client_id,
          TEST_CLIENTS.confidential.client_secret
        ),
      },
    });

    assertOAuth2Error(response, 'unsupported_grant_type');
  });

  it('should reject implicit grant type at token endpoint', async () => {
    const response = await httpClient.postForm(ENDPOINTS.token, {
      grant_type: 'implicit',
    }, {
      headers: {
        Authorization: buildBasicAuth(
          TEST_CLIENTS.confidential.client_id,
          TEST_CLIENTS.confidential.client_secret
        ),
      },
    });

    assertOAuth2Error(response, 'unsupported_grant_type');
  });
});
