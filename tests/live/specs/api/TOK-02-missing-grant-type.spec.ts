/**
 * TOK-02: Missing Grant Type
 *
 * Validates that token requests without a grant_type parameter
 * return a 400 Bad Request with invalid_request error.
 *
 * Per RFC 6749 Section 4.1.3, the grant_type parameter is REQUIRED.
 */

import { describe, it, expect } from 'vitest';
import { httpClient, assertOAuth2Error, buildBasicAuth } from '../../support/api';
import { ENDPOINTS } from '../../setup';
import { TEST_CLIENTS } from '../../fixtures';

describe('TOK-02: Missing Grant Type', () => {
  it('should return invalid_request when grant_type is missing', async () => {
    const response = await httpClient.postForm(ENDPOINTS.token, {
      code: 'some-code',
      redirect_uri: TEST_CLIENTS.confidential.redirect_uri,
    }, {
      headers: {
        Authorization: buildBasicAuth(
          TEST_CLIENTS.confidential.client_id,
          TEST_CLIENTS.confidential.client_secret
        ),
      },
    });

    assertOAuth2Error(response, 'invalid_request');
  });

  it('should return invalid_request with empty grant_type', async () => {
    const response = await httpClient.postForm(ENDPOINTS.token, {
      grant_type: '',
      code: 'some-code',
    }, {
      headers: {
        Authorization: buildBasicAuth(
          TEST_CLIENTS.confidential.client_id,
          TEST_CLIENTS.confidential.client_secret
        ),
      },
    });

    assertOAuth2Error(response, 'invalid_request');
  });
});
