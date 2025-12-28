/**
 * AUT-01: Missing Client ID
 *
 * Validates that authorization requests without a client_id parameter
 * return a 400 Bad Request error page instead of redirecting.
 *
 * Per RFC 6749 Section 4.1.2.1, if the request fails due to a missing,
 * invalid, or mismatching redirection URI, or if the client identifier
 * is missing or invalid, the authorization server SHOULD inform the
 * resource owner of the error and MUST NOT automatically redirect.
 */

import { describe, it, expect } from 'vitest';
import { httpClient } from '../../support/api';
import { ENDPOINTS } from '../../setup';

describe('AUT-01: Missing Client ID', () => {
  it('should return 400 Bad Request when client_id is missing', async () => {
    const response = await httpClient.get(`${ENDPOINTS.authorize}?response_type=code`, {
      followRedirects: false,
    });

    // Must NOT redirect - should show error page
    expect(response.status).toBe(400);
  });

  it('should not redirect to any URI when client_id is absent', async () => {
    const response = await httpClient.get(`${ENDPOINTS.authorize}?response_type=code`, {
      followRedirects: false,
    });

    // Location header should not be present for client identification failures
    const location = response.headers.get('location');
    expect(location).toBeNull();
  });
});
