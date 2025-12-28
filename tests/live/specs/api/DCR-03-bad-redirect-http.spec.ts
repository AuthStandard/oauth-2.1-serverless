/**
 * DCR-03: Bad Redirect URI (HTTP)
 *
 * Validates that registration with an HTTP (non-HTTPS) redirect URI
 * is rejected. HTTPS is required for security per OAuth 2.1.
 */

import { describe, it, expect } from 'vitest';
import { httpClient, assertOAuth2Error } from '../../support/api';
import { createValidDCRPayload } from '../../fixtures';
import { ENDPOINTS } from '../../setup';

describe('DCR-03: Bad Redirect URI (HTTP)', () => {
  it('should reject registration with HTTP redirect URI', async () => {
    // Arrange - Use HTTP instead of HTTPS
    const payload = createValidDCRPayload({
      redirect_uris: ['http://app.com/callback'],
    });

    // Act
    const response = await httpClient.postJson(ENDPOINTS.register, payload);

    // Assert - Should be rejected with 400
    expect(response.status).toBe(400);
    assertOAuth2Error(response, 'invalid_redirect_uri');
  });

  it('should reject registration with mixed HTTP and HTTPS URIs', async () => {
    // Arrange
    const payload = createValidDCRPayload({
      redirect_uris: ['https://app.com/callback', 'http://app.com/other'],
    });

    // Act
    const response = await httpClient.postJson(ENDPOINTS.register, payload);

    // Assert
    expect(response.status).toBe(400);
    assertOAuth2Error(response, 'invalid_redirect_uri');
  });
});
