/**
 * LOG-05: Malicious Post Logout URI
 *
 * Validates that unregistered post_logout_redirect_uri values
 * are rejected to prevent open redirect attacks.
 *
 * SKIPPED: Requires valid id_token for proper testing.
 */

import { describe, it, expect } from 'vitest';
import { httpClient } from '../../support/api';
import { ENDPOINTS } from '../../setup';

describe('LOG-05: Malicious Post Logout URI', () => {
  it('should not redirect to unregistered URI', async () => {
    const params = new URLSearchParams({
      post_logout_redirect_uri: 'https://evil.com/steal-session',
    });

    const response = await httpClient.get(`${ENDPOINTS.logout}?${params}`, {
      followRedirects: false,
    });

    // Should either show confirmation page or error, not redirect to evil.com
    if (response.status >= 300 && response.status < 400) {
      const location = response.headers.get('location');
      expect(location).not.toContain('evil.com');
    }
  });
});
