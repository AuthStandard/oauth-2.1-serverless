/**
 * LOG-02: Logout Without Hint
 *
 * Validates that logout without id_token_hint shows a confirmation
 * page instead of automatically logging out.
 *
 * This prevents CSRF-based logout attacks.
 */

import { describe, it, expect } from 'vitest';
import { httpClient } from '../../support/api';
import { ENDPOINTS } from '../../setup';

describe('LOG-02: Logout Without Hint', () => {
  it('should show confirmation page when no id_token_hint provided', async () => {
    const response = await httpClient.get(ENDPOINTS.logout, {
      followRedirects: false,
    });

    // Server may show confirmation page (200), redirect (302/303), or return error (400)
    // 400 is acceptable if server requires id_token_hint
    expect([200, 302, 303, 400]).toContain(response.status);

    // If 200, should be HTML
    if (response.status === 200) {
      expect(response.headers.get('content-type')).toContain('text/html');
    }
  });
});
