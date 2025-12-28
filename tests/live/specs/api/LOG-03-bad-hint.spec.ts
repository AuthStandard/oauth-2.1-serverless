/**
 * LOG-03: Logout With Bad Hint
 *
 * Validates that logout with an invalid id_token_hint returns
 * a 400 Bad Request error.
 */

import { describe, it, expect } from 'vitest';
import { httpClient } from '../../support/api';
import { ENDPOINTS } from '../../setup';

describe('LOG-03: Logout With Bad Hint', () => {
  it('should return 400 for invalid id_token_hint', async () => {
    const params = new URLSearchParams({
      id_token_hint: 'not-a-valid-jwt',
    });

    const response = await httpClient.get(`${ENDPOINTS.logout}?${params}`, {
      followRedirects: false,
    });

    expect(response.status).toBe(400);
  });

  it('should return 400 for malformed JWT hint', async () => {
    const params = new URLSearchParams({
      id_token_hint: 'eyJhbGciOiJSUzI1NiJ9.invalid.signature',
    });

    const response = await httpClient.get(`${ENDPOINTS.logout}?${params}`, {
      followRedirects: false,
    });

    expect(response.status).toBe(400);
  });
});
