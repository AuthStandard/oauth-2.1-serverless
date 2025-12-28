/**
 * INF-04: HTTP Method Check
 *
 * Validates that the discovery endpoint rejects non-GET methods.
 *
 * Note: API Gateway returns 404 for unconfigured method+path combinations
 * rather than 405. This is expected AWS behavior when routes are only
 * defined for specific methods.
 *
 * @see RFC 7231 Section 6.5.5 - 405 Method Not Allowed
 */

import { describe, it, expect } from 'vitest';
import { httpClient } from '../../support/api';
import { ENDPOINTS } from '../../setup';

describe('INF-04: HTTP Method Check', () => {
  it('should reject POST to discovery endpoint', async () => {
    const response = await httpClient.postJson(ENDPOINTS.discovery, {});

    // API Gateway returns 404 for unconfigured routes, 403 for unauthorized,
    // or 405 if explicitly configured. All indicate the method is not allowed.
    expect([403, 404, 405]).toContain(response.status);
  });

  it('should reject PUT to discovery endpoint', async () => {
    const response = await httpClient.put(ENDPOINTS.discovery, {});

    expect([403, 404, 405]).toContain(response.status);
  });

  it('should reject DELETE to discovery endpoint', async () => {
    const response = await httpClient.delete(ENDPOINTS.discovery);

    expect([403, 404, 405]).toContain(response.status);
  });

  it('should still allow GET requests to discovery endpoint', async () => {
    const response = await httpClient.get(ENDPOINTS.discovery);

    expect(response.status).toBe(200);
  });
});
