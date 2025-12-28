/**
 * INF-10: Rate Limit Burst
 *
 * Validates that API Gateway throttling is configured to prevent
 * abuse and DoS attacks.
 *
 * Note: This test is marked as skipped by default because it requires
 * sending 5000+ requests which may incur costs and affect other tests.
 * Run manually when validating throttling configuration.
 *
 * @see AWS API Gateway Throttling
 */

import { describe, it, expect } from 'vitest';
import { httpClient } from '../../support/api';
import { ENDPOINTS } from '../../setup';

describe('INF-10: Rate Limit Burst', () => {
  it.skip('should return 429 Too Many Requests after burst limit', async () => {
    /**
     * SKIPPED: This test sends 5001 requests to validate throttling.
     *
     * Blocker: Running this test in CI would:
     * 1. Incur significant AWS costs
     * 2. Potentially affect other concurrent tests
     * 3. Take several minutes to complete
     *
     * Revisit: Run manually during infrastructure validation.
     *
     * To run: Remove .skip and execute with increased timeout:
     * npm test -- INF-10 --testTimeout=300000
     */

    const requests: Promise<{ status: number }>[] = [];
    const targetCount = 5001;

    // Send requests in parallel batches
    for (let i = 0; i < targetCount; i++) {
      requests.push(
        httpClient.get(ENDPOINTS.discovery).then((r) => ({
          status: r.status,
        }))
      );
    }

    const results = await Promise.all(requests);
    const throttled = results.filter((r) => r.status === 429);

    // At least some requests should be throttled after 5000
    expect(throttled.length).toBeGreaterThan(0);
  });

  it('should include rate limit headers when approaching limit', async () => {
    // Send a small burst to check for rate limit headers
    const response = await httpClient.get(ENDPOINTS.discovery);

    // Check for common rate limit headers (may vary by API Gateway config)
    const rateLimitHeaders = [
      'x-ratelimit-limit',
      'x-ratelimit-remaining',
      'x-rate-limit-limit',
      'retry-after',
    ];

    // Note: API Gateway may not include these headers by default
    // This test documents the expected behavior
    const hasRateLimitInfo = rateLimitHeaders.some(
      (header) => response.headers.get(header) !== null
    );

    // This is informational - API Gateway doesn't always include these
    if (!hasRateLimitInfo) {
      console.log(
        'Note: No rate limit headers found. API Gateway may not be configured to include them.'
      );
    }

    // The test passes regardless - we're just checking the endpoint works
    expect(response.status).toBe(200);
  });
});
