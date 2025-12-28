/**
 * USR-04: Deactivate User
 *
 * Validates that setting active=false revokes all user tokens.
 *
 * SKIPPED: Requires SCIM endpoint and user with active tokens.
 */

import { describe, it } from 'vitest';

describe('USR-04: Deactivate User', () => {
  it.skip('should revoke tokens when user is deactivated', async () => {
    /**
     * SKIPPED: This test requires:
     * 1. SCIM endpoint URL
     * 2. User with active refresh tokens
     * 3. PATCH request to set active=false
     * 4. Verification that tokens are revoked
     *
     * Revisit: When SCIM endpoint is documented.
     */
  });
});
