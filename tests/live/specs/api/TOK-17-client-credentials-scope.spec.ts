/**
 * TOK-17: Client Credentials Scope Governance
 *
 * Validates that client_credentials grant respects scope restrictions.
 * Clients should not be able to request scopes they are not authorized for.
 */

import { describe, it, expect } from 'vitest';
import { httpClient, buildBasicAuth, type TokenResponse } from '../../support/api';
import { ENDPOINTS } from '../../setup';
import { TEST_CLIENTS } from '../../fixtures';

describe('TOK-17: Client Credentials Scope Governance', () => {
  it('should reject or downscope unauthorized scope requests', async () => {
    const response = await httpClient.postForm<TokenResponse>(ENDPOINTS.token, {
      grant_type: 'client_credentials',
      scope: 'admin superuser root',
    }, {
      headers: {
        Authorization: buildBasicAuth(
          TEST_CLIENTS.adminCli.client_id,
          TEST_CLIENTS.adminCli.client_secret
        ),
      },
    });

    // Server should either:
    // 1. Return 400 with invalid_scope error
    // 2. Return 200 with downscoped (or empty) scope
    expect([200, 400]).toContain(response.status);

    if (response.status === 200) {
      // If successful, verify scope was downscoped
      const data = response.data;
      if (data.scope) {
        // Should not contain unauthorized scopes
        expect(data.scope).not.toContain('superuser');
        expect(data.scope).not.toContain('root');
      }
    }
  });

  it('should accept valid scope for client', async () => {
    const response = await httpClient.postForm<TokenResponse>(ENDPOINTS.token, {
      grant_type: 'client_credentials',
      scope: 'openid',
    }, {
      headers: {
        Authorization: buildBasicAuth(
          TEST_CLIENTS.adminCli.client_id,
          TEST_CLIENTS.adminCli.client_secret
        ),
      },
    });

    expect(response.status).toBe(200);
  });
});
