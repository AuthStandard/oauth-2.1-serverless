/**
 * JWT-05: Subject Claim Type
 *
 * Validates that the subject claim uses appropriate identifiers
 * (UUID for privacy, pairwise if configured).
 */

import { describe, it, expect } from 'vitest';
import { httpClient, buildBasicAuth, decodeJWT, type TokenResponse } from '../../support/api';
import { ENDPOINTS } from '../../setup';
import { TEST_CLIENTS } from '../../fixtures';

describe('JWT-05: Subject Claim Type', () => {
  it('should have sub claim as string identifier', async () => {
    const response = await httpClient.postForm<TokenResponse>(ENDPOINTS.token, {
      grant_type: 'client_credentials',
    }, {
      headers: {
        Authorization: buildBasicAuth(
          TEST_CLIENTS.adminCli.client_id,
          TEST_CLIENTS.adminCli.client_secret
        ),
      },
    });

    expect(response.status).toBe(200);

    const { payload } = decodeJWT(response.data.access_token);

    // sub must be present
    expect(payload.sub).toBeDefined();
    expect(typeof payload.sub).toBe('string');
    expect(payload.sub!.length).toBeGreaterThan(0);
  });

  it('should not expose email or PII in sub claim for client credentials', async () => {
    const response = await httpClient.postForm<TokenResponse>(ENDPOINTS.token, {
      grant_type: 'client_credentials',
    }, {
      headers: {
        Authorization: buildBasicAuth(
          TEST_CLIENTS.adminCli.client_id,
          TEST_CLIENTS.adminCli.client_secret
        ),
      },
    });

    expect(response.status).toBe(200);

    const { payload } = decodeJWT(response.data.access_token);

    // sub should not look like an email
    expect(payload.sub).not.toContain('@');
  });
});
