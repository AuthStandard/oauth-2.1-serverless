/**
 * TOK-19: DPoP Invalid Proof
 *
 * Validates that DPoP proofs with invalid signatures are rejected.
 * Per RFC 9449, the server must validate the DPoP proof signature.
 */

import { describe, it, expect } from 'vitest';
import { httpClient, buildBasicAuth } from '../../support/api';
import { ENDPOINTS } from '../../setup';
import { TEST_CLIENTS } from '../../fixtures';

describe('TOK-19: DPoP Invalid Proof', () => {
  it('should reject DPoP proof with invalid signature', async () => {
    // Create a malformed DPoP proof (invalid JWT structure)
    const invalidDPoPProof = 'eyJhbGciOiJFUzI1NiIsInR5cCI6ImRwb3Arand0IiwiandrIjp7Imt0eSI6IkVDIiwiY3J2IjoiUC0yNTYiLCJ4IjoiMTIzIiwieSI6IjQ1NiJ9fQ.eyJqdGkiOiJ0ZXN0LWp0aSIsImh0bSI6IlBPU1QiLCJodHUiOiJodHRwczovL2V4YW1wbGUuY29tL3Rva2VuIiwiaWF0IjoxNjAwMDAwMDAwfQ.invalid-signature';

    const response = await httpClient.postForm(ENDPOINTS.token, {
      grant_type: 'client_credentials',
    }, {
      headers: {
        Authorization: buildBasicAuth(
          TEST_CLIENTS.adminCli.client_id,
          TEST_CLIENTS.adminCli.client_secret
        ),
        DPoP: invalidDPoPProof,
      },
    });

    // Should reject with 400 or 401
    expect([400, 401]).toContain(response.status);

    // Should return invalid_dpop_proof error
    const data = response.data as { error?: string };
    expect(data.error).toBe('invalid_dpop_proof');
  });

  it('should reject DPoP proof with wrong typ header', async () => {
    // DPoP proof with wrong typ (should be "dpop+jwt")
    // Header: {"alg":"ES256","typ":"JWT"} (wrong typ)
    const wrongTypProof = 'eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJqdGkiOiJ0ZXN0LWp0aSIsImh0bSI6IlBPU1QiLCJodHUiOiJodHRwczovL2V4YW1wbGUuY29tL3Rva2VuIiwiaWF0IjoxNjAwMDAwMDAwfQ.invalid';

    const response = await httpClient.postForm(ENDPOINTS.token, {
      grant_type: 'client_credentials',
    }, {
      headers: {
        Authorization: buildBasicAuth(
          TEST_CLIENTS.adminCli.client_id,
          TEST_CLIENTS.adminCli.client_secret
        ),
        DPoP: wrongTypProof,
      },
    });

    expect([400, 401]).toContain(response.status);
  });

  it('should reject completely malformed DPoP header', async () => {
    const response = await httpClient.postForm(ENDPOINTS.token, {
      grant_type: 'client_credentials',
    }, {
      headers: {
        Authorization: buildBasicAuth(
          TEST_CLIENTS.adminCli.client_id,
          TEST_CLIENTS.adminCli.client_secret
        ),
        DPoP: 'not-a-valid-jwt-at-all',
      },
    });

    expect([400, 401]).toContain(response.status);
  });
});
