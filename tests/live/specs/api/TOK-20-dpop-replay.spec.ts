/**
 * TOK-20: DPoP Replay Attack Prevention
 *
 * Validates that DPoP proofs cannot be reused (jti check).
 * Per RFC 9449 Section 11.1, servers must prevent replay attacks
 * by tracking used jti values.
 *
 * This test requires generating valid DPoP proofs, which needs
 * cryptographic key generation and JWT signing.
 */

import { describe, it, expect, beforeAll } from 'vitest';
import { httpClient, buildBasicAuth, type TokenResponse } from '../../support/api';
import { ENDPOINTS, API_BASE_URL } from '../../setup';
import { TEST_CLIENTS } from '../../fixtures';
import * as jose from 'jose';

describe('TOK-20: DPoP Replay Attack Prevention', () => {
  let privateKey: jose.KeyLike;
  let publicJwk: jose.JWK;

  beforeAll(async () => {
    // Generate an EC key pair for DPoP proofs (ES256 per RFC 9449)
    const keyPair = await jose.generateKeyPair('ES256');
    privateKey = keyPair.privateKey;
    publicJwk = await jose.exportJWK(keyPair.publicKey);
  });

  /**
   * Generate a valid DPoP proof JWT.
   */
  async function generateDPoPProof(jti: string): Promise<string> {
    const now = Math.floor(Date.now() / 1000);

    const proof = await new jose.SignJWT({
      jti,
      htm: 'POST',
      htu: `${API_BASE_URL}/token`,
      iat: now,
    })
      .setProtectedHeader({
        alg: 'ES256',
        typ: 'dpop+jwt',
        jwk: publicJwk,
      })
      .sign(privateKey);

    return proof;
  }

  it('should accept first use of DPoP proof', async () => {
    const jti = `test-jti-${Date.now()}-${Math.random().toString(36).slice(2)}`;
    const dpopProof = await generateDPoPProof(jti);

    const response = await httpClient.postForm<TokenResponse>(ENDPOINTS.token, {
      grant_type: 'client_credentials',
    }, {
      headers: {
        Authorization: buildBasicAuth(
          TEST_CLIENTS.adminCli.client_id,
          TEST_CLIENTS.adminCli.client_secret
        ),
        DPoP: dpopProof,
      },
    });

    expect(response.status).toBe(200);

    // Token type should be DPoP since we used DPoP binding
    expect(response.data.token_type).toBe('DPoP');
  });

  it('should reject reused DPoP proof (replay attack)', async () => {
    const jti = `replay-test-${Date.now()}-${Math.random().toString(36).slice(2)}`;
    const dpopProof = await generateDPoPProof(jti);

    // First request should succeed
    const firstResponse = await httpClient.postForm<TokenResponse>(ENDPOINTS.token, {
      grant_type: 'client_credentials',
    }, {
      headers: {
        Authorization: buildBasicAuth(
          TEST_CLIENTS.adminCli.client_id,
          TEST_CLIENTS.adminCli.client_secret
        ),
        DPoP: dpopProof,
      },
    });

    expect(firstResponse.status).toBe(200);

    // Second request with same proof should fail (replay)
    const secondResponse = await httpClient.postForm(ENDPOINTS.token, {
      grant_type: 'client_credentials',
    }, {
      headers: {
        Authorization: buildBasicAuth(
          TEST_CLIENTS.adminCli.client_id,
          TEST_CLIENTS.adminCli.client_secret
        ),
        DPoP: dpopProof,
      },
    });

    expect([400, 401]).toContain(secondResponse.status);

    const data = secondResponse.data as { error?: string; error_description?: string };
    expect(data.error).toBe('invalid_dpop_proof');
    expect(data.error_description).toContain('replay');
  });

  it('should accept different DPoP proofs with unique jti values', async () => {
    // First proof
    const jti1 = `unique-1-${Date.now()}-${Math.random().toString(36).slice(2)}`;
    const proof1 = await generateDPoPProof(jti1);

    const response1 = await httpClient.postForm<TokenResponse>(ENDPOINTS.token, {
      grant_type: 'client_credentials',
    }, {
      headers: {
        Authorization: buildBasicAuth(
          TEST_CLIENTS.adminCli.client_id,
          TEST_CLIENTS.adminCli.client_secret
        ),
        DPoP: proof1,
      },
    });

    expect(response1.status).toBe(200);

    // Second proof with different jti
    const jti2 = `unique-2-${Date.now()}-${Math.random().toString(36).slice(2)}`;
    const proof2 = await generateDPoPProof(jti2);

    const response2 = await httpClient.postForm<TokenResponse>(ENDPOINTS.token, {
      grant_type: 'client_credentials',
    }, {
      headers: {
        Authorization: buildBasicAuth(
          TEST_CLIENTS.adminCli.client_id,
          TEST_CLIENTS.adminCli.client_secret
        ),
        DPoP: proof2,
      },
    });

    expect(response2.status).toBe(200);
  });
});
