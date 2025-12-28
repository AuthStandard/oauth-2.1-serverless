/**
 * INF-01: OIDC Discovery Integrity
 *
 * Validates that the OpenID Connect Discovery document is correctly served
 * and the issuer claim matches the API domain exactly.
 *
 * This prevents Issuer Mismatch attacks where a malicious server could
 * impersonate the IdP by serving a discovery document with a different issuer.
 *
 * @see OpenID Connect Discovery 1.0 Section 3
 * @see RFC 8414 - OAuth 2.0 Authorization Server Metadata
 */

import { describe, it, expect } from 'vitest';
import { httpClient, type OIDCDiscoveryDocument } from '../../support/api';
import { API_BASE_URL, ENDPOINTS } from '../../setup';

describe('INF-01: OIDC Discovery Integrity', () => {
  it('should return 200 OK with valid JSON discovery document', async () => {
    const response = await httpClient.get<OIDCDiscoveryDocument>(ENDPOINTS.discovery);

    expect(response.status).toBe(200);
    expect(response.headers.get('content-type')).toContain('application/json');
  });

  it('should have issuer matching the API domain exactly (no trailing slash)', async () => {
    const response = await httpClient.get<OIDCDiscoveryDocument>(ENDPOINTS.discovery);

    const discovery = response.data;

    // Issuer must be present
    expect(discovery.issuer).toBeDefined();

    // Issuer must match API base URL exactly
    // Remove trailing slash from both for comparison
    const normalizedIssuer = discovery.issuer.replace(/\/$/, '');
    const normalizedBaseUrl = API_BASE_URL.replace(/\/$/, '');

    expect(normalizedIssuer).toBe(normalizedBaseUrl);

    // Verify no trailing slash mismatch (common misconfiguration)
    // The issuer should not have a trailing slash if the base URL doesn't
    if (!API_BASE_URL.endsWith('/')) {
      expect(discovery.issuer.endsWith('/')).toBe(false);
    }
  });

  it('should contain all required OIDC discovery fields', async () => {
    const response = await httpClient.get<OIDCDiscoveryDocument>(ENDPOINTS.discovery);

    const discovery = response.data;

    // Required fields per OpenID Connect Discovery 1.0
    expect(discovery.issuer).toBeDefined();
    expect(discovery.authorization_endpoint).toBeDefined();
    expect(discovery.token_endpoint).toBeDefined();
    expect(discovery.jwks_uri).toBeDefined();
    expect(discovery.response_types_supported).toBeDefined();
    expect(Array.isArray(discovery.response_types_supported)).toBe(true);
    expect(discovery.subject_types_supported).toBeDefined();
    expect(discovery.id_token_signing_alg_values_supported).toBeDefined();
  });

  it('should have endpoints using the same base URL as issuer', async () => {
    const response = await httpClient.get<OIDCDiscoveryDocument>(ENDPOINTS.discovery);

    const discovery = response.data;
    const issuerBase = new URL(discovery.issuer).origin;

    // All endpoints should be under the same origin as the issuer
    expect(new URL(discovery.authorization_endpoint).origin).toBe(issuerBase);
    expect(new URL(discovery.token_endpoint).origin).toBe(issuerBase);
    expect(new URL(discovery.jwks_uri).origin).toBe(issuerBase);

    if (discovery.userinfo_endpoint) {
      expect(new URL(discovery.userinfo_endpoint).origin).toBe(issuerBase);
    }
    if (discovery.registration_endpoint) {
      expect(new URL(discovery.registration_endpoint).origin).toBe(issuerBase);
    }
    if (discovery.revocation_endpoint) {
      expect(new URL(discovery.revocation_endpoint).origin).toBe(issuerBase);
    }
    if (discovery.introspection_endpoint) {
      expect(new URL(discovery.introspection_endpoint).origin).toBe(issuerBase);
    }
  });
});
