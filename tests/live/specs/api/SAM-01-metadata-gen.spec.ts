/**
 * SAM-01: SAML Metadata Generation
 *
 * Validates that the SAML SP metadata endpoint returns valid XML.
 *
 * Note: SAML module may not be deployed in all environments.
 */

import { describe, it, expect } from 'vitest';
import { httpClient } from '../../support/api';
import { ENDPOINTS } from '../../setup';

describe('SAM-01: SAML Metadata Generation', () => {
  it('should return valid SAML metadata XML or 404 if not deployed', async () => {
    const response = await httpClient.get<string>(ENDPOINTS.samlMetadata);

    // SAML module may not be deployed - 404 is acceptable
    if (response.status === 404) {
      console.log('SAML module not deployed in this environment');
      return;
    }

    expect(response.status).toBe(200);

    // Should return XML content type
    const contentType = response.headers.get('content-type');
    expect(contentType).toMatch(/xml/);

    // Should contain SAML metadata elements
    const xml = response.data;
    expect(xml).toContain('EntityDescriptor');
    expect(xml).toContain('SPSSODescriptor');
    expect(xml).toContain('AssertionConsumerService');
  });

  it('should include entity ID in metadata if deployed', async () => {
    const response = await httpClient.get<string>(ENDPOINTS.samlMetadata);

    // SAML module may not be deployed
    if (response.status === 404) {
      return;
    }

    expect(response.status).toBe(200);

    const xml = response.data;
    expect(xml).toContain('entityID=');
  });
});
