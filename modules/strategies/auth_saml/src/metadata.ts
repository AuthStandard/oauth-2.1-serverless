/**
 * SAML Strategy - Service Provider Metadata Endpoint
 *
 * Lambda handler for GET /auth/saml/metadata
 * Generates SAML 2.0 SP metadata XML for IdP configuration.
 *
 * This metadata file is uploaded to Okta, Azure AD, Google Workspace, etc.
 * to configure the Service Provider integration.
 *
 * @see https://docs.oasis-open.org/security/saml/v2.0/saml-metadata-2.0-os.pdf
 */

import type { APIGatewayProxyEventV2, APIGatewayProxyResultV2, Context } from 'aws-lambda';
import { createLogger } from '@oauth-server/shared';
import { xmlResponse, serverError } from './response';
import type { MetadataEnvConfig } from './types';

// =============================================================================
// Environment Configuration
// =============================================================================

function getEnvConfig(): MetadataEnvConfig {
    const entityId = process.env.ENTITY_ID;
    const acsUrl = process.env.ACS_URL;
    const issuer = process.env.ISSUER;

    if (!entityId) {
        throw new Error('ENTITY_ID environment variable is required');
    }

    if (!acsUrl) {
        throw new Error('ACS_URL environment variable is required');
    }

    if (!issuer) {
        throw new Error('ISSUER environment variable is required');
    }

    return { entityId, acsUrl, issuer };
}

// =============================================================================
// XML Utilities
// =============================================================================

/**
 * Escape special XML characters to prevent injection.
 */
function escapeXml(str: string): string {
    return str
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&apos;');
}

// =============================================================================
// SP Metadata Generation
// =============================================================================

/**
 * Generate SAML 2.0 Service Provider metadata XML.
 */
function generateSpMetadata(config: MetadataEnvConfig): string {
    // Metadata valid for 1 year
    const validUntil = new Date(Date.now() + 365 * 24 * 60 * 60 * 1000).toISOString();

    return `<?xml version="1.0" encoding="UTF-8"?>
<md:EntityDescriptor
    xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata"
    entityID="${escapeXml(config.entityId)}"
    validUntil="${validUntil}">
  
  <md:SPSSODescriptor
      AuthnRequestsSigned="false"
      WantAssertionsSigned="true"
      protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    
    <!-- Supported NameID formats (in order of preference) -->
    <md:NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress</md:NameIDFormat>
    <md:NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:persistent</md:NameIDFormat>
    <md:NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:transient</md:NameIDFormat>
    
    <!-- Assertion Consumer Service (ACS) - HTTP-POST binding only -->
    <md:AssertionConsumerService
        Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
        Location="${escapeXml(config.acsUrl)}"
        index="0"
        isDefault="true"/>
    
  </md:SPSSODescriptor>
  
  <!-- Organization information -->
  <md:Organization>
    <md:OrganizationName xml:lang="en">OAuth Server</md:OrganizationName>
    <md:OrganizationDisplayName xml:lang="en">OAuth Server Identity Provider</md:OrganizationDisplayName>
    <md:OrganizationURL xml:lang="en">${escapeXml(config.issuer)}</md:OrganizationURL>
  </md:Organization>
  
</md:EntityDescriptor>`;
}

// =============================================================================
// Lambda Handler
// =============================================================================

export const handler = async (
    event: APIGatewayProxyEventV2,
    context: Context
): Promise<APIGatewayProxyResultV2> => {
    const log = createLogger(event, context);

    try {
        log.info('SAML SP metadata request');

        const config = getEnvConfig();
        const metadata = generateSpMetadata(config);

        log.info('Returning SP metadata', { entityId: config.entityId });

        return xmlResponse(metadata);
    } catch (err) {
        const error = err as Error;
        log.error('SAML metadata error', { error: error.message, stack: error.stack });
        return serverError('Failed to generate SP metadata');
    }
};
