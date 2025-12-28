/**
 * OAuth Server - SAML Provider Entity Types
 *
 * SAML Identity Provider configuration stored in DynamoDB.
 *
 * Key Pattern:
 *   PK: SAML#<issuer>
 *   SK: CONFIG
 *   GSI1PK: SAML_PROVIDERS
 *   GSI1SK: <issuer>
 *
 * @see SAML 2.0 Core Specification
 * @see SAML 2.0 Bindings Specification
 */

import type { BaseItem } from './base';

// =============================================================================
// SAML Types
// =============================================================================

export type SAMLNameIdFormat =
    | 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress'
    | 'urn:oasis:names:tc:SAML:2.0:nameid-format:persistent'
    | 'urn:oasis:names:tc:SAML:2.0:nameid-format:transient';

export interface SAMLAttributeMapping {
    /** SAML attribute name for email */
    email: string;
    /** SAML attribute name for given/first name */
    givenName?: string;
    /** SAML attribute name for family/last name */
    familyName?: string;
}

// =============================================================================
// SAML Provider Entity
// =============================================================================

export interface SAMLProviderItem extends BaseItem {
    /** PK pattern: SAML#<issuer_entity_id> */
    PK: `SAML#${string}`;
    SK: 'CONFIG';
    entityType: 'SAML_PROVIDER';

    /** SAML Identity Provider Entity ID (issuer) */
    issuer: string;

    /** X.509 Certificate in PEM format for signature validation */
    certPem: string;

    /** SAML SSO endpoint URL */
    ssoUrl: string;

    /** Optional SLO (Single Logout) endpoint URL */
    sloUrl?: string;

    /** SAML NameID format preference */
    nameIdFormat: SAMLNameIdFormat;

    /** Attribute mapping from SAML assertion to user profile */
    attributeMapping: SAMLAttributeMapping;

    /** Whether this provider is enabled */
    enabled: boolean;

    /** Display name for the login button */
    displayName: string;
}

// =============================================================================
// Type Guard Declarations
// =============================================================================

// Note: Type guard implementations are provided in the shared module (type-guards.ts).
// These declarations exist for documentation purposes only.
