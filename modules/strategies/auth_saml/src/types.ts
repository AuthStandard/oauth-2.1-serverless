/**
 * SAML Strategy - Type Definitions
 *
 * Shared types for SAML authentication handlers.
 */

// =============================================================================
// Environment Configuration
// =============================================================================

export interface CallbackEnvConfig {
    tableName: string;
    callbackUrl: string;
    entityId: string;
}

export interface MetadataEnvConfig {
    entityId: string;
    acsUrl: string;
    issuer: string;
}

// =============================================================================
// DynamoDB Entity Types
// =============================================================================

export interface SAMLProviderItem {
    PK: string;
    SK: 'CONFIG';
    entityType: 'SAML_PROVIDER';
    issuer: string;
    certPem: string;
    ssoUrl: string;
    nameIdFormat: string;
    attributeMapping: {
        email: string;
        givenName?: string;
        familyName?: string;
    };
    enabled: boolean;
    displayName: string;
}

export interface LoginSessionItem {
    PK: string;
    SK: 'METADATA';
    entityType: 'LOGIN_SESSION';
    sessionId: string;
    clientId: string;
    ttl: number;
    authenticatedUserId?: string;
    authenticatedAt?: string;
    authMethod?: string;
}

export interface UserItem {
    PK: string;
    SK: 'PROFILE';
    entityType: 'USER';
    sub: string;
    email: string;
    emailVerified: boolean;
    status: 'ACTIVE' | 'SUSPENDED' | 'PENDING_VERIFICATION';
    profile: {
        givenName?: string;
        familyName?: string;
    };
    zoneinfo: string;
    createdAt: string;
    updatedAt: string;
    GSI1PK: string;
    GSI1SK: string;
    ttl: number;
}

// =============================================================================
// SAML Types
// =============================================================================

export interface SAMLAssertion {
    /** IdP Entity ID */
    issuer: string;
    /** Subject identifier from IdP */
    nameId: string;
    /** Extracted user attributes */
    attributes: Record<string, string>;
    /** Assertion validity start time */
    notBefore?: Date;
    /** Assertion validity end time */
    notOnOrAfter?: Date;
    /** Audience restriction (should match our SP Entity ID) */
    audience?: string;
    /** InResponseTo for replay protection */
    inResponseTo?: string;
}

export interface AttributeMapping {
    email: string;
    givenName?: string;
    familyName?: string;
}
