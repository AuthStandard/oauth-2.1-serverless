/**
 * OAuth Server - Constants and Configuration
 *
 * Centralized constants for OAuth 2.1 implementation.
 * All magic numbers and strings are defined here for consistency.
 *
 * Design Principles:
 * - Protocol-level constants that don't change between environments
 * - Runtime configuration (TTLs, endpoints) comes from environment variables
 * - All values are immutable (as const) for type safety
 *
 * @see RFC 6749 - OAuth 2.0 Authorization Framework
 * @see RFC 7636 - Proof Key for Code Exchange (PKCE)
 * @see OAuth 2.1 Draft - https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1
 */

// =============================================================================
// OAuth 2.1 Grant Types
// =============================================================================

/**
 * OAuth 2.1 grant types.
 * Note: Implicit grant and Resource Owner Password Credentials (ROPC)
 * are removed in OAuth 2.1 for security reasons.
 *
 * @see OAuth 2.1 Draft Section 1.3 - Authorization Grant
 */
export const GrantTypes = {
    /** Authorization code grant with mandatory PKCE */
    AUTHORIZATION_CODE: 'authorization_code',
    /** Refresh token grant for obtaining new access tokens */
    REFRESH_TOKEN: 'refresh_token',
    /** Client credentials grant for machine-to-machine auth */
    CLIENT_CREDENTIALS: 'client_credentials',
} as const;

export type GrantType = typeof GrantTypes[keyof typeof GrantTypes];

// =============================================================================
// OAuth 2.1 Response Types
// =============================================================================

/**
 * OAuth 2.1 response types.
 * Only 'code' is supported - implicit flow (token) is removed in OAuth 2.1.
 *
 * @see OAuth 2.1 Draft Section 4.1.1 - Authorization Request
 */
export const ResponseTypes = {
    /** Authorization code response (the only valid response type in OAuth 2.1) */
    CODE: 'code',
} as const;

export type ResponseType = typeof ResponseTypes[keyof typeof ResponseTypes];

// =============================================================================
// PKCE Challenge Methods
// =============================================================================

/**
 * PKCE code challenge methods.
 * OAuth 2.1 mandates S256 only - the "plain" method is explicitly forbidden.
 *
 * @see RFC 7636 Section 4.2 - code_challenge_method
 * @see OAuth 2.1 Draft Section 4.1.1 - PKCE is required, S256 is mandatory
 */
export const ChallengeMethods = {
    /** SHA-256 hash of code_verifier, base64url-encoded (mandatory) */
    S256: 'S256',
} as const;

export type ChallengeMethod = typeof ChallengeMethods[keyof typeof ChallengeMethods];

// =============================================================================
// Token Types
// =============================================================================

/**
 * OAuth 2.1 token types.
 *
 * @see RFC 6750 - Bearer Token Usage
 */
export const TokenTypes = {
    /** Bearer token type - the standard for OAuth 2.x */
    BEARER: 'Bearer',
} as const;

export type TokenType = typeof TokenTypes[keyof typeof TokenTypes];

// =============================================================================
// Client Types
// =============================================================================

/**
 * OAuth 2.1 client types.
 *
 * @see OAuth 2.1 Draft Section 2.1 - Client Types
 */
export const ClientTypes = {
    /** Public clients cannot maintain confidentiality of credentials (SPAs, mobile apps) */
    PUBLIC: 'PUBLIC',
    /** Confidential clients can securely authenticate (server-side apps) */
    CONFIDENTIAL: 'CONFIDENTIAL',
} as const;

export type ClientType = typeof ClientTypes[keyof typeof ClientTypes];

// =============================================================================
// User Status
// =============================================================================

/**
 * User account status values.
 */
export const UserStatus = {
    /** User can authenticate and access resources */
    ACTIVE: 'ACTIVE',
    /** User is temporarily blocked from authentication */
    SUSPENDED: 'SUSPENDED',
    /** User must verify email before activation */
    PENDING_VERIFICATION: 'PENDING_VERIFICATION',
} as const;

export type UserStatusType = typeof UserStatus[keyof typeof UserStatus];

// =============================================================================
// DynamoDB Entity Types
// =============================================================================

/**
 * Entity type discriminators for Single Table Design.
 * Used for type guards and GSI queries.
 */
export const EntityTypes = {
    CLIENT: 'CLIENT',
    USER: 'USER',
    AUTH_CODE: 'AUTH_CODE',
    REFRESH_TOKEN: 'REFRESH_TOKEN',
    SAML_PROVIDER: 'SAML_PROVIDER',
    LOGIN_SESSION: 'LOGIN_SESSION',
} as const;

export type EntityType = typeof EntityTypes[keyof typeof EntityTypes];

// =============================================================================
// DynamoDB Key Prefixes
// =============================================================================

/**
 * Partition key prefixes for Single Table Design.
 * Format: PREFIX#<identifier>
 */
export const KeyPrefixes = {
    CLIENT: 'CLIENT#',
    USER: 'USER#',
    CODE: 'CODE#',
    REFRESH: 'REFRESH#',
    SESSION: 'SESSION#',
    SAML: 'SAML#',
    EMAIL: 'EMAIL#',
} as const;

// =============================================================================
// Standard Scopes
// =============================================================================

/**
 * OpenID Connect standard scopes.
 *
 * @see OpenID Connect Core 1.0 Section 5.4 - Requesting Claims using Scope Values
 */
export const StandardScopes = {
    /** Required for OIDC - indicates this is an authentication request */
    OPENID: 'openid',
    /** Request access to default profile claims */
    PROFILE: 'profile',
    /** Request access to email and email_verified claims */
    EMAIL: 'email',
    /** Request a refresh token for offline access */
    OFFLINE_ACCESS: 'offline_access',
} as const;

// =============================================================================
// Default Token Lifetimes (in seconds)
// =============================================================================

/**
 * Default token lifetimes in seconds.
 *
 * These values serve as secure defaults when client-specific configuration
 * is not provided. Production deployments SHOULD override these via
 * terraform.tfvars to match organizational security policies.
 *
 * Security Rationale:
 * - Access tokens (1 hour): Short-lived to minimize exposure window if compromised.
 *   Per OAuth Security BCP, access tokens SHOULD have a lifetime appropriate
 *   to the sensitivity of the resource.
 * - ID tokens (1 hour): Matches access token lifetime for consistency in OIDC flows.
 * - Refresh tokens (30 days): Enables offline access while requiring periodic
 *   re-authentication. Token rotation mitigates long-lived token risks.
 * - Authorization codes (10 minutes): Per OAuth 2.1 Section 4.1.2, codes SHOULD
 *   expire shortly after issuance. 10 minutes allows for network latency.
 * - Login sessions (10 minutes): Matches authorization code lifetime to provide
 *   consistent timeout behavior during the authorization flow.
 *
 * @see OAuth 2.1 Draft Section 4.1.2 - Authorization code expiration
 * @see OAuth 2.1 Draft Section 4.3.3 - Refresh token rotation recommendations
 * @see RFC 9700 Section 4.12 - Access Token Lifetime Recommendations
 */
export const DefaultTokenLifetimes = {
    /** Access token: 1 hour (3600 seconds) - short-lived per OAuth 2.1 best practices */
    ACCESS_TOKEN: 3600,
    /** ID token: 1 hour (3600 seconds) - matches access token lifetime for OIDC */
    ID_TOKEN: 3600,
    /** Refresh token: 30 days (2592000 seconds) - long-lived for offline access */
    REFRESH_TOKEN: 2592000,
    /** Authorization code: 10 minutes (600 seconds) - per OAuth 2.1 recommendation */
    AUTHORIZATION_CODE: 600,
    /** Login session: 10 minutes (600 seconds) - for authorization flow timeout */
    LOGIN_SESSION: 600,
} as const;

// =============================================================================
// PKCE Constants
// =============================================================================

/**
 * PKCE-related constants per RFC 7636.
 *
 * @see RFC 7636 Section 4.1 - code_verifier requirements
 * @see RFC 7636 Section 4.2 - code_challenge requirements
 */
export const PkceConstants = {
    /** Minimum code_verifier length per RFC 7636 Section 4.1 */
    CODE_VERIFIER_MIN_LENGTH: 43,
    /** Maximum code_verifier length per RFC 7636 Section 4.1 */
    CODE_VERIFIER_MAX_LENGTH: 128,
    /** S256 code_challenge length (32 bytes SHA-256 → 43 chars base64url) */
    CODE_CHALLENGE_LENGTH: 43,
} as const;

// =============================================================================
// HTTP Headers
// =============================================================================

/**
 * Standard HTTP headers for OAuth 2.1 responses.
 * Cache-Control: no-store is mandatory for token responses per RFC 6749.
 */
export const HttpHeaders = {
    /** Headers for JSON API responses */
    JSON: {
        'Content-Type': 'application/json',
        'Cache-Control': 'no-store',
        'Pragma': 'no-cache',
    },
    /** Headers for HTML responses (login pages, etc.) */
    HTML: {
        'Content-Type': 'text/html; charset=utf-8',
        'Cache-Control': 'no-store',
        'Pragma': 'no-cache',
        'X-Content-Type-Options': 'nosniff',
        'X-Frame-Options': 'DENY',
    },
    /** Headers for redirect responses */
    REDIRECT: {
        'Cache-Control': 'no-store',
        'Pragma': 'no-cache',
    },
    /** CORS headers for public endpoints (e.g., OIDC discovery) */
    CORS_PUBLIC: {
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Methods': 'GET, OPTIONS',
    },
} as const;

// =============================================================================
// JWT Algorithm
// =============================================================================

/**
 * JWT signing algorithms.
 * RS256 (RSA with SHA-256) is used for asymmetric signing with KMS.
 *
 * @see RFC 7518 - JSON Web Algorithms (JWA)
 */
export const JwtAlgorithm = {
    /** RSA signature with SHA-256 - used with KMS asymmetric keys */
    RS256: 'RS256',
} as const;

// =============================================================================
// Authentication Methods
// =============================================================================

/**
 * Authentication method identifiers.
 * Used in audit logs and session tracking.
 */
export const AuthMethods = {
    /** Username/password authentication */
    PASSWORD: 'password',
    /** SAML 2.0 federated authentication */
    SAML: 'saml',
} as const;

export type AuthMethod = typeof AuthMethods[keyof typeof AuthMethods];
