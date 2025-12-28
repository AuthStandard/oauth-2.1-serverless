/**
 * OAuth 2.1 Token Endpoint - Type Definitions
 *
 * Centralized type definitions for the token endpoint module.
 * Entity types are re-exported from shared_types for Single Source of Truth.
 *
 * Design Principles:
 * - All entity types come from shared_types (DRY)
 * - Runtime config comes from environment variables (no hardcoding)
 * - Request/response types match OAuth 2.1 specification exactly
 *
 * @module oauth2_token/types
 * @see https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1-14
 */

// =============================================================================
// Entity Types (Re-exported from Shared Schema)
// =============================================================================

export type {
    AuthCodeItem,
    ClientItem,
    RefreshTokenItem,
    LoginSessionItem,
    UserItem,
} from '../../../shared_types/schema';

// =============================================================================
// Environment Configuration
// =============================================================================

/**
 * Runtime configuration injected via Lambda environment variables.
 * All values originate from Terraform variables - no hardcoded defaults.
 *
 * Environment Variable Mapping:
 * - TABLE_NAME → tableName
 * - ISSUER → issuer
 * - KEY_ID → keyId
 * - ACCESS_TOKEN_TTL → accessTokenTtl
 * - ID_TOKEN_TTL → idTokenTtl
 * - REFRESH_TOKEN_TTL → refreshTokenTtl
 * - ALLOWED_ORIGINS → allowedOrigins (comma-separated)
 *
 * @see modules/protocols/oauth2_token/variables.tf
 * @see modules/protocols/oauth2_token/main.tf (Lambda environment block)
 */
export interface EnvConfig {
    /** DynamoDB table name for all OAuth entities */
    readonly tableName: string;

    /** OAuth 2.1 issuer URL (iss claim in tokens). MUST be HTTPS. */
    readonly issuer: string;

    /** JWT Key ID (kid claim in JWT header). Must match JWKS endpoint. */
    readonly keyId: string;

    /** Access token lifetime in seconds (default: 3600) */
    readonly accessTokenTtl: number;

    /** ID token lifetime in seconds (default: 3600) */
    readonly idTokenTtl: number;

    /** Refresh token lifetime in seconds (default: 2592000 = 30 days) */
    readonly refreshTokenTtl: number;

    /**
     * Allowed CORS origins for browser-based clients.
     * Supports exact matches and wildcard patterns (e.g., https://*.example.com).
     * Empty array allows all origins (for development only).
     */
    readonly allowedOrigins: string[];
}

// =============================================================================
// Token Request Parameters
// =============================================================================

/**
 * Parsed parameters from POST /token request body.
 *
 * Per OAuth 2.1 Section 3.2.2:
 * - All parameters are form-urlencoded (application/x-www-form-urlencoded)
 * - grant_type is always required
 * - Other parameters depend on the grant type
 *
 * Grant Type Requirements:
 * - authorization_code: code, redirect_uri, code_verifier required
 * - refresh_token: refresh_token required
 * - client_credentials: scope optional
 */
export interface TokenRequestParams {
    /** OAuth 2.1 grant type (authorization_code, refresh_token, client_credentials) */
    readonly grantType: string;

    /** Authorization code (authorization_code grant only) */
    readonly code?: string;

    /** Redirect URI for validation (authorization_code grant only) */
    readonly redirectUri?: string;

    /** PKCE code verifier (authorization_code grant, mandatory per OAuth 2.1) */
    readonly codeVerifier?: string;

    /** Client identifier (required for public clients, optional for confidential with Basic auth) */
    readonly clientId?: string;

    /** Client secret (confidential clients using client_secret_post) */
    readonly clientSecret?: string;

    /** Refresh token (refresh_token grant only) */
    readonly refreshToken?: string;

    /** Requested scope (optional, for scope downscoping or client_credentials) */
    readonly scope?: string;
}

// =============================================================================
// Token Response Types
// =============================================================================

/**
 * OAuth 2.1 Token Response per Section 3.2.3.
 *
 * Required fields:
 * - access_token: The access token string
 * - token_type: "Bearer" or "DPoP" (RFC 9449)
 * - expires_in: Token lifetime in seconds
 *
 * Conditional fields:
 * - scope: REQUIRED if different from requested scope
 * - refresh_token: If offline_access scope granted
 * - id_token: If openid scope granted (OIDC)
 */
export interface TokenResponse {
    /** The access token issued by the authorization server */
    readonly access_token: string;

    /** Token type - "Bearer" or "DPoP" for sender-constrained tokens (RFC 9449) */
    readonly token_type: 'Bearer' | 'DPoP';

    /** Lifetime of the access token in seconds */
    readonly expires_in: number;

    /** Space-delimited scope string */
    readonly scope: string;

    /** Refresh token for obtaining new access tokens */
    readonly refresh_token?: string;

    /** ID token for OpenID Connect authentication */
    readonly id_token?: string;
}

/**
 * OAuth 2.1 Error Response per Section 3.2.4.
 *
 * Error codes are standardized per OAuth 2.1:
 * - invalid_request: Malformed request (400)
 * - invalid_client: Client authentication failed (401)
 * - invalid_grant: Invalid authorization grant (400)
 * - unauthorized_client: Client not authorized for grant type (401)
 * - unsupported_grant_type: Grant type not supported (400)
 * - invalid_scope: Invalid scope requested (400)
 */
export interface TokenErrorResponse {
    /** OAuth 2.1 error code */
    readonly error: string;

    /** Human-readable error description (for developers, not end users) */
    readonly error_description?: string;

    /** URI to a web page with more information about the error */
    readonly error_uri?: string;
}
