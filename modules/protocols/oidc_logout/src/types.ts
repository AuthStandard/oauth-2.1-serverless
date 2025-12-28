/**
 * OIDC RP-Initiated Logout - Type Definitions
 *
 * Type definitions for the logout endpoint per OpenID Connect RP-Initiated Logout 1.0.
 *
 * @see https://openid.net/specs/openid-connect-rpinitiated-1_0.html
 */

// =============================================================================
// Environment Configuration
// =============================================================================

/**
 * Environment configuration loaded from Terraform-injected variables.
 * All values are required - no hardcoded defaults.
 */
export interface EnvConfig {
    /** DynamoDB table name for session and token storage */
    readonly tableName: string;
    /** KMS Key ID for JWT signature verification */
    readonly kmsKeyId: string;
    /** OAuth 2.1 issuer URL for token validation */
    readonly issuer: string;
    /** Session cookie name for browser session management */
    readonly sessionCookieName: string;
    /** Session cookie domain (optional, defaults to current domain) */
    readonly sessionCookieDomain: string;
    /** Default logout redirect URL when no valid post_logout_redirect_uri provided */
    readonly defaultLogoutRedirectUrl: string;
}

// =============================================================================
// Request Parameters
// =============================================================================

/**
 * OIDC RP-Initiated Logout request parameters.
 *
 * @see https://openid.net/specs/openid-connect-rpinitiated-1_0.html#RPLogout
 */
export interface LogoutRequestParams {
    /**
     * ID Token previously issued to the RP.
     * Used to identify the user and validate the logout request.
     * RECOMMENDED per spec, but we require it for security.
     */
    readonly id_token_hint?: string;

    /**
     * URL to redirect the user after logout.
     * MUST be registered with the client configuration.
     */
    readonly post_logout_redirect_uri?: string;

    /**
     * Opaque value for maintaining state between request and callback.
     * Returned unchanged in the redirect response.
     */
    readonly state?: string;

    /**
     * Client identifier for the RP requesting logout.
     * Used when id_token_hint is not provided to identify the client.
     */
    readonly client_id?: string;

    /**
     * End-user's preferred languages for the logout UI.
     * Space-separated list of BCP47 language tags.
     */
    readonly ui_locales?: string;
}

// =============================================================================
// ID Token Claims
// =============================================================================

/**
 * ID Token payload structure for logout validation.
 * Only includes claims relevant to logout processing.
 */
export interface IdTokenPayload {
    /** Issuer identifier - must match expected issuer */
    readonly iss: string;
    /** Subject identifier - the user being logged out */
    readonly sub: string;
    /** Audience - client_id or array of client_ids */
    readonly aud: string | string[];
    /** Expiration time (Unix timestamp) - may be expired for logout */
    readonly exp: number;
    /** Issued at time (Unix timestamp) */
    readonly iat: number;
    /** Session ID - identifies the session to terminate */
    readonly sid?: string;
    /** Authentication time (Unix timestamp) */
    readonly auth_time?: number;
    /** Nonce value from original authentication request */
    readonly nonce?: string;
}

// =============================================================================
// Client Configuration
// =============================================================================

/**
 * Client record structure from DynamoDB.
 * Only includes fields relevant to logout validation.
 */
export interface ClientRecord {
    /** OAuth2 Client ID */
    readonly clientId: string;
    /** Registered redirect URIs */
    readonly redirectUris: readonly string[];
    /** Registered post-logout redirect URIs */
    readonly postLogoutRedirectUris?: readonly string[];
    /** Client display name */
    readonly clientName: string;
}

// =============================================================================
// Session Record
// =============================================================================

/**
 * Login session record from DynamoDB.
 */
export interface SessionRecord {
    /** Session identifier */
    readonly sessionId: string;
    /** Client ID that initiated the session */
    readonly clientId: string;
    /** Authenticated user's subject identifier */
    readonly authenticatedUserId?: string;
    /** Session creation timestamp */
    readonly createdAt: string;
    /** TTL for automatic cleanup */
    readonly ttl?: number;
}
