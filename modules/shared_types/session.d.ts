/**
 * OAuth Server - Login Session Entity Types
 *
 * Temporary login sessions created during authorization flow.
 *
 * Key Pattern:
 *   PK: SESSION#<session_id>
 *   SK: METADATA
 *   GSI1PK: CLIENT#<client_id>
 *   GSI1SK: SESSION#<timestamp>
 *
 * @see OAuth 2.1 Draft Section 4.1.1 - Authorization Request
 * @see https://openid.net/specs/openid-connect-core-1_0.html#AuthRequest
 */

import type { BaseItem } from './base';

// =============================================================================
// Login Session Entity
// =============================================================================

/**
 * Temporary login session created during authorization flow.
 * 
 * Lifecycle:
 * 1. Created by /authorize endpoint with OAuth parameters and PKCE challenge
 * 2. Updated by authentication strategy with authenticatedUserId after successful login
 * 3. Consumed by /authorize/callback to generate authorization code
 * 4. Deleted after code generation (single-use)
 * 
 * Short TTL (typically 10 minutes) ensures abandoned sessions are cleaned up.
 * 
 * @see OAuth 2.1 Section 4.1.1 - Authorization Request
 */
export interface LoginSessionItem extends BaseItem {
    /** PK pattern: SESSION#<session_id> */
    PK: `SESSION#${string}`;
    SK: 'METADATA';
    entityType: 'LOGIN_SESSION';

    /** Unique session identifier (UUID) */
    sessionId: string;

    /** Client ID that initiated the authorization request */
    clientId: string;

    /** Requested scopes (space-delimited) */
    scope: string;

    /** PKCE code challenge (SHA256 hash, base64url encoded) */
    codeChallenge: string;

    /** PKCE challenge method (OAuth 2.1 mandates S256 only) */
    codeChallengeMethod: 'S256';

    /** Redirect URI (validated against client registration) */
    redirectUri: string;

    /** State parameter (if provided by client) */
    state?: string;

    /** OIDC nonce value (if provided) */
    nonce?: string;

    /** Response type (always 'code' for OAuth 2.1) */
    responseType: 'code';

    /** Authentication strategy to use (e.g., 'password', 'saml') */
    authStrategyId?: string;

    /**
     * User's subject identifier after successful authentication.
     * Set by the authentication strategy (e.g., auth_password, auth_saml).
     * Required before /authorize/callback can issue an authorization code.
     */
    authenticatedUserId?: string;

    /** ISO 8601 timestamp when authentication completed */
    authenticatedAt?: string;

    /** Authentication method used (e.g., 'password', 'saml') */
    authMethod?: string;

    // =========================================================================
    // OIDC Extension Parameters
    // =========================================================================

    /**
     * Response mode for authorization response delivery.
     * - query: Parameters in query string (default)
     * - fragment: Parameters in URI fragment
     * - form_post: Parameters via HTML form POST
     *
     * @see https://openid.net/specs/oauth-v2-form-post-response-mode-1_0.html
     */
    responseMode?: 'query' | 'fragment' | 'form_post';

    /**
     * Prompt parameter for controlling authentication UI.
     * - none: Silent auth, error if interaction required
     * - login: Force re-authentication
     * - consent: Force consent screen
     * - select_account: Account selection
     *
     * @see https://openid.net/specs/openid-connect-core-1_0.html#AuthRequest
     */
    prompt?: 'none' | 'login' | 'consent' | 'select_account';

    /**
     * Hint about the user's identity (email, phone, etc.).
     * Used to pre-fill login forms or skip account selection.
     */
    loginHint?: string;

    /**
     * Maximum authentication age in seconds.
     * If the user's auth is older than this, force re-authentication.
     */
    maxAge?: number;

    /**
     * Preferred UI languages (space-delimited BCP47 tags).
     * e.g., "en de fr"
     */
    uiLocales?: string;

    /**
     * Requested Authentication Context Class Reference values.
     * Space-delimited list of ACR values in order of preference.
     */
    acrValues?: string;
}

// =============================================================================
// Type Guard Declarations
// =============================================================================

// Note: Type guard implementations are provided in the shared module (type-guards.ts).
// These declarations exist for documentation purposes only.
