/**
 * OAuth 2.1 Authorization Endpoint - Type Definitions
 *
 * @module oauth2_authorize/types
 * @see https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1-14#section-4.1.1
 * @see https://openid.net/specs/oauth-v2-form-post-response-mode-1_0.html
 * @see https://openid.net/specs/openid-connect-core-1_0.html#AuthRequest
 */

// =============================================================================
// Entity Types (from shared schema)
// =============================================================================

export type {
    ClientItem,
    LoginSessionItem,
    AuthCodeItem,
    AuthenticatedSessionItem,
} from '../../../shared_types/schema';

// =============================================================================
// Environment Configuration
// =============================================================================

/** Authorize handler configuration (from Terraform) */
export interface AuthorizeEnvConfig {
    readonly tableName: string;
    readonly loginRouterUrl: string;
    readonly sessionTtlSeconds: number;
    readonly issuer: string;
    /** Session cookie name (default: __Host-sid) */
    readonly sessionCookieName: string;
}

/** Callback handler configuration (from Terraform) */
export interface CallbackEnvConfig {
    readonly tableName: string;
    readonly codeTtlSeconds: number;
    readonly issuer: string;
    /** Session cookie name (default: __Host-sid) */
    readonly sessionCookieName: string;
    /** Session cookie domain (optional) */
    readonly sessionCookieDomain?: string;
    /** Authenticated session TTL in seconds (default: 86400 = 24 hours) */
    readonly authSessionTtlSeconds: number;
}

// =============================================================================
// Response Mode (OAuth 2.0 Multiple Response Types)
// =============================================================================

/**
 * Supported response modes per OAuth 2.0 Multiple Response Types.
 *
 * - query: Parameters in query string (default for code flow)
 * - fragment: Parameters in URI fragment (not used in OAuth 2.1 code flow)
 * - form_post: Parameters via HTML form POST
 *
 * @see https://openid.net/specs/oauth-v2-form-post-response-mode-1_0.html
 */
export type ResponseMode = 'query' | 'fragment' | 'form_post';

// =============================================================================
// Prompt Parameter (OIDC)
// =============================================================================

/**
 * Supported prompt values per OpenID Connect Core 1.0.
 *
 * - none: No UI displayed, error if auth required (silent auth)
 * - login: Force re-authentication
 * - consent: Force consent screen
 * - select_account: Prompt for account selection
 *
 * @see https://openid.net/specs/openid-connect-core-1_0.html#AuthRequest
 */
export type PromptValue = 'none' | 'login' | 'consent' | 'select_account';

// =============================================================================
// Authorization Request Parameters
// =============================================================================

/**
 * Validated authorization request parameters.
 *
 * Per OAuth 2.1 Section 4.1.1:
 * - client_id: REQUIRED
 * - response_type: REQUIRED, must be "code"
 * - redirect_uri: REQUIRED
 * - code_challenge: REQUIRED (PKCE mandatory)
 * - code_challenge_method: must be "S256"
 * - scope: OPTIONAL (defaults to "openid")
 * - state: RECOMMENDED
 * - nonce: OPTIONAL (OIDC)
 *
 * Additional OIDC parameters:
 * - response_mode: OPTIONAL (query, fragment, form_post)
 * - prompt: OPTIONAL (none, login, consent, select_account)
 * - login_hint: OPTIONAL (hint about user identity)
 * - max_age: OPTIONAL (max auth age in seconds)
 * - ui_locales: OPTIONAL (preferred UI languages)
 * - acr_values: OPTIONAL (requested authentication context)
 */
export interface AuthorizeParams {
    readonly clientId: string;
    readonly responseType: 'code';
    readonly redirectUri: string;
    readonly scope: string;
    readonly state?: string;
    readonly codeChallenge: string;
    readonly codeChallengeMethod: 'S256';
    readonly nonce?: string;
    readonly responseMode?: ResponseMode;
    readonly prompt?: PromptValue;
    readonly loginHint?: string;
    readonly maxAge?: number;
    readonly uiLocales?: string;
    readonly acrValues?: string;
}
