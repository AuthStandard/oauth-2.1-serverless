/**
 * OAuth Server - OAuth 2.1 Parameter Validation
 *
 * Validation functions for OAuth 2.1 request parameters.
 * Implements RFC-compliant validation with strict security requirements.
 *
 * Security Principles:
 * - Strict character whitelisting prevents injection attacks
 * - Length limits prevent DoS via oversized inputs
 * - Type guards provide compile-time safety
 * - All validation fails closed (reject if not explicitly valid)
 *
 * @see RFC 6749 - OAuth 2.0 Authorization Framework
 * @see RFC 7636 - Proof Key for Code Exchange (PKCE)
 * @see OAuth 2.1 Draft - https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1
 */

// =============================================================================
// Constants
// =============================================================================

/** Maximum allowed client_id length (generous limit for various ID formats) */
const MAX_CLIENT_ID_LENGTH = 256;

/** Maximum allowed state parameter length (prevents abuse while allowing UUIDs and JWTs) */
const MAX_STATE_LENGTH = 512;

/** Maximum allowed nonce parameter length (for OIDC replay protection) */
const MAX_NONCE_LENGTH = 512;

/** PKCE code_challenge length for S256 (32 bytes SHA-256 → 43 chars base64url) */
const CODE_CHALLENGE_LENGTH = 43;

/** Minimum code_verifier length per RFC 7636 Section 4.1 */
const CODE_VERIFIER_MIN_LENGTH = 43;

/** Maximum code_verifier length per RFC 7636 Section 4.1 */
const CODE_VERIFIER_MAX_LENGTH = 128;

/** Maximum redirect URI length (prevents DoS via oversized URIs) */
const MAX_REDIRECT_URI_LENGTH = 2048;

/**
 * Regex pattern for valid client_id characters.
 * Allows alphanumeric, hyphens, underscores, and periods.
 * Periods support reverse-domain style IDs per RFC 8252.
 */
const CLIENT_ID_PATTERN = /^[a-zA-Z0-9._-]+$/;

/**
 * Regex pattern for base64url characters (used in PKCE).
 * Per RFC 4648 Section 5: A-Z, a-z, 0-9, -, _
 */
const BASE64URL_PATTERN = /^[A-Za-z0-9_-]+$/;

/**
 * Regex pattern for PKCE code_verifier (unreserved URI characters).
 * Per RFC 3986 Section 2.3: ALPHA / DIGIT / "-" / "." / "_" / "~"
 */
const CODE_VERIFIER_PATTERN = /^[A-Za-z0-9\-._~]+$/;

// =============================================================================
// Client ID Validation
// =============================================================================

/**
 * Validate a client_id parameter.
 *
 * Per RFC 6749 Section 2.2, client_id is a unique string issued by the
 * authorization server. This implementation allows:
 * - Alphanumeric characters (A-Z, a-z, 0-9)
 * - Hyphens (-), underscores (_), periods (.)
 *
 * Periods support reverse-domain style IDs (e.g., com.example.app)
 * per RFC 8252 Section 7.1 for native app client identifiers.
 *
 * @param clientId - The client identifier to validate
 * @returns True if valid (also narrows type to string)
 *
 * @see RFC 6749 Section 2.2 - Client Identifier
 * @see RFC 8252 Section 7.1 - Native App Client Identifiers
 */
export function isValidClientId(clientId: string | undefined | null): clientId is string {
    if (clientId === null || clientId === undefined || typeof clientId !== 'string') {
        return false;
    }

    // Early length check before any processing (DoS protection)
    if (clientId.length > MAX_CLIENT_ID_LENGTH) {
        return false;
    }

    const trimmed = clientId.trim();
    if (trimmed.length < 1 || trimmed.length > MAX_CLIENT_ID_LENGTH) {
        return false;
    }

    return CLIENT_ID_PATTERN.test(trimmed);
}

// =============================================================================
// Redirect URI Validation
// =============================================================================

/**
 * Validate a redirect_uri parameter.
 *
 * OAuth 2.1 requires exact string matching against registered URIs.
 * This function validates the URI is well-formed and meets security requirements.
 *
 * Security Requirements:
 * - HTTPS required for production deployments
 * - HTTP allowed only for localhost/127.0.0.1 (development)
 * - No fragments allowed (per OAuth 2.1 Section 2.3.1)
 * - Custom schemes allowed for native apps (per RFC 8252)
 * - Length limit enforced before parsing (DoS protection)
 *
 * @param uri - The redirect URI to validate
 * @returns True if the URI is well-formed (also narrows type to string)
 *
 * @see OAuth 2.1 Draft Section 2.3.1 - Redirect URI Registration
 * @see RFC 8252 Section 7.1 - Private-Use URI Scheme Redirection
 */
export function isValidRedirectUri(uri: string | undefined | null): uri is string {
    if (uri === null || uri === undefined || typeof uri !== 'string') {
        return false;
    }

    // Early length check before URL parsing (DoS protection)
    if (uri.length > MAX_REDIRECT_URI_LENGTH) {
        return false;
    }

    try {
        const parsed = new URL(uri);

        // No fragments allowed per OAuth 2.1 Section 2.3.1
        if (parsed.hash) {
            return false;
        }

        // HTTPS is required except for localhost development
        if (parsed.protocol === 'http:') {
            const isLocalhost = parsed.hostname === 'localhost' || parsed.hostname === '127.0.0.1';
            if (!isLocalhost) {
                return false;
            }
        } else if (parsed.protocol !== 'https:') {
            // Allow custom schemes for native apps (e.g., com.example.app://)
            // Custom schemes must be reverse-domain format per RFC 8252
            const customScheme = parsed.protocol.slice(0, -1); // Remove trailing ':'
            if (!/^[a-z][a-z0-9+.-]*$/i.test(customScheme)) {
                return false;
            }
        }

        return true;
    } catch {
        return false;
    }
}

// =============================================================================
// State Parameter Validation
// =============================================================================

/**
 * Validate a state parameter.
 *
 * State is an opaque value used for CSRF protection. Per OAuth 2.1,
 * state is RECOMMENDED and should be unpredictable and tied to the
 * user's session.
 *
 * @param state - The state parameter to validate
 * @returns True if valid (or undefined/null, as state is optional)
 *
 * @see RFC 6749 Section 4.1.1 - state parameter
 * @see OAuth 2.1 Draft Section 4.1.1 - state is RECOMMENDED
 * @see OAuth Security BCP Section 4.7.1 - CSRF Protection via state
 */
export function isValidState(state: string | undefined | null): boolean {
    if (state === undefined || state === null) {
        return true; // State is optional (though strongly recommended)
    }

    if (typeof state !== 'string') {
        return false;
    }

    // Reasonable length limit to prevent abuse
    return state.length > 0 && state.length <= MAX_STATE_LENGTH;
}

// =============================================================================
// PKCE Validation
// =============================================================================

/**
 * Validate a PKCE code_challenge parameter.
 *
 * For S256 method (mandatory in OAuth 2.1), the code_challenge is:
 * BASE64URL(SHA256(code_verifier))
 *
 * SHA-256 produces 32 bytes, which base64url-encodes to exactly 43 characters
 * (without padding).
 *
 * @param challenge - The code challenge to validate
 * @returns True if valid (also narrows type to string)
 *
 * @see RFC 7636 Section 4.2 - code_challenge
 * @see OAuth 2.1 Draft Section 4.1.1 - PKCE is mandatory, S256 only
 */
export function isValidCodeChallenge(challenge: string | undefined | null): challenge is string {
    if (challenge === null || challenge === undefined || typeof challenge !== 'string') {
        return false;
    }

    // S256 produces exactly 43-character base64url string
    // (32 bytes SHA-256 output → 43 chars when base64url encoded without padding)
    if (challenge.length !== CODE_CHALLENGE_LENGTH) {
        return false;
    }

    return BASE64URL_PATTERN.test(challenge);
}

/**
 * Validate a PKCE code_verifier parameter.
 *
 * Per RFC 7636 Section 4.1, code_verifier must be:
 * - 43-128 characters in length
 * - Composed of unreserved URI characters per RFC 3986 Section 2.3
 *
 * Unreserved characters: ALPHA / DIGIT / "-" / "." / "_" / "~"
 *
 * @param verifier - The code verifier to validate
 * @returns True if valid (also narrows type to string)
 *
 * @see RFC 7636 Section 4.1 - code_verifier = 43*128unreserved
 * @see RFC 3986 Section 2.3 - unreserved characters
 */
export function isValidCodeVerifier(verifier: string | undefined | null): verifier is string {
    if (verifier === null || verifier === undefined || typeof verifier !== 'string') {
        return false;
    }

    // Per RFC 7636 Section 4.1: 43-128 characters
    if (verifier.length < CODE_VERIFIER_MIN_LENGTH || verifier.length > CODE_VERIFIER_MAX_LENGTH) {
        return false;
    }

    return CODE_VERIFIER_PATTERN.test(verifier);
}

/**
 * Validate an OIDC nonce parameter.
 *
 * Nonce is an opaque value used for replay protection in OIDC.
 * It binds the ID token to the client session.
 *
 * @param nonce - The nonce parameter to validate
 * @returns True if valid (or undefined/null, as nonce is optional)
 *
 * @see OpenID Connect Core 1.0 Section 3.1.2.1 - nonce parameter
 */
export function isValidNonce(nonce: string | undefined | null): boolean {
    if (nonce === undefined || nonce === null) {
        return true; // Nonce is optional
    }

    if (typeof nonce !== 'string') {
        return false;
    }

    // Reasonable length limit to prevent abuse
    return nonce.length > 0 && nonce.length <= MAX_NONCE_LENGTH;
}
