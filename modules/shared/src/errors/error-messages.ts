/**
 * OAuth Server - Error Messages
 *
 * Human-readable error descriptions for common OAuth 2.1 scenarios.
 * These messages are used in error_description fields.
 */

export const ErrorMessages = {
    // -------------------------------------------------------------------------
    // Authorization Endpoint Errors
    // -------------------------------------------------------------------------

    /** Missing client_id parameter */
    MISSING_CLIENT_ID: 'Missing required parameter: client_id',

    /** Missing response_type parameter */
    MISSING_RESPONSE_TYPE: 'Missing required parameter: response_type',

    /** Missing redirect_uri parameter */
    MISSING_REDIRECT_URI: 'Missing required parameter: redirect_uri',

    /** Missing code_challenge parameter (PKCE is mandatory in OAuth 2.1) */
    MISSING_CODE_CHALLENGE: 'Missing required parameter: code_challenge (PKCE is mandatory in OAuth 2.1)',

    /** Invalid response_type value */
    INVALID_RESPONSE_TYPE: 'response_type must be "code" (OAuth 2.1)',

    /** Invalid code_challenge_method value */
    INVALID_CODE_CHALLENGE_METHOD: 'code_challenge_method must be "S256" (OAuth 2.1)',

    /** Client not found */
    UNKNOWN_CLIENT: 'Unknown client_id',

    /** Redirect URI not registered for this client */
    REDIRECT_URI_MISMATCH: 'redirect_uri does not match any registered URIs for this client',

    /** Redirect URI is malformed or uses insecure protocol */
    INVALID_REDIRECT_URI: 'redirect_uri is malformed or uses an insecure protocol',

    /** Missing state parameter (when required by policy) */
    MISSING_STATE: 'Missing recommended parameter: state (CSRF protection)',

    // -------------------------------------------------------------------------
    // Token Endpoint Errors
    // -------------------------------------------------------------------------

    /** Missing grant_type parameter */
    MISSING_GRANT_TYPE: 'Missing required parameter: grant_type',

    /** Missing code parameter */
    MISSING_CODE: 'Missing required parameter: code',

    /** Missing code_verifier parameter (PKCE is mandatory) */
    MISSING_CODE_VERIFIER: 'Missing required parameter: code_verifier (PKCE is mandatory)',

    /** Missing refresh_token parameter */
    MISSING_REFRESH_TOKEN: 'Missing required parameter: refresh_token',

    /** Authorization code is invalid or expired */
    INVALID_CODE: 'Authorization code is invalid or expired',

    /** Authorization code has already been used */
    CODE_ALREADY_USED: 'Authorization code has already been used',

    /** Authorization code has expired */
    CODE_EXPIRED: 'Authorization code has expired',

    /** PKCE code_verifier is invalid */
    INVALID_CODE_VERIFIER: 'code_verifier is invalid',

    /** Refresh token is invalid or expired */
    INVALID_REFRESH_TOKEN: 'Refresh token is invalid or expired',

    /** Refresh token has been revoked */
    REFRESH_TOKEN_REVOKED: 'Refresh token has been revoked',

    /** Client authentication failed */
    CLIENT_AUTH_FAILED: 'Client authentication failed',

    /** Client authentication required */
    CLIENT_AUTH_REQUIRED: 'Client authentication required',

    /** Grant type not supported */
    UNSUPPORTED_GRANT: 'The authorization grant type is not supported',

    // -------------------------------------------------------------------------
    // Session Errors
    // -------------------------------------------------------------------------

    /** Session has expired */
    SESSION_EXPIRED: 'Session has expired',

    /** Session not found */
    SESSION_NOT_FOUND: 'Invalid or expired session',

    // -------------------------------------------------------------------------
    // User Errors
    // -------------------------------------------------------------------------

    /** User not found */
    USER_NOT_FOUND: 'User not found',

    /** User account is not active */
    ACCOUNT_INACTIVE: 'User account is not active',

    // -------------------------------------------------------------------------
    // General Errors
    // -------------------------------------------------------------------------

    /** Internal server error */
    INTERNAL_ERROR: 'An unexpected error occurred',

    /** Scope validation failed */
    SCOPE_EXCEEDS_ALLOWED: 'Requested scope exceeds allowed scopes for this client',

    /** Invalid scope format */
    INVALID_SCOPE_FORMAT: 'Scope parameter contains invalid characters',

    /** Token has been rotated (refresh token reuse detected) */
    TOKEN_REUSE_DETECTED: 'Refresh token has already been used (potential replay attack)',

    /** Token family has been revoked due to security event */
    TOKEN_FAMILY_REVOKED: 'Token family has been revoked due to detected token reuse',

    // -------------------------------------------------------------------------
    // PKCE Errors
    // -------------------------------------------------------------------------

    /** PKCE verification failed */
    PKCE_VERIFICATION_FAILED: 'PKCE verification failed: code_verifier does not match code_challenge',

    /** Invalid code_challenge format */
    INVALID_CODE_CHALLENGE: 'code_challenge must be a 43-character base64url-encoded string',

    /** Invalid code_verifier format */
    INVALID_CODE_VERIFIER_FORMAT: 'code_verifier must be 43-128 characters using unreserved URI characters',

    // -------------------------------------------------------------------------
    // Token Introspection Errors
    // -------------------------------------------------------------------------

    /** Token introspection requires client authentication */
    INTROSPECTION_AUTH_REQUIRED: 'Token introspection requires client authentication',

    /** Missing token parameter in introspection request */
    MISSING_TOKEN: 'Missing required parameter: token',

    // -------------------------------------------------------------------------
    // Access Control Errors
    // -------------------------------------------------------------------------

    /** Access denied by resource owner or authorization server */
    ACCESS_DENIED: 'The resource owner or authorization server denied the request',

    /** Service temporarily unavailable */
    SERVICE_UNAVAILABLE: 'The authorization server is temporarily unable to handle the request',

    // -------------------------------------------------------------------------
    // Client Errors
    // -------------------------------------------------------------------------

    /** Client not authorized for this grant type */
    CLIENT_NOT_AUTHORIZED_FOR_GRANT: 'This client is not authorized to use this grant type',

    /** Client redirect URI validation failed */
    CLIENT_REDIRECT_VALIDATION_FAILED: 'Client redirect URI validation failed',
} as const;
