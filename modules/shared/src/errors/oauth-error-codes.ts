/**
 * OAuth Server - OAuth 2.1 Error Codes
 *
 * Standardized error codes per OAuth 2.1 specification.
 *
 * @see OAuth 2.1 Draft Section 3.2.4 - Error Response
 * @see OAuth 2.1 Draft Section 4.1.2.1 - Authorization Error Response
 * @see RFC 6750 Section 3 - Bearer Token Error Codes
 */

// =============================================================================
// Authorization Endpoint Error Codes
// =============================================================================

/**
 * OAuth 2.1 standard error codes for the authorization endpoint.
 *
 * @see OAuth 2.1 Draft Section 4.1.2.1 - Error Response
 */
export const AuthorizationErrors = {
    /** The request is missing a required parameter or is otherwise malformed */
    INVALID_REQUEST: 'invalid_request',

    /** The client is not authorized to request an authorization code */
    UNAUTHORIZED_CLIENT: 'unauthorized_client',

    /** The resource owner or authorization server denied the request */
    ACCESS_DENIED: 'access_denied',

    /** The authorization server does not support the requested response type */
    UNSUPPORTED_RESPONSE_TYPE: 'unsupported_response_type',

    /** The requested scope is invalid, unknown, or malformed */
    INVALID_SCOPE: 'invalid_scope',

    /** The authorization server encountered an unexpected condition */
    SERVER_ERROR: 'server_error',

    /** The authorization server is currently unable to handle the request */
    TEMPORARILY_UNAVAILABLE: 'temporarily_unavailable',
} as const;

export type AuthorizationErrorCode = typeof AuthorizationErrors[keyof typeof AuthorizationErrors];

// =============================================================================
// Token Endpoint Error Codes
// =============================================================================

/**
 * OAuth 2.1 standard error codes for the token endpoint.
 *
 * @see OAuth 2.1 Draft Section 3.2.4 - Error Response
 */
export const TokenErrors = {
    /** The request is missing a required parameter or is otherwise malformed */
    INVALID_REQUEST: 'invalid_request',

    /** Client authentication failed */
    INVALID_CLIENT: 'invalid_client',

    /** The provided authorization grant is invalid, expired, or revoked */
    INVALID_GRANT: 'invalid_grant',

    /** The client is not authorized to use this authorization grant type */
    UNAUTHORIZED_CLIENT: 'unauthorized_client',

    /** The authorization grant type is not supported by the authorization server */
    UNSUPPORTED_GRANT_TYPE: 'unsupported_grant_type',

    /** The requested scope is invalid, unknown, or malformed */
    INVALID_SCOPE: 'invalid_scope',

    /** The resource owner or authorization server denied the request */
    ACCESS_DENIED: 'access_denied',

    /** The authorization server encountered an unexpected condition */
    SERVER_ERROR: 'server_error',

    /** The authorization server is temporarily unable to handle the request */
    TEMPORARILY_UNAVAILABLE: 'temporarily_unavailable',
} as const;

export type TokenErrorCode = typeof TokenErrors[keyof typeof TokenErrors];

// =============================================================================
// Resource Server Error Codes
// =============================================================================

/**
 * OAuth 2.1 standard error codes for resource server responses.
 *
 * @see RFC 6750 Section 3.1 - Error Codes
 */
export const ResourceErrors = {
    /** The access token is invalid, expired, or revoked */
    INVALID_TOKEN: 'invalid_token',

    /** The request requires higher privileges than provided by the access token */
    INSUFFICIENT_SCOPE: 'insufficient_scope',
} as const;

export type ResourceErrorCode = typeof ResourceErrors[keyof typeof ResourceErrors];

// =============================================================================
// Union Type
// =============================================================================

export type OAuthErrorCode = AuthorizationErrorCode | TokenErrorCode | ResourceErrorCode;
