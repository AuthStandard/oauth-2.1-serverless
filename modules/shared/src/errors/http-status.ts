/**
 * OAuth Server - HTTP Status Codes
 *
 * Standard HTTP status codes used in OAuth 2.1 responses.
 *
 * @see RFC 9110 - HTTP Semantics
 * @see RFC 6585 - Additional HTTP Status Codes (429)
 */

export const HttpStatus = {
    /** Request succeeded */
    OK: 200,
    /** Resource created successfully */
    CREATED: 201,
    /** Request succeeded with no content to return */
    NO_CONTENT: 204,
    /** Resource permanently moved */
    MOVED_PERMANENTLY: 301,
    /** Resource temporarily moved */
    FOUND: 302,
    /** Redirect after POST (POST-redirect-GET pattern) */
    SEE_OTHER: 303,
    /** Malformed request syntax or invalid parameters */
    BAD_REQUEST: 400,
    /** Authentication required or credentials invalid */
    UNAUTHORIZED: 401,
    /** Authenticated but not authorized for this resource */
    FORBIDDEN: 403,
    /** Resource not found */
    NOT_FOUND: 404,
    /** HTTP method not allowed for this endpoint */
    METHOD_NOT_ALLOWED: 405,
    /** Rate limit exceeded - per RFC 6585 Section 4 */
    TOO_MANY_REQUESTS: 429,
    /** Unexpected server error */
    INTERNAL_SERVER_ERROR: 500,
    /** Server temporarily unavailable */
    SERVICE_UNAVAILABLE: 503,
} as const;

/** Type representing valid HTTP status code values */
export type HttpStatusCode = typeof HttpStatus[keyof typeof HttpStatus];
