/**
 * OAuth 2.1 Token Endpoint - HTTP Response Builders
 *
 * Standardized response formatting per OAuth 2.1 Section 3.2.3 and 3.2.4.
 *
 * Security Headers (SOC2 Compliance):
 * - Strict-Transport-Security: Enforces HTTPS connections (RFC 6797)
 * - X-Content-Type-Options: nosniff - Prevents MIME sniffing attacks
 * - X-Frame-Options: DENY - Prevents clickjacking
 * - Content-Security-Policy: Restricts resource loading
 * - Cache-Control: no-store (REQUIRED per RFC 6749 Section 5.1)
 * - Pragma: no-cache (HTTP/1.0 backward compatibility)
 *
 * CORS Support:
 * - Token endpoint supports CORS for browser-based clients
 * - Configurable allowed origins for security
 *
 * @module oauth2_token/response
 * @see https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1-14#section-3.2.3
 * @see https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1-14#section-3.2.4
 * @see https://datatracker.ietf.org/doc/html/rfc6797 (HSTS)
 */

import type { APIGatewayProxyResultV2 } from 'aws-lambda';

// =============================================================================
// Response Headers
// =============================================================================

/**
 * SOC2-compliant security headers applied to all responses.
 */
const SECURITY_HEADERS = {
    'Strict-Transport-Security': 'max-age=63072000; includeSubDomains; preload',
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'DENY',
    'Content-Security-Policy': "default-src 'none'; frame-ancestors 'none'",
    'Referrer-Policy': 'strict-origin-when-cross-origin',
} as const;

/**
 * Standard headers for all token endpoint responses.
 * Cache-Control: no-store is REQUIRED per OAuth 2.1 Section 3.2.3.
 */
const BASE_HEADERS = {
    'Content-Type': 'application/json;charset=UTF-8',
    'Cache-Control': 'no-store',
    'Pragma': 'no-cache',
    ...SECURITY_HEADERS,
} as const;

/**
 * Headers for 401 Unauthorized responses.
 * Includes WWW-Authenticate header per RFC 6749 Section 5.2.
 */
const UNAUTHORIZED_HEADERS = {
    ...BASE_HEADERS,
    'WWW-Authenticate': 'Basic realm="oauth"',
} as const;

// =============================================================================
// CORS Support
// =============================================================================

/**
 * Add CORS headers to a response.
 *
 * Per OAuth 2.1, the token endpoint may need to support CORS for
 * browser-based public clients (SPAs).
 *
 * @param response - The response to add CORS headers to
 * @param origin - The allowed origin (use specific origin, not '*' for credentials)
 * @returns Response with CORS headers
 */
export function withCors(
    response: APIGatewayProxyResultV2,
    origin?: string
): APIGatewayProxyResultV2 {
    // Handle string responses (shouldn't happen in our codebase, but type-safe)
    if (typeof response === 'string') {
        return response;
    }
    const corsHeaders: Record<string, string> = {
        'Access-Control-Allow-Origin': origin || '*',
        'Access-Control-Allow-Methods': 'POST, OPTIONS',
        'Access-Control-Allow-Headers': 'Content-Type, Authorization, DPoP',
        'Access-Control-Expose-Headers': 'DPoP-Nonce, WWW-Authenticate',
        'Access-Control-Max-Age': '86400',
    };

    // Don't allow credentials with wildcard origin
    if (origin && origin !== '*') {
        corsHeaders['Access-Control-Allow-Credentials'] = 'true';
    }

    return {
        ...response,
        headers: {
            ...response.headers,
            ...corsHeaders,
        },
    };
}

/**
 * Return a CORS preflight response for OPTIONS requests.
 * Includes SOC2-compliant security headers.
 *
 * @param origin - The allowed origin
 * @returns 204 No Content with CORS headers
 */
export function corsPreflightResponse(origin?: string): APIGatewayProxyResultV2 {
    const corsHeaders: Record<string, string> = {
        ...SECURITY_HEADERS,
        'Access-Control-Allow-Origin': origin || '*',
        'Access-Control-Allow-Methods': 'POST, OPTIONS',
        'Access-Control-Allow-Headers': 'Content-Type, Authorization, DPoP',
        'Access-Control-Expose-Headers': 'DPoP-Nonce, WWW-Authenticate',
        'Access-Control-Max-Age': '86400',
    };

    if (origin && origin !== '*') {
        corsHeaders['Access-Control-Allow-Credentials'] = 'true';
    }

    return {
        statusCode: 204,
        headers: corsHeaders,
        body: '',
    };
}

// =============================================================================
// Success Response
// =============================================================================

/**
 * Token response body interface per OAuth 2.1 Section 3.2.3.
 */
export interface TokenResponseBody {
    access_token: string;
    token_type: 'Bearer' | 'DPoP';
    expires_in: number;
    refresh_token?: string;
    scope?: string;
    id_token?: string;
}

/**
 * Create a successful token response per OAuth 2.1 Section 3.2.3.
 *
 * Per OAuth 2.1 Section 3.2.3, the scope parameter is REQUIRED in the
 * response if the issued scope differs from the requested scope. We always
 * include scope for clarity and consistency.
 *
 * @param body - Token response body (access_token, token_type, expires_in, etc.)
 * @returns HTTP 200 response with JSON body
 */
export function tokenResponse(
    body: TokenResponseBody | Record<string, unknown>
): APIGatewayProxyResultV2 {
    return {
        statusCode: 200,
        headers: BASE_HEADERS,
        body: JSON.stringify(body),
    };
}

// =============================================================================
// Error Responses
// =============================================================================

/**
 * Create an OAuth 2.1 error response per Section 3.2.4.
 *
 * HTTP Status Codes per OAuth 2.1:
 * - 400: invalid_request, invalid_grant, invalid_scope, unsupported_grant_type
 * - 401: invalid_client (with WWW-Authenticate header)
 * - 401: unauthorized_client (client not authorized for grant type)
 *
 * @param statusCode - HTTP status code
 * @param error - OAuth 2.1 error code
 * @param description - Human-readable error description
 * @returns HTTP error response with JSON body
 */
export function errorResponse(
    statusCode: number,
    error: string,
    description?: string
): APIGatewayProxyResultV2 {
    const body: { error: string; error_description?: string } = { error };
    if (description) {
        body.error_description = description;
    }

    return {
        statusCode,
        headers: statusCode === 401 ? UNAUTHORIZED_HEADERS : BASE_HEADERS,
        body: JSON.stringify(body),
    };
}
