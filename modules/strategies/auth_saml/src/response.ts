/**
 * SAML Strategy - HTTP Response Helpers
 *
 * Standardized response builders for Lambda handlers.
 * Includes SOC2-compliant security headers on all responses.
 *
 * @module strategies/auth_saml/response
 */

import type { APIGatewayProxyResultV2 } from 'aws-lambda';

// =============================================================================
// Security Headers (SOC2 Compliance)
// =============================================================================

/**
 * Security headers applied to all responses per SOC2 requirements.
 * These headers protect against common web vulnerabilities.
 */
const SECURITY_HEADERS = {
    'Strict-Transport-Security': 'max-age=63072000; includeSubDomains; preload',
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'DENY',
} as const;

// =============================================================================
// Response Headers
// =============================================================================

const JSON_HEADERS = {
    ...SECURITY_HEADERS,
    'Content-Type': 'application/json',
    'Cache-Control': 'no-store',
    'Pragma': 'no-cache',
} as const;

/**
 * XML headers for SP metadata endpoint.
 * Note: Metadata is public and cacheable, but we still apply security headers.
 * Cache reduced to 4 hours to allow faster certificate rotation propagation.
 */
const XML_HEADERS = {
    ...SECURITY_HEADERS,
    'Content-Type': 'application/xml; charset=utf-8',
    'Cache-Control': 'public, max-age=14400',
} as const;

const REDIRECT_HEADERS = {
    ...SECURITY_HEADERS,
    'Cache-Control': 'no-store',
    'Pragma': 'no-cache',
} as const;

// =============================================================================
// Response Builders
// =============================================================================

/**
 * Create an HTTP 303 See Other redirect response.
 *
 * @param url - Target URL for redirect
 */
export function redirect(url: string): APIGatewayProxyResultV2 {
    return {
        statusCode: 303,
        headers: {
            ...REDIRECT_HEADERS,
            Location: url,
        },
        body: '',
    };
}

/**
 * Create an OAuth-compliant error response.
 *
 * @param statusCode - HTTP status code
 * @param error - OAuth error code
 * @param description - Human-readable error description
 */
export function errorResponse(
    statusCode: number,
    error: string,
    description: string
): APIGatewayProxyResultV2 {
    return {
        statusCode,
        headers: JSON_HEADERS,
        body: JSON.stringify({
            error,
            error_description: description,
        }),
    };
}

/**
 * Create an XML response (for SP metadata).
 *
 * @param body - XML content
 */
export function xmlResponse(body: string): APIGatewayProxyResultV2 {
    return {
        statusCode: 200,
        headers: XML_HEADERS,
        body,
    };
}

/**
 * Create a server error response.
 *
 * @param description - Error description
 */
export function serverError(description: string): APIGatewayProxyResultV2 {
    return errorResponse(500, 'server_error', description);
}
