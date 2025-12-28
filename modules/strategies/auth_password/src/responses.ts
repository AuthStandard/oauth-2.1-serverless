/**
 * OAuth Server - HTTP Response Helpers
 *
 * Standardized response formatting for the password authentication strategy.
 * Follows OAuth 2.1 error response specifications and security best practices.
 *
 * Security Headers:
 * - Cache-Control/Pragma: Prevent caching of sensitive authentication pages
 * - X-Content-Type-Options: Prevent MIME type sniffing
 * - X-Frame-Options: Prevent clickjacking attacks
 * - Referrer-Policy: Limit referrer information leakage
 * - Content-Security-Policy: Restrict resource loading and prevent XSS
 *
 * Note: X-XSS-Protection is intentionally omitted as it's deprecated and can
 * introduce vulnerabilities in modern browsers. CSP provides superior protection.
 *
 * @see https://owasp.org/www-project-secure-headers/
 * @see https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-XSS-Protection
 */

import type { LambdaResponse } from './types';

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
    'Referrer-Policy': 'strict-origin-when-cross-origin',
} as const;

/**
 * Get HTML headers with security CSP.
 * 
 * Note: form-action is intentionally omitted. While form-action 'self' should work,
 * some browsers have issues with it on serverless/API Gateway deployments where
 * the origin handling can be inconsistent. The other CSP directives (default-src,
 * frame-ancestors) provide the critical security protections.
 */
const HTML_HEADERS = {
    'Content-Type': 'text/html; charset=utf-8',
    'Cache-Control': 'no-store',
    'Pragma': 'no-cache',
    ...SECURITY_HEADERS,
    'Content-Security-Policy': "default-src 'self'; style-src 'unsafe-inline'; frame-ancestors 'none'",
} as const;

const JSON_HEADERS = {
    'Content-Type': 'application/json',
    'Cache-Control': 'no-store',
    'Pragma': 'no-cache',
    'Content-Security-Policy': "default-src 'none'; frame-ancestors 'none'",
    ...SECURITY_HEADERS,
} as const;

const REDIRECT_HEADERS = {
    'Cache-Control': 'no-store',
    'Pragma': 'no-cache',
    ...SECURITY_HEADERS,
} as const;

// =============================================================================
// Response Builders
// =============================================================================

/**
 * Return an HTML response with security headers.
 */
export function htmlResponse(body: string, statusCode = 200): LambdaResponse {
    return {
        statusCode,
        headers: HTML_HEADERS,
        body,
    };
}

/**
 * Return a JSON error response following OAuth 2.1 format.
 */
export function errorResponse(
    statusCode: number,
    error: string,
    description: string
): LambdaResponse {
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
 * Return an HTTP 303 See Other redirect response.
 * Uses 303 to ensure the browser performs a GET request to the target URL.
 */
export function redirect(url: string): LambdaResponse {
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
 * Redirect back to the login page with an error code.
 */
export function redirectToLoginWithError(
    loginUrl: string,
    sessionId: string,
    errorCode: string
): LambdaResponse {
    const url = `${loginUrl}?session_id=${encodeURIComponent(sessionId)}&error=${encodeURIComponent(errorCode)}`;
    return redirect(url);
}


/**
 * Return a JSON success response.
 */
export function jsonResponse(
    statusCode: number,
    body: Record<string, unknown>
): LambdaResponse {
    return {
        statusCode,
        headers: JSON_HEADERS,
        body: JSON.stringify(body),
    };
}
