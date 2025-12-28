/**
 * OAuth Server - TOTP MFA Response Helpers
 *
 * Standardized response formatting for the TOTP MFA strategy.
 */

import type { LambdaResponse } from './types';

// =============================================================================
// Response Headers
// =============================================================================

const SECURITY_HEADERS = {
    'Strict-Transport-Security': 'max-age=63072000; includeSubDomains; preload',
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'DENY',
    'Referrer-Policy': 'strict-origin-when-cross-origin',
} as const;

const JSON_HEADERS = {
    'Content-Type': 'application/json',
    'Cache-Control': 'no-store',
    'Pragma': 'no-cache',
    'Content-Security-Policy': "default-src 'none'; frame-ancestors 'none'",
    ...SECURITY_HEADERS,
} as const;

// =============================================================================
// Response Builders
// =============================================================================

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

/**
 * Return a JSON error response.
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
