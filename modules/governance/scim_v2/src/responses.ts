/**
 * SCIM v2 User Provisioning - HTTP Response Builders
 *
 * Standardized response formatting per RFC 7644.
 *
 * @module governance/scim_v2/responses
 * @see RFC 7644 Section 3.12 - Error Handling
 */

import type { APIGatewayProxyResultV2 } from 'aws-lambda';
import type { ScimUser, ScimErrorResponse, ScimErrorType, ScimListResponse } from './types';
import { SCIM_ERROR_SCHEMA, SCIM_LIST_SCHEMA } from './types';

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
} as const;

/**
 * Standard headers for SCIM responses.
 * Content-Type must be application/scim+json per RFC 7644 Section 3.1.
 */
const SCIM_HEADERS = {
    'Content-Type': 'application/scim+json;charset=UTF-8',
    'Cache-Control': 'no-store',
    ...SECURITY_HEADERS,
} as const;

// =============================================================================
// Success Responses
// =============================================================================

/**
 * Return a SCIM User resource (200 OK or 201 Created).
 *
 * @param user - SCIM User resource
 * @param statusCode - HTTP status code (200 or 201)
 * @returns API Gateway response
 */
export function scimUserResponse(
    user: ScimUser,
    statusCode: 200 | 201 = 200
): APIGatewayProxyResultV2 {
    return {
        statusCode,
        headers: SCIM_HEADERS,
        body: JSON.stringify(user),
    };
}

/**
 * Return a SCIM List Response (200 OK).
 *
 * @param users - Array of SCIM User resources
 * @param totalResults - Total number of results
 * @param startIndex - Starting index (1-based)
 * @returns API Gateway response
 */
export function scimListResponse(
    users: readonly ScimUser[],
    totalResults: number,
    startIndex: number = 1
): APIGatewayProxyResultV2 {
    const response: ScimListResponse<ScimUser> = {
        schemas: [SCIM_LIST_SCHEMA],
        totalResults,
        startIndex,
        itemsPerPage: users.length,
        Resources: users,
    };

    return {
        statusCode: 200,
        headers: SCIM_HEADERS,
        body: JSON.stringify(response),
    };
}

/**
 * Return 204 No Content (for successful DELETE).
 */
export function scimNoContent(): APIGatewayProxyResultV2 {
    return {
        statusCode: 204,
        headers: SCIM_HEADERS,
        body: '',
    };
}

// =============================================================================
// Error Responses
// =============================================================================

/**
 * Build a SCIM error response per RFC 7644 Section 3.12.
 *
 * @param statusCode - HTTP status code
 * @param detail - Human-readable error detail
 * @param scimType - SCIM error type (optional)
 * @returns API Gateway response
 */
export function scimError(
    statusCode: number,
    detail: string,
    scimType?: ScimErrorType
): APIGatewayProxyResultV2 {
    const error: ScimErrorResponse = {
        schemas: [SCIM_ERROR_SCHEMA],
        status: statusCode.toString(),
        detail,
        ...(scimType && { scimType }),
    };

    return {
        statusCode,
        headers: SCIM_HEADERS,
        body: JSON.stringify(error),
    };
}

/**
 * 400 Bad Request - Invalid request syntax.
 */
export function scimBadRequest(detail: string, scimType?: ScimErrorType): APIGatewayProxyResultV2 {
    return scimError(400, detail, scimType || 'invalidSyntax');
}

/**
 * 401 Unauthorized - Authentication required.
 */
export function scimUnauthorized(detail: string = 'Authentication required'): APIGatewayProxyResultV2 {
    return {
        statusCode: 401,
        headers: {
            ...SCIM_HEADERS,
            'WWW-Authenticate': 'Bearer realm="scim"',
        },
        body: JSON.stringify({
            schemas: [SCIM_ERROR_SCHEMA],
            status: '401',
            detail,
        } as ScimErrorResponse),
    };
}

/**
 * 403 Forbidden - Insufficient permissions.
 */
export function scimForbidden(detail: string = 'Insufficient permissions'): APIGatewayProxyResultV2 {
    return scimError(403, detail);
}

/**
 * 404 Not Found - Resource does not exist.
 */
export function scimNotFound(detail: string = 'Resource not found'): APIGatewayProxyResultV2 {
    return scimError(404, detail);
}

/**
 * 409 Conflict - Resource already exists (uniqueness violation).
 */
export function scimConflict(detail: string): APIGatewayProxyResultV2 {
    return scimError(409, detail, 'uniqueness');
}

/**
 * 500 Internal Server Error.
 */
export function scimServerError(detail: string = 'An unexpected error occurred'): APIGatewayProxyResultV2 {
    return scimError(500, detail);
}
