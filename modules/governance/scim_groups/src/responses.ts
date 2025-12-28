/**
 * SCIM v2 Group Provisioning - HTTP Response Builders
 *
 * Standardized response formatting per RFC 7644.
 *
 * @module governance/scim_groups/responses
 * @see RFC 7644 Section 3.12 - Error Handling
 */

import type { APIGatewayProxyResultV2 } from 'aws-lambda';
import type { ScimGroup, ScimErrorResponse, ScimErrorType, ScimListResponse } from './types';
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
 * Return a SCIM Group resource (200 OK or 201 Created).
 *
 * @param group - SCIM Group resource
 * @param statusCode - HTTP status code (200 or 201)
 * @returns API Gateway response
 */
export function scimGroupResponse(
    group: ScimGroup,
    statusCode: 200 | 201 = 200
): APIGatewayProxyResultV2 {
    return {
        statusCode,
        headers: SCIM_HEADERS,
        body: JSON.stringify(group),
    };
}

/**
 * Return a SCIM List Response (200 OK).
 *
 * @param groups - Array of SCIM Group resources
 * @param totalResults - Total number of results
 * @param startIndex - Starting index (1-based)
 * @returns API Gateway response
 */
export function scimListResponse(
    groups: readonly ScimGroup[],
    totalResults: number,
    startIndex: number = 1
): APIGatewayProxyResultV2 {
    const response: ScimListResponse<ScimGroup> = {
        schemas: [SCIM_LIST_SCHEMA],
        totalResults,
        startIndex,
        itemsPerPage: groups.length,
        Resources: groups,
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
    const errorResponse: ScimErrorResponse = {
        schemas: [SCIM_ERROR_SCHEMA],
        status: statusCode.toString(),
        detail,
        ...(scimType && { scimType }),
    };

    return {
        statusCode,
        headers: SCIM_HEADERS,
        body: JSON.stringify(errorResponse),
    };
}

/**
 * Return 400 Bad Request with SCIM error format.
 */
export function scimBadRequest(detail: string, scimType?: ScimErrorType): APIGatewayProxyResultV2 {
    return scimError(400, detail, scimType);
}

/**
 * Return 401 Unauthorized with SCIM error format.
 */
export function scimUnauthorized(detail: string = 'Authentication required'): APIGatewayProxyResultV2 {
    return scimError(401, detail);
}

/**
 * Return 403 Forbidden with SCIM error format.
 */
export function scimForbidden(detail: string = 'Access denied'): APIGatewayProxyResultV2 {
    return scimError(403, detail);
}

/**
 * Return 404 Not Found with SCIM error format.
 */
export function scimNotFound(detail: string): APIGatewayProxyResultV2 {
    return scimError(404, detail, 'noTarget');
}

/**
 * Return 409 Conflict with SCIM error format.
 */
export function scimConflict(detail: string): APIGatewayProxyResultV2 {
    return scimError(409, detail, 'uniqueness');
}

/**
 * Return 500 Internal Server Error with SCIM error format.
 */
export function scimServerError(detail: string = 'Internal server error'): APIGatewayProxyResultV2 {
    return scimError(500, detail);
}
