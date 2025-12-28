/**
 * SCIM v2 User Provisioning - Lambda Handler
 *
 * Implements SCIM 2.0 (RFC 7643, RFC 7644) User Resource endpoints:
 * - POST /scim/v2/Users - Create user (with Enterprise Extension support)
 * - GET /scim/v2/Users/{id} - Read user
 * - PATCH /scim/v2/Users/{id} - Update user
 * - GET /scim/v2/Me - Self-service profile retrieval (RFC 7644 Section 3.11)
 * - PATCH /scim/v2/Me - Self-service profile update (limited fields)
 *
 * Enterprise Extension (RFC 7643 Section 4.3):
 * - urn:ietf:params:scim:schemas:extension:enterprise:2.0:User
 * - Supports: employeeNumber, costCenter, organization, division, department, manager
 *
 * Security:
 * - Admin endpoints require Bearer token authentication
 * - /Me endpoints use User Access Token (extracts sub from JWT)
 * - /Me restricts updates to safe fields only (name, locale, zoneinfo)
 * - SOC2-compliant structured audit logging
 * - Token revocation on user deactivation
 *
 * @module governance/scim_v2
 * @see RFC 7643 - SCIM Core Schema
 * @see RFC 7644 - SCIM Protocol
 */

import type { APIGatewayProxyEventV2, APIGatewayProxyResultV2, Context } from 'aws-lambda';
import { DynamoDBClient } from '@aws-sdk/client-dynamodb';
import { DynamoDBDocumentClient } from '@aws-sdk/lib-dynamodb';
import { createLogger, withContext } from '@oauth-server/shared';
import type { EnvConfig, ScimUserCreateRequest, ScimPatchRequest } from './types';
import { handlePostUser } from './post-user';
import { handleGetUser } from './get-user';
import { handlePatchUser } from './patch-user';
import { handleGetMe, handlePatchMe } from './me';
import { scimBadRequest, scimServerError, scimUnauthorized } from './responses';

// =============================================================================
// Environment Configuration
// =============================================================================

function getEnvConfig(): EnvConfig {
    const tableName = process.env.TABLE_NAME;
    const issuer = process.env.ISSUER;

    if (!tableName) throw new Error('TABLE_NAME environment variable is required');
    if (!issuer) throw new Error('ISSUER environment variable is required');

    // SCIM base URL derived from issuer
    const scimBaseUrl = `${issuer}/scim/v2`;

    return { tableName, issuer, scimBaseUrl };
}

// =============================================================================
// DynamoDB Client (Singleton)
// =============================================================================

let docClient: DynamoDBDocumentClient | null = null;

function getDocClient(): DynamoDBDocumentClient {
    if (!docClient) {
        const client = new DynamoDBClient({});
        docClient = DynamoDBDocumentClient.from(client, {
            marshallOptions: { removeUndefinedValues: true },
        });
    }
    return docClient;
}

// =============================================================================
// Request Parsing
// =============================================================================

/**
 * Extract user ID from path parameters.
 * Path: /scim/v2/Users/{id}
 */
function extractUserId(event: APIGatewayProxyEventV2): string | undefined {
    return event.pathParameters?.id;
}

/**
 * Parse JSON request body.
 */
function parseJsonBody<T>(event: APIGatewayProxyEventV2): T | null {
    try {
        let body = event.body || '{}';
        if (event.isBase64Encoded) {
            body = Buffer.from(body, 'base64').toString('utf-8');
        }
        return JSON.parse(body) as T;
    } catch {
        return null;
    }
}

/**
 * Validate Bearer token authentication.
 * In production, this should validate against an access token.
 * For now, we just check that a Bearer token is present.
 */
function validateAuth(authHeader: string | undefined): boolean {
    if (!authHeader) {
        return false;
    }
    return authHeader.toLowerCase().startsWith('bearer ');
}

/**
 * Extract user ID (sub) from Bearer token for /Me endpoint.
 * Decodes the JWT payload without verification (verification should be done by API Gateway or middleware).
 *
 * @param authHeader - Authorization header value
 * @returns User ID (sub) or null if extraction fails
 */
function extractUserIdFromToken(authHeader: string | undefined): string | null {
    if (!authHeader || !authHeader.toLowerCase().startsWith('bearer ')) {
        return null;
    }

    const token = authHeader.substring(7).trim();
    if (!token) {
        return null;
    }

    try {
        // JWT format: header.payload.signature
        const parts = token.split('.');
        if (parts.length !== 3) {
            return null;
        }

        // Decode payload (base64url)
        const payloadBase64 = parts[1]
            .replace(/-/g, '+')
            .replace(/_/g, '/');
        const payloadJson = Buffer.from(payloadBase64, 'base64').toString('utf-8');
        const payload = JSON.parse(payloadJson) as { sub?: string };

        return payload.sub || null;
    } catch {
        return null;
    }
}

/**
 * Check if the request path is for /Me endpoint.
 */
function isMeEndpoint(path: string): boolean {
    return path.toLowerCase().endsWith('/me') || path.toLowerCase().includes('/me/');
}

// =============================================================================
// CORS Headers
// =============================================================================

const CORS_HEADERS = {
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'GET, POST, PATCH, DELETE, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization',
    'Access-Control-Max-Age': '86400',
} as const;

function withCors(response: APIGatewayProxyResultV2): APIGatewayProxyResultV2 {
    if (typeof response === 'string') {
        return response;
    }
    return {
        ...response,
        headers: {
            ...response.headers,
            ...CORS_HEADERS,
        },
    };
}

// =============================================================================
// Lambda Handler
// =============================================================================

/**
 * SCIM v2 User Provisioning handler.
 */
export const handler = async (
    event: APIGatewayProxyEventV2,
    context: Context
): Promise<APIGatewayProxyResultV2> => {
    const logger = createLogger(event, context);
    const audit = withContext(event, context);
    const requestId = context.awsRequestId;

    try {
        const config = getEnvConfig();
        const method = event.requestContext.http.method;
        const path = event.requestContext.http.path;

        logger.info('SCIM request received', { method, path });

        // Handle CORS preflight
        if (method === 'OPTIONS') {
            return withCors({
                statusCode: 204,
                headers: {},
                body: '',
            });
        }

        // Validate authentication
        const authHeader = event.headers?.['authorization'];
        if (!validateAuth(authHeader)) {
            return withCors(scimUnauthorized());
        }

        const client = getDocClient();

        let response: APIGatewayProxyResultV2;

        // Route /Me endpoints (RFC 7644 Section 3.11)
        if (isMeEndpoint(path)) {
            const tokenUserId = extractUserIdFromToken(authHeader);
            if (!tokenUserId) {
                response = scimUnauthorized('Invalid or missing user identity in token');
                return withCors(response);
            }

            switch (method) {
                case 'GET': {
                    // GET /scim/v2/Me - Retrieve authenticated user's profile
                    response = await handleGetMe(tokenUserId, config, client);
                    break;
                }

                case 'PATCH': {
                    // PATCH /scim/v2/Me - Update authenticated user's profile
                    const contentType = event.headers?.['content-type'] || '';
                    if (!contentType.includes('application/json') && !contentType.includes('application/scim+json')) {
                        response = scimBadRequest('Content-Type must be application/json or application/scim+json');
                        break;
                    }

                    const body = parseJsonBody<ScimPatchRequest>(event);
                    if (!body) {
                        response = scimBadRequest('Invalid JSON body', 'invalidSyntax');
                        break;
                    }

                    response = await handlePatchMe(tokenUserId, body, config, client, audit, requestId);
                    break;
                }

                default:
                    response = scimBadRequest('Method not allowed for /Me endpoint. Use GET or PATCH.');
            }

            return withCors(response);
        }

        // Route /Users endpoints
        const userId = extractUserId(event);

        switch (method) {
            case 'POST': {
                // POST /scim/v2/Users - Create user
                const contentType = event.headers?.['content-type'] || '';
                if (!contentType.includes('application/json') && !contentType.includes('application/scim+json')) {
                    response = scimBadRequest('Content-Type must be application/json or application/scim+json');
                    break;
                }

                const body = parseJsonBody<ScimUserCreateRequest>(event);
                if (!body) {
                    response = scimBadRequest('Invalid JSON body', 'invalidSyntax');
                    break;
                }

                response = await handlePostUser(body, config, client, audit);
                break;
            }

            case 'GET': {
                // GET /scim/v2/Users/{id} - Read user
                if (!userId) {
                    response = scimBadRequest('Missing user ID in path');
                    break;
                }
                response = await handleGetUser(userId, config, client);
                break;
            }

            case 'PATCH': {
                // PATCH /scim/v2/Users/{id} - Update user
                if (!userId) {
                    response = scimBadRequest('Missing user ID in path');
                    break;
                }

                const contentType = event.headers?.['content-type'] || '';
                if (!contentType.includes('application/json') && !contentType.includes('application/scim+json')) {
                    response = scimBadRequest('Content-Type must be application/json or application/scim+json');
                    break;
                }

                const body = parseJsonBody<ScimPatchRequest>(event);
                if (!body) {
                    response = scimBadRequest('Invalid JSON body', 'invalidSyntax');
                    break;
                }

                response = await handlePatchUser(userId, body, config, client, audit, requestId);
                break;
            }

            default:
                response = scimBadRequest('Method not allowed');
        }

        return withCors(response);
    } catch (err) {
        const e = err as Error;
        logger.error('SCIM endpoint error', { error: e.message, stack: e.stack });
        return withCors(scimServerError());
    }
};
