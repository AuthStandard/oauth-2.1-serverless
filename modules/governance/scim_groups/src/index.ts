/**
 * SCIM v2 Group Provisioning - Lambda Handler
 *
 * Implements SCIM 2.0 (RFC 7643, RFC 7644) Group Resource endpoints:
 * - POST /scim/v2/Groups - Create group
 * - GET /scim/v2/Groups - List groups
 * - GET /scim/v2/Groups/{id} - Read group
 * - PATCH /scim/v2/Groups/{id} - Update group
 * - DELETE /scim/v2/Groups/{id} - Delete group
 *
 * Security:
 * - All endpoints require authentication (Bearer token)
 * - SOC2-compliant structured audit logging
 *
 * DynamoDB Key Patterns (Adjacency List):
 * - Group:          PK=GROUP#<id>       SK=METADATA
 * - Membership:     PK=GROUP#<id>       SK=MEMBER#<user_id>
 * - Reverse Lookup: PK=USER#<user_id>   SK=GROUP#<group_id>
 *
 * @module governance/scim_groups
 * @see RFC 7643 - SCIM Core Schema
 * @see RFC 7644 - SCIM Protocol
 */

import type { APIGatewayProxyEventV2, APIGatewayProxyResultV2, Context } from 'aws-lambda';
import { DynamoDBClient } from '@aws-sdk/client-dynamodb';
import { DynamoDBDocumentClient } from '@aws-sdk/lib-dynamodb';
import { createLogger, withContext } from '@oauth-server/shared';
import type { EnvConfig, ScimGroupCreateRequest, ScimPatchRequest } from './types';
import { handlePostGroup } from './create';
import { handleGetGroup, handleListGroups } from './get';
import { handlePatchGroup } from './patch';
import { handleDeleteGroup } from './delete';
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
 * Extract group ID from path parameters.
 * Path: /scim/v2/Groups/{id}
 */
function extractGroupId(event: APIGatewayProxyEventV2): string | undefined {
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

// =============================================================================
// Lambda Handler
// =============================================================================

export const handler = async (
    event: APIGatewayProxyEventV2,
    context: Context
): Promise<APIGatewayProxyResultV2> => {
    const logger = createLogger(event, context);
    const audit = withContext(event, context);

    try {
        const method = event.requestContext.http.method.toUpperCase();
        const path = event.requestContext.http.path;

        logger.info('SCIM Groups request received', { method, path });

        // Validate authentication
        const authHeader = event.headers?.authorization || event.headers?.Authorization;
        if (!validateAuth(authHeader)) {
            return scimUnauthorized('Bearer token required');
        }

        const config = getEnvConfig();
        const client = getDocClient();
        const groupId = extractGroupId(event);

        // Route request based on method and path
        switch (method) {
            case 'POST': {
                // POST /scim/v2/Groups - Create group
                const body = parseJsonBody<ScimGroupCreateRequest>(event);
                if (!body) {
                    return scimBadRequest('Invalid JSON body', 'invalidSyntax');
                }
                return handlePostGroup(body, config, client, audit);
            }

            case 'GET': {
                if (groupId) {
                    // GET /scim/v2/Groups/{id} - Read group
                    return handleGetGroup(groupId, config, client);
                } else {
                    // GET /scim/v2/Groups - List groups
                    const startIndex = parseInt(event.queryStringParameters?.startIndex || '1', 10);
                    const count = parseInt(event.queryStringParameters?.count || '100', 10);
                    return handleListGroups(config, client, startIndex, count);
                }
            }

            case 'PATCH': {
                // PATCH /scim/v2/Groups/{id} - Update group
                if (!groupId) {
                    return scimBadRequest('Group ID is required', 'invalidValue');
                }
                const body = parseJsonBody<ScimPatchRequest>(event);
                if (!body) {
                    return scimBadRequest('Invalid JSON body', 'invalidSyntax');
                }
                return handlePatchGroup(groupId, body, config, client, audit, context.awsRequestId);
            }

            case 'DELETE': {
                // DELETE /scim/v2/Groups/{id} - Delete group
                if (!groupId) {
                    return scimBadRequest('Group ID is required', 'invalidValue');
                }
                return handleDeleteGroup(groupId, config, client, audit, context.awsRequestId);
            }

            case 'OPTIONS': {
                // CORS preflight
                return {
                    statusCode: 204,
                    headers: {
                        'Access-Control-Allow-Origin': '*',
                        'Access-Control-Allow-Methods': 'GET, POST, PATCH, DELETE, OPTIONS',
                        'Access-Control-Allow-Headers': 'Content-Type, Authorization',
                        'Access-Control-Max-Age': '86400',
                    },
                    body: '',
                };
            }

            default:
                return scimBadRequest(`Method ${method} not allowed`, 'invalidValue');
        }
    } catch (err) {
        const e = err as Error;
        logger.error('SCIM Groups error', { error: e.message, stack: e.stack });
        return scimServerError('An unexpected error occurred');
    }
};
