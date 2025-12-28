/**
 * RFC 7591/7592 Dynamic Client Registration - Lambda Handler
 *
 * Implements OAuth 2.0 Dynamic Client Registration Protocol endpoints:
 * - POST /connect/register - Create client (RFC 7591)
 * - GET /connect/register/:clientId - Read client (RFC 7592)
 * - PUT /connect/register/:clientId - Update client (RFC 7592)
 * - DELETE /connect/register/:clientId - Delete client (RFC 7592)
 *
 * Security:
 * - POST requires Initial Access Token or is open (configurable)
 * - GET/PUT/DELETE require Registration Access Token
 *
 * @module governance/client_registry
 * @see RFC 7591 - OAuth 2.0 Dynamic Client Registration Protocol
 * @see RFC 7592 - OAuth 2.0 Dynamic Client Registration Management Protocol
 */

import type { APIGatewayProxyEventV2, APIGatewayProxyResultV2, Context } from 'aws-lambda';
import { DynamoDBClient } from '@aws-sdk/client-dynamodb';
import { DynamoDBDocumentClient } from '@aws-sdk/lib-dynamodb';
import { createLogger, withContext, serverError, error, corsPreflight, withCors } from '@oauth-server/shared';
import type { EnvConfig, ClientRegistrationRequest } from './types';
import { handleCreateClient } from './create';
import { handleReadClient } from './read';
import { handleUpdateClient } from './update';
import { handleDeleteClient } from './delete';

// =============================================================================
// Environment Configuration
// =============================================================================

function getEnvConfig(): EnvConfig {
    const tableName = process.env.TABLE_NAME;
    const issuer = process.env.ISSUER;

    if (!tableName) throw new Error('TABLE_NAME environment variable is required');
    if (!issuer) throw new Error('ISSUER environment variable is required');

    // Registration endpoint is derived from issuer
    const registrationEndpoint = `${issuer}/connect/register`;

    return { tableName, issuer, registrationEndpoint };
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
 * Extract client_id from path parameters.
 * Path: /connect/register/{clientId}
 */
function extractClientId(event: APIGatewayProxyEventV2): string | undefined {
    return event.pathParameters?.clientId;
}

/**
 * Parse JSON request body.
 */
function parseJsonBody(event: APIGatewayProxyEventV2): ClientRegistrationRequest | null {
    try {
        let body = event.body || '{}';
        if (event.isBase64Encoded) {
            body = Buffer.from(body, 'base64').toString('utf-8');
        }
        return JSON.parse(body);
    } catch {
        return null;
    }
}



// =============================================================================
// Lambda Handler
// =============================================================================

/**
 * RFC 7591/7592 Dynamic Client Registration handler.
 */
export const handler = async (
    event: APIGatewayProxyEventV2,
    context: Context
): Promise<APIGatewayProxyResultV2> => {
    const logger = createLogger(event, context);
    const audit = withContext(event, context);

    try {
        const config = getEnvConfig();
        const method = event.requestContext.http.method;
        const path = event.requestContext.http.path;

        logger.info('Client registry request received', { method, path });

        // Handle CORS preflight
        if (method === 'OPTIONS') {
            return corsPreflight('*');
        }

        const client = getDocClient();
        const authHeader = event.headers?.['authorization'];
        const clientId = extractClientId(event);

        let response: APIGatewayProxyResultV2;

        switch (method) {
            case 'POST': {
                // POST /connect/register - Create client
                const contentType = event.headers?.['content-type'] || '';
                if (!contentType.includes('application/json')) {
                    response = error(400, 'invalid_request', 'Content-Type must be application/json');
                    break;
                }

                const body = parseJsonBody(event);
                if (!body) {
                    response = error(400, 'invalid_request', 'Invalid JSON body');
                    break;
                }

                response = await handleCreateClient(body, config, client, audit);
                break;
            }

            case 'GET': {
                // GET /connect/register/:clientId - Read client
                if (!clientId) {
                    response = error(400, 'invalid_request', 'Missing client_id in path');
                    break;
                }
                response = await handleReadClient(clientId, authHeader, config, client, audit);
                break;
            }

            case 'PUT': {
                // PUT /connect/register/:clientId - Update client
                if (!clientId) {
                    response = error(400, 'invalid_request', 'Missing client_id in path');
                    break;
                }

                const contentType = event.headers?.['content-type'] || '';
                if (!contentType.includes('application/json')) {
                    response = error(400, 'invalid_request', 'Content-Type must be application/json');
                    break;
                }

                const body = parseJsonBody(event);
                if (!body) {
                    response = error(400, 'invalid_request', 'Invalid JSON body');
                    break;
                }

                response = await handleUpdateClient(clientId, body, authHeader, config, client, audit);
                break;
            }

            case 'DELETE': {
                // DELETE /connect/register/:clientId - Delete client
                if (!clientId) {
                    response = error(400, 'invalid_request', 'Missing client_id in path');
                    break;
                }
                response = await handleDeleteClient(clientId, authHeader, config, client, audit);
                break;
            }

            default:
                response = error(405, 'invalid_request', 'Method not allowed');
        }

        // Add CORS headers
        return withCors(response as Exclude<APIGatewayProxyResultV2, string>, '*');
    } catch (err) {
        const e = err as Error;
        logger.error('Client registry error', { error: e.message, stack: e.stack });
        return serverError('An unexpected error occurred');
    }
};
