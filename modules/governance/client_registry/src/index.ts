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
import { createLogger, withContext, serverError, error, corsPreflight, withCors, timingSafeStringEqual } from '@oauth-server/shared';
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

    // Initial Access Token for protecting open registration (RFC 7591 Section 1.2)
    const initialAccessToken = process.env.INITIAL_ACCESS_TOKEN;
    const allowOpenRegistration = process.env.ALLOW_OPEN_REGISTRATION === 'true';

    return { tableName, issuer, registrationEndpoint, initialAccessToken, allowOpenRegistration };
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
// Initial Access Token Validation (RFC 7591 Section 1.2)
// =============================================================================

interface IatValidationResult {
    valid: boolean;
    error?: string;
}

/**
 * Validate Initial Access Token for client registration.
 *
 * Per RFC 7591 Section 1.2, the authorization server MAY require an
 * Initial Access Token to protect the registration endpoint from
 * unauthorized access.
 *
 * Security:
 * - Uses constant-time comparison to prevent timing attacks
 * - Supports both open registration and protected registration modes
 *
 * @param authHeader - Authorization header from request
 * @param config - Environment configuration
 * @returns Validation result
 */
function validateInitialAccessToken(
    authHeader: string | undefined,
    config: EnvConfig
): IatValidationResult {
    // If no Initial Access Token is configured and open registration is allowed
    if (!config.initialAccessToken && config.allowOpenRegistration) {
        return { valid: true };
    }

    // If Initial Access Token is configured, it MUST be provided
    if (config.initialAccessToken) {
        if (!authHeader) {
            return { valid: false, error: 'Initial Access Token required for client registration' };
        }

        // Extract Bearer token
        const match = authHeader.match(/^Bearer\s+(.+)$/i);
        if (!match) {
            return { valid: false, error: 'Invalid Authorization header format. Use: Bearer <token>' };
        }

        const providedToken = match[1];

        // Constant-time comparison to prevent timing attacks
        if (!timingSafeStringEqual(providedToken, config.initialAccessToken)) {
            return { valid: false, error: 'Invalid Initial Access Token' };
        }

        return { valid: true };
    }

    // No Initial Access Token configured and open registration not allowed
    return { valid: false, error: 'Client registration is not available' };
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
            // Use configured allowed origins or restrict to issuer domain
            const allowedOrigin = config.issuer;
            return corsPreflight(allowedOrigin);
        }

        const client = getDocClient();
        const authHeader = event.headers?.['authorization'];
        const clientId = extractClientId(event);

        let response: APIGatewayProxyResultV2;

        switch (method) {
            case 'POST': {
                // POST /connect/register - Create client
                // RFC 7591 Section 1.2: Initial Access Token protection
                const iatValidation = validateInitialAccessToken(authHeader, config);
                if (!iatValidation.valid) {
                    audit.log({
                        action: 'CLIENT_REGISTRATION_DENIED',
                        actor: { type: 'ANONYMOUS' },
                        details: { reason: iatValidation.error },
                    });
                    response = error(401, 'invalid_token', iatValidation.error || 'Invalid or missing Initial Access Token');
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

        // Add CORS headers (restrict to issuer domain for security)
        const allowedOrigin = config.issuer;
        return withCors(response as Exclude<APIGatewayProxyResultV2, string>, allowedOrigin);
    } catch (err) {
        const e = err as Error;
        logger.error('Client registry error', { error: e.message, stack: e.stack });
        return serverError('An unexpected error occurred');
    }
};
