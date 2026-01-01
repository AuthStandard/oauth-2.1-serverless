/**
 * OAuth 2.1 Token Revocation Endpoint (RFC 7009)
 *
 * Enables clients to notify the authorization server that a previously obtained
 * token is no longer needed, allowing the server to clean up associated data.
 *
 * Request: POST /revoke (application/x-www-form-urlencoded)
 *   - token (REQUIRED): The token to revoke
 *   - token_type_hint (OPTIONAL): "refresh_token" | "access_token" - optimization hint
 *
 * Response (RFC 7009 Section 2.2):
 *   - HTTP 200 OK with empty body for all outcomes (success, invalid, or unknown token)
 *   - Uniform response prevents token enumeration attacks
 *
 * Security Controls:
 *   - Client authentication required for confidential clients (RFC 7009 Section 2.1)
 *   - Public clients identified by client_id parameter
 *   - Token ownership verification prevents cross-client revocation
 *   - Constant-time secret comparison via shared auth module (RFC 9700 Section 4.8.2)
 *
 * Implementation Notes:
 *   - Access tokens are stateless JWTs and cannot be revoked server-side
 *   - Only refresh tokens (stored in DynamoDB) support revocation
 *   - Access token revocation requests return 200 OK per RFC 7009 Section 2.2
 *   - Use short access token TTLs for effective access control
 *
 * @see https://datatracker.ietf.org/doc/html/rfc7009
 * @see https://datatracker.ietf.org/doc/html/rfc9700
 */

import type { APIGatewayProxyEventV2, APIGatewayProxyResultV2, Context } from 'aws-lambda';
import { DynamoDBClient } from '@aws-sdk/client-dynamodb';
import { DynamoDBDocumentClient, GetCommand, UpdateCommand } from '@aws-sdk/lib-dynamodb';
import {
    hashToken,
    invalidRequest,
    serverError,
    createLogger,
    withContext,
    authenticateClient,
} from '@oauth-server/shared';

// =============================================================================
// Types
// =============================================================================

/** Refresh token record structure from DynamoDB */
interface RefreshTokenRecord {
    readonly tokenHash: string;
    readonly clientId: string;
    readonly sub: string;
    readonly scope: string;
    readonly familyId: string;
    readonly rotated: boolean;
    readonly rotatedAt?: string;
    readonly revokedAt?: string;
    readonly revokedReason?: string;
    readonly ttl?: number;
}

// =============================================================================
// Environment Configuration
// =============================================================================

interface EnvConfig {
    readonly tableName: string;
}

/** Cached configuration to avoid repeated env lookups */
let envConfig: EnvConfig | null = null;

/**
 * Load and validate environment configuration.
 * All values are injected by Terraform - no hardcoded defaults.
 * @throws Error if required environment variables are missing
 */
function getEnvConfig(): EnvConfig {
    if (envConfig) return envConfig;

    const tableName = process.env.TABLE_NAME;
    if (!tableName) throw new Error('TABLE_NAME environment variable is required');

    envConfig = { tableName };
    return envConfig;
}

// =============================================================================
// DynamoDB Client
// =============================================================================

/** Cached client for Lambda container reuse */
let docClient: DynamoDBDocumentClient | null = null;

function getDocClient(): DynamoDBDocumentClient {
    if (!docClient) {
        docClient = DynamoDBDocumentClient.from(new DynamoDBClient({}), {
            marshallOptions: { removeUndefinedValues: true },
        });
    }
    return docClient;
}

// =============================================================================
// Constants
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
 * Standard headers for revocation responses.
 * Per RFC 7009 Section 2.2, the response body is empty, so no Content-Type is needed.
 * Cache-Control: no-store is required per OAuth 2.1 for all token-related responses.
 */
const REVOCATION_HEADERS = {
    'Cache-Control': 'no-store',
    'Pragma': 'no-cache',
    ...SECURITY_HEADERS,
} as const;

// =============================================================================
// Response Helpers
// =============================================================================

/**
 * RFC 7009 Section 2.2 compliant success response.
 *
 * Returns HTTP 200 OK with empty JSON body regardless of outcome.
 * This uniform response prevents token enumeration attacks by not
 * revealing whether a token existed or was successfully revoked.
 */
function revocationSuccess(): APIGatewayProxyResultV2 {
    return {
        statusCode: 200,
        headers: REVOCATION_HEADERS,
        body: '',
    };
}

// =============================================================================
// Lambda Handler
// =============================================================================

export const handler = async (
    event: APIGatewayProxyEventV2,
    context: Context
): Promise<APIGatewayProxyResultV2> => {
    const logger = createLogger(event, context);
    const auditLogger = withContext(event, context);

    try {
        logger.info('Revocation request received');

        // RFC 7009 Section 2.1: Must be POST
        if (event.requestContext.http.method !== 'POST') {
            return invalidRequest('Method not allowed');
        }

        // Validate Content-Type per RFC 7009 Section 2.1 (v2 headers are lowercase)
        const contentType = event.headers?.['content-type'] || '';
        if (!contentType.includes('application/x-www-form-urlencoded')) {
            return invalidRequest('Content-Type must be application/x-www-form-urlencoded');
        }

        // Parse request body
        let body = event.body || '';
        if (event.isBase64Encoded) {
            body = Buffer.from(body, 'base64').toString('utf8');
        }
        const params = new URLSearchParams(body);

        // RFC 7009 Section 2.1: token parameter is required
        const token = params.get('token');
        if (!token) {
            return invalidRequest('Missing required parameter: token');
        }

        // RFC 7009 Section 2.1: token_type_hint is optional (used for logging only)
        const tokenTypeHint = params.get('token_type_hint');

        const config = getEnvConfig();
        const client = getDocClient();
        const authHeader = event.headers?.['authorization'];

        // RFC 7009 Section 2.1: Client authentication required
        const authResult = await authenticateClient(params, authHeader, client, config.tableName);
        if (!authResult.valid) {
            return authResult.error!;
        }

        // Hash the token for DynamoDB lookup
        const tokenHash = hashToken(token);

        // Attempt to find and revoke the refresh token
        // RFC 7009 Section 2.2: Always return 200 OK (prevents enumeration)
        const refreshResult = await client.send(
            new GetCommand({
                TableName: config.tableName,
                Key: { PK: `REFRESH#${tokenHash}`, SK: 'METADATA' },
            })
        );

        if (refreshResult.Item) {
            const refreshToken = refreshResult.Item as RefreshTokenRecord;

            // Verify token ownership (prevents cross-client revocation)
            if (refreshToken.clientId !== authResult.clientItem!.clientId) {
                logger.warn('Token revocation denied - client mismatch', {
                    tokenClientId: refreshToken.clientId,
                    requestClientId: authResult.clientItem!.clientId,
                });
                // RFC 7009 Section 2.2: Return 200 OK to prevent enumeration
                return revocationSuccess();
            }

            // Revoke the token if not already revoked
            if (!refreshToken.rotated) {
                try {
                    await client.send(
                        new UpdateCommand({
                            TableName: config.tableName,
                            Key: { PK: `REFRESH#${tokenHash}`, SK: 'METADATA' },
                            UpdateExpression: 'SET rotated = :true, rotatedAt = :now, revokedAt = :now, revokedReason = :reason, updatedAt = :now',
                            ConditionExpression: 'rotated = :false',
                            ExpressionAttributeValues: {
                                ':true': true,
                                ':false': false,
                                ':now': new Date().toISOString(),
                                ':reason': 'client_revocation',
                            },
                        })
                    );

                    logger.info('Refresh token revoked', {
                        clientId: authResult.clientItem!.clientId,
                        sub: refreshToken.sub,
                    });

                    auditLogger.tokenRevoked(
                        { type: 'CLIENT', clientId: authResult.clientItem!.clientId },
                        {
                            tokenType: 'refresh_token',
                            reason: 'client_revocation',
                            tokenHint: refreshToken.familyId,
                        }
                    );
                } catch (err) {
                    // ConditionalCheckFailedException means token was already revoked
                    if ((err as Error).name !== 'ConditionalCheckFailedException') {
                        throw err;
                    }
                    logger.info('Token already revoked (concurrent request)');
                }
            } else {
                logger.info('Token already revoked', {
                    clientId: authResult.clientItem!.clientId,
                });
            }
        } else {
            // Token not found - could be access token (JWT) or invalid token
            // Access tokens are stateless JWTs and cannot be revoked server-side
            // RFC 7009 Section 2.2: Return 200 OK regardless
            logger.info('Token not found (may be access token or invalid)', {
                clientId: authResult.clientItem!.clientId,
                tokenTypeHint: tokenTypeHint || 'none',
            });
        }

        // RFC 7009 Section 2.2: Return 200 OK with empty body
        return revocationSuccess();
    } catch (err) {
        const error = err as Error;
        logger.error('Revocation endpoint error', { error: error.message, stack: error.stack });
        return serverError('An unexpected error occurred');
    }
};
