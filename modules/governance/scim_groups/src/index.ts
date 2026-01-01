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
 * Security (Enterprise-Grade):
 * - All endpoints require valid JWT with scim:groups scope
 * - JWT signature verified against KMS public key
 * - Token expiration, iat, and audience validation
 * - Token revocation check
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
import { KMSClient, GetPublicKeyCommand } from '@aws-sdk/client-kms';
import { createVerify } from 'node:crypto';
import { createLogger, withContext, base64UrlDecode } from '@oauth-server/shared';
import type { EnvConfig, ScimGroupCreateRequest, ScimPatchRequest } from './types';
import { handlePostGroup } from './create';
import { handleGetGroup, handleListGroups } from './get';
import { handlePatchGroup } from './patch';
import { handleDeleteGroup } from './delete';
import { scimBadRequest, scimServerError, scimUnauthorized, scimForbidden } from './responses';

// =============================================================================
// Environment Configuration
// =============================================================================

function getEnvConfig(): EnvConfig {
    const tableName = process.env.TABLE_NAME;
    const issuer = process.env.ISSUER;
    const kmsKeyId = process.env.KMS_KEY_ID;

    if (!tableName) throw new Error('TABLE_NAME environment variable is required');
    if (!issuer) throw new Error('ISSUER environment variable is required');
    if (!kmsKeyId) throw new Error('KMS_KEY_ID environment variable is required');

    // SCIM base URL derived from issuer
    const scimBaseUrl = `${issuer}/scim/v2`;

    return { tableName, issuer, scimBaseUrl, kmsKeyId };
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
// KMS Client & Public Key Cache
// =============================================================================

let kmsClient: KMSClient | null = null;
let publicKeyCache: { pem: string; keyId: string } | null = null;

function getKmsClient(): KMSClient {
    if (!kmsClient) kmsClient = new KMSClient({});
    return kmsClient;
}

async function getPublicKey(kmsKeyId: string): Promise<string> {
    if (publicKeyCache?.keyId === kmsKeyId) return publicKeyCache.pem;

    const result = await getKmsClient().send(new GetPublicKeyCommand({ KeyId: kmsKeyId }));
    if (!result.PublicKey) throw new Error('KMS returned no public key');

    const base64Key = Buffer.from(result.PublicKey).toString('base64');
    const pemLines = base64Key.match(/.{1,64}/g) ?? [];
    const pem = `-----BEGIN PUBLIC KEY-----\n${pemLines.join('\n')}\n-----END PUBLIC KEY-----`;

    publicKeyCache = { pem, keyId: kmsKeyId };
    return pem;
}

// =============================================================================
// JWT Token Verification - Enterprise Grade
// =============================================================================

/** Maximum allowed clock skew for iat validation (5 minutes) */
const MAX_CLOCK_SKEW_SECONDS = 300;

/** Maximum token age from iat to prevent replay attacks (24 hours) */
const MAX_TOKEN_AGE_SECONDS = 86400;

/** Required scope for SCIM Group operations */
const SCIM_GROUPS_SCOPE = 'scim:groups';

interface AccessTokenPayload {
    readonly iss: string;
    readonly sub: string;
    readonly aud: string | readonly string[];
    readonly exp: number;
    readonly iat: number;
    readonly scope: string;
    readonly client_id: string;
    readonly jti?: string;
}

interface TokenValidationResult {
    readonly valid: boolean;
    readonly payload?: AccessTokenPayload;
    readonly error?: string;
}

/**
 * Enterprise-grade access token verification.
 */
function verifyAccessToken(
    token: string,
    publicKey: string,
    expectedIssuer: string
): TokenValidationResult {
    const parts = token.split('.');
    if (parts.length !== 3) {
        return { valid: false, error: 'Malformed JWT' };
    }

    const [headerB64, payloadB64, signatureB64] = parts;

    try {
        const header = JSON.parse(base64UrlDecode(headerB64).toString('utf8')) as { alg?: string };
        if (header.alg !== 'RS256') {
            return { valid: false, error: `Unsupported algorithm: ${header.alg}` };
        }

        const payload = JSON.parse(base64UrlDecode(payloadB64).toString('utf8')) as AccessTokenPayload;

        const verifier = createVerify('RSA-SHA256');
        verifier.update(`${headerB64}.${payloadB64}`);
        if (!verifier.verify(publicKey, base64UrlDecode(signatureB64))) {
            return { valid: false, error: 'Invalid signature' };
        }

        const now = Math.floor(Date.now() / 1000);

        if (!payload.exp || payload.exp <= now) {
            return { valid: false, error: 'Token has expired' };
        }

        if (!payload.iat) {
            return { valid: false, error: 'Missing iat claim' };
        }
        if (payload.iat > now + MAX_CLOCK_SKEW_SECONDS) {
            return { valid: false, error: 'Token issued in the future' };
        }

        const tokenAge = now - payload.iat;
        if (tokenAge > MAX_TOKEN_AGE_SECONDS) {
            return { valid: false, error: 'Token exceeds maximum age' };
        }

        if (payload.iss !== expectedIssuer) {
            return { valid: false, error: 'Invalid issuer' };
        }

        const audiences = Array.isArray(payload.aud) ? payload.aud : [payload.aud];
        if (!audiences.includes(expectedIssuer)) {
            return { valid: false, error: 'Token not intended for this audience' };
        }

        return { valid: true, payload };
    } catch (e) {
        const error = e as Error;
        return { valid: false, error: `Token parsing failed: ${error.message}` };
    }
}

function hasRequiredScope(payload: AccessTokenPayload, requiredScope: string): boolean {
    const tokenScopes = payload.scope.split(' ').filter(s => s.length > 0);
    return tokenScopes.includes(requiredScope);
}

async function isTokenRevoked(
    jti: string | undefined,
    client: DynamoDBDocumentClient,
    tableName: string
): Promise<boolean> {
    if (!jti) return false;

    try {
        const { GetCommand } = await import('@aws-sdk/lib-dynamodb');
        const result = await client.send(
            new GetCommand({
                TableName: tableName,
                Key: { PK: `TOKEN#${jti}`, SK: 'REVOKED' },
                ProjectionExpression: 'revokedAt',
            })
        );
        return !!result.Item;
    } catch {
        return false;
    }
}

// =============================================================================
// CORS Headers
// =============================================================================

/**
 * CORS headers for SCIM endpoints.
 * Required for browser-based SCIM clients.
 */
const CORS_HEADERS = {
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'GET, POST, PATCH, DELETE, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization',
    'Access-Control-Max-Age': '86400',
} as const;

/**
 * Add CORS headers to a response.
 *
 * @param response - API Gateway response
 * @returns Response with CORS headers
 */
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
// Request Parsing
// =============================================================================

function extractGroupId(event: APIGatewayProxyEventV2): string | undefined {
    return event.pathParameters?.id;
}

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

        // Handle CORS preflight
        if (method === 'OPTIONS') {
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

        // =====================================================================
        // Authentication & Authorization (Enterprise-Grade)
        // =====================================================================

        const authHeader = event.headers?.authorization || event.headers?.Authorization;
        if (!authHeader || !authHeader.toLowerCase().startsWith('bearer ')) {
            audit.log({
                action: 'CLIENT_AUTH_FAILED',
                actor: { type: 'ANONYMOUS' },
                details: { reason: 'missing_bearer_token', path },
            });
            return withCors(scimUnauthorized('Missing or invalid Authorization header'));
        }

        const token = authHeader.slice(7);
        const config = getEnvConfig();

        const publicKey = await getPublicKey(config.kmsKeyId);
        const validationResult = verifyAccessToken(token, publicKey, config.issuer);

        if (!validationResult.valid || !validationResult.payload) {
            logger.warn('Access token verification failed', { error: validationResult.error });
            audit.log({
                action: 'CLIENT_AUTH_FAILED',
                actor: { type: 'ANONYMOUS' },
                details: { reason: validationResult.error, path },
            });
            return withCors(scimUnauthorized(validationResult.error || 'Invalid access token'));
        }

        const tokenPayload = validationResult.payload;
        const client = getDocClient();

        const revoked = await isTokenRevoked(tokenPayload.jti, client, config.tableName);
        if (revoked) {
            logger.warn('Revoked token used', { sub: tokenPayload.sub, jti: tokenPayload.jti });
            audit.log({
                action: 'CLIENT_AUTH_FAILED',
                actor: { type: 'USER', sub: tokenPayload.sub },
                details: { reason: 'token_revoked', jti: tokenPayload.jti },
            });
            return withCors(scimUnauthorized('Token has been revoked'));
        }

        // Scope validation
        if (!hasRequiredScope(tokenPayload, SCIM_GROUPS_SCOPE)) {
            logger.warn('Insufficient scope', { sub: tokenPayload.sub, scope: tokenPayload.scope });
            audit.log({
                action: 'CLIENT_AUTH_FAILED',
                actor: { type: 'USER', sub: tokenPayload.sub },
                details: { reason: 'insufficient_scope', required: SCIM_GROUPS_SCOPE, provided: tokenPayload.scope },
            });
            return withCors(scimForbidden(`Required scope: ${SCIM_GROUPS_SCOPE}`));
        }

        const groupId = extractGroupId(event);
        let response: APIGatewayProxyResultV2;

        // Route request
        switch (method) {
            case 'POST': {
                const body = parseJsonBody<ScimGroupCreateRequest>(event);
                if (!body) {
                    return withCors(scimBadRequest('Invalid JSON body', 'invalidSyntax'));
                }
                response = await handlePostGroup(body, config, client, audit);
                break;
            }

            case 'GET': {
                if (groupId) {
                    response = await handleGetGroup(groupId, config, client);
                } else {
                    const startIndex = parseInt(event.queryStringParameters?.startIndex || '1', 10);
                    const count = parseInt(event.queryStringParameters?.count || '100', 10);
                    response = await handleListGroups(config, client, startIndex, count);
                }
                break;
            }

            case 'PATCH': {
                if (!groupId) {
                    return withCors(scimBadRequest('Group ID is required', 'invalidValue'));
                }
                const body = parseJsonBody<ScimPatchRequest>(event);
                if (!body) {
                    return withCors(scimBadRequest('Invalid JSON body', 'invalidSyntax'));
                }
                response = await handlePatchGroup(groupId, body, config, client, audit, context.awsRequestId);
                break;
            }

            case 'DELETE': {
                if (!groupId) {
                    return withCors(scimBadRequest('Group ID is required', 'invalidValue'));
                }
                response = await handleDeleteGroup(groupId, config, client, audit, context.awsRequestId);
                break;
            }

            default:
                return withCors(scimBadRequest(`Method ${method} not allowed`, 'invalidValue'));
        }

        return withCors(response);
    } catch (err) {
        const e = err as Error;
        logger.error('SCIM Groups error', { error: e.message, stack: e.stack });
        return withCors(scimServerError('An unexpected error occurred'));
    }
};
