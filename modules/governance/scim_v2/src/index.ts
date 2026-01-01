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
 * - Admin endpoints require valid JWT with scim:users scope
 * - JWT signature verified against KMS public key
 * - Token expiration and issuer validation
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
import { KMSClient, GetPublicKeyCommand } from '@aws-sdk/client-kms';
import { createVerify } from 'node:crypto';
import { createLogger, withContext, base64UrlDecode } from '@oauth-server/shared';
import type { EnvConfig, ScimUserCreateRequest, ScimPatchRequest } from './types';
import { handlePostUser } from './post-user';
import { handleGetUser } from './get-user';
import { handlePatchUser } from './patch-user';
import { handleGetMe, handlePatchMe } from './me';
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

/** Required scope for SCIM User operations */
const SCIM_USERS_SCOPE = 'scim:users';

/** Required scope for SCIM self-service /Me operations */
const SCIM_ME_SCOPE = 'openid';

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
    readonly errorCode?: 'invalid_token' | 'insufficient_scope' | 'token_revoked';
}

/**
 * Enterprise-grade access token verification.
 * 
 * Validates per RFC 9068 (JWT Access Tokens) and industry best practices:
 * 1. JWT structure (header.payload.signature)
 * 2. Algorithm is RS256 (asymmetric, KMS-compatible)
 * 3. Cryptographic signature via KMS public key
 * 4. Expiration check (exp claim)
 * 5. Not-before check with clock skew (iat claim)
 * 6. Maximum token age (iat must be within 24 hours)
 * 7. Issuer validation (iss claim)
 * 8. Audience validation (aud claim)
 * 
 * @param token - The JWT access token string
 * @param publicKey - PEM-encoded public key from KMS
 * @param expectedIssuer - Expected issuer URL for validation
 * @returns Validation result with payload or error details
 */
function verifyAccessToken(
    token: string,
    publicKey: string,
    expectedIssuer: string
): TokenValidationResult {
    const parts = token.split('.');
    if (parts.length !== 3) {
        return { valid: false, error: 'Malformed JWT: expected 3 parts', errorCode: 'invalid_token' };
    }

    const [headerB64, payloadB64, signatureB64] = parts;

    try {
        // 1. Decode and validate header
        const header = JSON.parse(base64UrlDecode(headerB64).toString('utf8')) as { alg?: string; typ?: string };
        if (header.alg !== 'RS256') {
            return { valid: false, error: `Unsupported algorithm: ${header.alg}`, errorCode: 'invalid_token' };
        }

        // 2. Decode payload
        const payload = JSON.parse(base64UrlDecode(payloadB64).toString('utf8')) as AccessTokenPayload;

        // 3. Verify cryptographic signature
        const verifier = createVerify('RSA-SHA256');
        verifier.update(`${headerB64}.${payloadB64}`);
        if (!verifier.verify(publicKey, base64UrlDecode(signatureB64))) {
            return { valid: false, error: 'Invalid signature', errorCode: 'invalid_token' };
        }

        const now = Math.floor(Date.now() / 1000);

        // 4. Validate expiration (exp)
        if (!payload.exp || payload.exp <= now) {
            return { valid: false, error: 'Token has expired', errorCode: 'invalid_token' };
        }

        // 5. Validate issued-at with clock skew (iat)
        if (!payload.iat) {
            return { valid: false, error: 'Missing iat claim', errorCode: 'invalid_token' };
        }
        if (payload.iat > now + MAX_CLOCK_SKEW_SECONDS) {
            return { valid: false, error: 'Token issued in the future', errorCode: 'invalid_token' };
        }

        // 6. Validate maximum token age (prevent replay of old tokens)
        const tokenAge = now - payload.iat;
        if (tokenAge > MAX_TOKEN_AGE_SECONDS) {
            return { valid: false, error: 'Token exceeds maximum age', errorCode: 'invalid_token' };
        }

        // 7. Validate issuer (iss)
        if (payload.iss !== expectedIssuer) {
            return { valid: false, error: `Invalid issuer: expected ${expectedIssuer}`, errorCode: 'invalid_token' };
        }

        // 8. Validate audience (aud) - token must be intended for this issuer or contain it in array
        const expectedAudience = expectedIssuer;
        const audiences = Array.isArray(payload.aud) ? payload.aud : [payload.aud];
        if (!audiences.includes(expectedAudience)) {
            return { valid: false, error: 'Token not intended for this audience', errorCode: 'invalid_token' };
        }

        return { valid: true, payload };
    } catch (e) {
        const error = e as Error;
        return { valid: false, error: `Token parsing failed: ${error.message}`, errorCode: 'invalid_token' };
    }
}

/**
 * Validate that the token has the required scope.
 * 
 * @param payload - Verified token payload
 * @param requiredScope - Space-delimited required scopes (any one must match)
 * @returns True if token has required scope
 */
function hasRequiredScope(payload: AccessTokenPayload, requiredScope: string): boolean {
    const tokenScopes = payload.scope.split(' ').filter(s => s.length > 0);
    const required = requiredScope.split(' ').filter(s => s.length > 0);
    return required.some(r => tokenScopes.includes(r));
}

/**
 * Check if a token has been revoked.
 * 
 * Queries DynamoDB for token revocation status using the jti (JWT ID) claim.
 * This adds latency but provides defense-in-depth against compromised tokens.
 * 
 * @param jti - JWT ID claim from the token
 * @param client - DynamoDB document client
 * @param tableName - DynamoDB table name
 * @returns True if token is revoked
 */
async function isTokenRevoked(
    jti: string | undefined,
    client: DynamoDBDocumentClient,
    tableName: string
): Promise<boolean> {
    if (!jti) {
        // Tokens without jti cannot be individually revoked
        // This is acceptable for short-lived tokens
        return false;
    }

    try {
        const { GetCommand } = await import('@aws-sdk/lib-dynamodb');
        const result = await client.send(
            new GetCommand({
                TableName: tableName,
                Key: {
                    PK: `TOKEN#${jti}`,
                    SK: 'REVOKED',
                },
                ProjectionExpression: 'revokedAt',
            })
        );
        return !!result.Item;
    } catch {
        // On error, fail open to avoid blocking legitimate requests
        // This should be monitored via CloudWatch alarms
        return false;
    }
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

        // =====================================================================
        // Authentication & Authorization (Enterprise-Grade)
        // =====================================================================

        // Extract Bearer token
        const authHeader = event.headers?.['authorization'];
        if (!authHeader || !authHeader.toLowerCase().startsWith('bearer ')) {
            audit.log({
                action: 'CLIENT_AUTH_FAILED',
                actor: { type: 'ANONYMOUS' },
                details: { reason: 'missing_bearer_token', path },
            });
            return withCors(scimUnauthorized('Missing or invalid Authorization header'));
        }

        const token = authHeader.slice(7);

        // Verify JWT signature and all claims
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

        // Check token revocation
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

        let response: APIGatewayProxyResultV2;

        // Route /Me endpoints (RFC 7644 Section 3.11)
        // /Me requires openid scope - any authenticated user can access their own profile
        if (isMeEndpoint(path)) {
            // Scope check for /Me endpoints
            if (!hasRequiredScope(tokenPayload, SCIM_ME_SCOPE)) {
                logger.warn('Insufficient scope for /Me', { sub: tokenPayload.sub, scope: tokenPayload.scope });
                audit.log({
                    action: 'CLIENT_AUTH_FAILED',
                    actor: { type: 'USER', sub: tokenPayload.sub },
                    details: { reason: 'insufficient_scope', required: SCIM_ME_SCOPE, provided: tokenPayload.scope },
                });
                return withCors(scimForbidden(`Required scope: ${SCIM_ME_SCOPE}`));
            }

            switch (method) {
                case 'GET': {
                    // GET /scim/v2/Me - Retrieve authenticated user's profile
                    response = await handleGetMe(tokenPayload.sub, config, client);
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

                    response = await handlePatchMe(tokenPayload.sub, body, config, client, audit, requestId);
                    break;
                }

                default:
                    response = scimBadRequest('Method not allowed for /Me endpoint. Use GET or PATCH.');
            }

            return withCors(response);
        }

        // =====================================================================
        // /Users Admin Endpoints - Require scim:users scope
        // =====================================================================

        if (!hasRequiredScope(tokenPayload, SCIM_USERS_SCOPE)) {
            logger.warn('Insufficient scope for /Users', { sub: tokenPayload.sub, scope: tokenPayload.scope });
            audit.log({
                action: 'CLIENT_AUTH_FAILED',
                actor: { type: 'USER', sub: tokenPayload.sub },
                details: { reason: 'insufficient_scope', required: SCIM_USERS_SCOPE, provided: tokenPayload.scope },
            });
            return withCors(scimForbidden(`Required scope: ${SCIM_USERS_SCOPE}`));
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
