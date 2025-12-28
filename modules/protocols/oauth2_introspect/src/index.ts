/**
 * OAuth 2.1 Token Introspection Endpoint (RFC 7662)
 *
 * Enables resource servers to validate tokens without parsing JWTs directly.
 * Returns token metadata for active tokens or { "active": false } for invalid/expired tokens.
 *
 * Request: POST /introspect (application/x-www-form-urlencoded)
 *   - token (REQUIRED): The token to introspect
 *   - token_type_hint (OPTIONAL): "access_token" | "refresh_token"
 *
 * Response (RFC 7662 Section 2.2):
 *   - Active: { active: true, scope, client_id, sub, exp, iat, ... }
 *   - Inactive: { active: false } (no additional info to prevent enumeration)
 *
 * Security Controls:
 *   - Client authentication required (RFC 7662 Section 2.1)
 *   - Constant-time secret comparison (RFC 9700 Section 4.8.2)
 *   - RS256 JWT signature verification via KMS public key
 *   - Refresh tokens validated via SHA-256 hash lookup
 *
 * @see https://datatracker.ietf.org/doc/html/rfc7662
 * @see https://datatracker.ietf.org/doc/html/rfc9700
 */

import type { APIGatewayProxyEventV2, APIGatewayProxyResultV2, Context } from 'aws-lambda';
import { DynamoDBClient } from '@aws-sdk/client-dynamodb';
import { DynamoDBDocumentClient, GetCommand } from '@aws-sdk/lib-dynamodb';
import { KMSClient, GetPublicKeyCommand } from '@aws-sdk/client-kms';
import { createVerify } from 'node:crypto';
import {
    hashToken,
    base64UrlDecode,
    introspectionActive,
    introspectionInactive,
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
    readonly issuedAt: string;
    readonly rotated: boolean;
    readonly ttl?: number;
}

/** DPoP confirmation claim in access token (RFC 9449) */
interface DPoPConfirmation {
    /** JWK SHA-256 thumbprint */
    readonly jkt: string;
}

/** JWT payload structure for access tokens (RFC 9068) */
interface AccessTokenPayload {
    readonly iss: string;
    readonly sub: string;
    readonly aud: string | string[];
    readonly exp: number;
    readonly iat: number;
    readonly nbf?: number;
    readonly jti: string;
    readonly scope: string;
    readonly client_id: string;
    /** DPoP confirmation claim (RFC 9449) */
    readonly cnf?: DPoPConfirmation;
}

// =============================================================================
// Environment Configuration
// =============================================================================

interface EnvConfig {
    readonly tableName: string;
    readonly kmsKeyId: string;
    readonly issuer: string;
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
    const kmsKeyId = process.env.KMS_KEY_ID;
    const issuer = process.env.ISSUER;

    if (!tableName) throw new Error('TABLE_NAME environment variable is required');
    if (!kmsKeyId) throw new Error('KMS_KEY_ID environment variable is required');
    if (!issuer) throw new Error('ISSUER environment variable is required');

    envConfig = { tableName, kmsKeyId, issuer };
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
// KMS Client & Public Key Cache
// =============================================================================

/** Cached KMS client for Lambda container reuse */
let kmsClient: KMSClient | null = null;

/** Cached public key PEM and associated key ID */
let publicKeyCache: { pem: string; keyId: string } | null = null;

function getKmsClient(): KMSClient {
    if (!kmsClient) kmsClient = new KMSClient({});
    return kmsClient;
}

/**
 * Retrieve and cache the public key from KMS in PEM format.
 * Cached for Lambda container lifetime to minimize KMS API calls.
 * @throws Error if KMS returns no public key
 */
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
// JWT Verification
// =============================================================================

/**
 * Verify an access token JWT and extract its payload.
 *
 * Validation sequence:
 *   1. JWT structure (header.payload.signature)
 *   2. Algorithm is RS256 (asymmetric, KMS-compatible)
 *   3. Cryptographic signature via KMS public key
 *   4. Issuer claim matches expected value
 *
 * @param token - The JWT access token string
 * @param publicKey - PEM-encoded public key from KMS
 * @param expectedIssuer - Expected issuer URL for validation
 * @returns Decoded payload if valid, null for any validation failure
 */
function verifyAccessToken(
    token: string,
    publicKey: string,
    expectedIssuer: string
): AccessTokenPayload | null {
    const parts = token.split('.');
    if (parts.length !== 3) return null;

    const [headerB64, payloadB64, signatureB64] = parts;

    try {
        const header = JSON.parse(base64UrlDecode(headerB64).toString('utf8')) as { alg?: string };
        if (header.alg !== 'RS256') return null;

        const payload = JSON.parse(base64UrlDecode(payloadB64).toString('utf8')) as AccessTokenPayload;

        const verifier = createVerify('RSA-SHA256');
        verifier.update(`${headerB64}.${payloadB64}`);
        if (!verifier.verify(publicKey, base64UrlDecode(signatureB64))) return null;

        if (payload.iss !== expectedIssuer) return null;

        return payload;
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
    const auditLogger = withContext(event, context);

    try {
        logger.info('Introspection request received');

        // RFC 7662 Section 2.1: Must be POST
        if (event.requestContext.http.method !== 'POST') {
            return invalidRequest('Method not allowed');
        }

        // Validate Content-Type (v2 headers are lowercase)
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

        // RFC 7662 Section 2.1: token parameter is required
        const token = params.get('token');
        if (!token) {
            return invalidRequest('Missing required parameter: token');
        }

        const tokenTypeHint = params.get('token_type_hint');
        const config = getEnvConfig();
        const client = getDocClient();
        const authHeader = event.headers?.['authorization'];

        // RFC 7662 Section 2.1: Client authentication required
        const authResult = await authenticateClient(params, authHeader, client, config.tableName);
        if (!authResult.valid) {
            return authResult.error!;
        }

        const now = Math.floor(Date.now() / 1000);

        // Try access token first (unless hint explicitly says refresh_token)
        if (tokenTypeHint !== 'refresh_token') {
            const publicKey = await getPublicKey(config.kmsKeyId);
            const accessPayload = verifyAccessToken(token, publicKey, config.issuer);

            if (accessPayload) {
                if (accessPayload.exp <= now) {
                    logger.info('Access token expired', { exp: accessPayload.exp });
                    return introspectionInactive();
                }

                if (accessPayload.nbf && accessPayload.nbf > now) {
                    logger.info('Access token not yet valid', { nbf: accessPayload.nbf });
                    return introspectionInactive();
                }

                const requestingClientId = authResult.clientItem!.clientId;
                logger.info('Access token introspected', {
                    sub: accessPayload.sub,
                    clientId: accessPayload.client_id,
                });

                auditLogger.tokenIntrospected(
                    { type: 'CLIENT', clientId: requestingClientId },
                    {
                        active: true,
                        tokenType: 'access_token',
                        tokenClientId: accessPayload.client_id,
                        requestingClientId,
                    }
                );

                return introspectionActive({
                    scope: accessPayload.scope,
                    client_id: accessPayload.client_id,
                    sub: accessPayload.sub,
                    token_type: accessPayload.cnf ? 'DPoP' : 'Bearer',
                    exp: accessPayload.exp,
                    iat: accessPayload.iat,
                    nbf: accessPayload.nbf,
                    aud: accessPayload.aud,
                    iss: accessPayload.iss,
                    jti: accessPayload.jti,
                    // Include DPoP confirmation claim if present (RFC 9449)
                    ...(accessPayload.cnf && { cnf: accessPayload.cnf }),
                });
            }
        }

        // Try refresh token lookup via hash
        const tokenHash = hashToken(token);
        const refreshResult = await client.send(
            new GetCommand({
                TableName: config.tableName,
                Key: { PK: `REFRESH#${tokenHash}`, SK: 'METADATA' },
            })
        );

        if (refreshResult.Item) {
            const refreshToken = refreshResult.Item as RefreshTokenRecord;

            if (refreshToken.rotated) {
                logger.info('Refresh token revoked via rotation');
                return introspectionInactive();
            }

            if (refreshToken.ttl && refreshToken.ttl <= now) {
                logger.info('Refresh token expired', { ttl: refreshToken.ttl });
                return introspectionInactive();
            }

            const requestingClientId = authResult.clientItem!.clientId;
            logger.info('Refresh token introspected', {
                sub: refreshToken.sub,
                clientId: refreshToken.clientId,
            });

            auditLogger.tokenIntrospected(
                { type: 'CLIENT', clientId: requestingClientId },
                {
                    active: true,
                    tokenType: 'refresh_token',
                    tokenClientId: refreshToken.clientId,
                    requestingClientId,
                }
            );

            return introspectionActive({
                scope: refreshToken.scope,
                client_id: refreshToken.clientId,
                sub: refreshToken.sub,
                token_type: 'refresh_token',
                iat: Math.floor(new Date(refreshToken.issuedAt).getTime() / 1000),
                exp: refreshToken.ttl,
            });
        }

        // RFC 7662 Section 2.2: Return inactive for unknown/invalid tokens
        logger.info('Token not found or invalid', { tokenTypeHint });
        return introspectionInactive();
    } catch (err) {
        const error = err as Error;
        logger.error('Introspection endpoint error', { error: error.message, stack: error.stack });
        return serverError('An unexpected error occurred');
    }
};
