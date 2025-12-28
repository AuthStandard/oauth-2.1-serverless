/**
 * OIDC UserInfo Endpoint - Lambda Handler
 *
 * Implements GET/POST /userinfo per OpenID Connect Core 1.0 Section 5.3.
 * Returns claims about the authenticated user based on granted scopes.
 *
 * Authentication (RFC 6750 & RFC 9449):
 *   - Bearer tokens: Authorization header "Bearer <token>"
 *   - DPoP tokens: Authorization header "DPoP <token>" + DPoP proof header
 *
 * DPoP Support (RFC 9449):
 *   - If access token contains cnf.jkt claim, DPoP proof is REQUIRED
 *   - DPoP proof must be signed by the key matching the jkt thumbprint
 *   - Provides sender-constrained token validation at resource server
 *
 * Scope-Based Claims (OIDC Core Section 5.4):
 *   - openid: sub (always included, REQUIRED for UserInfo)
 *   - profile: name, given_name, family_name, picture, locale, zoneinfo
 *   - email: email, email_verified
 *
 * Security Controls:
 *   - Bearer/DPoP token authentication per RFC 6750/9449
 *   - RS256 signature verification using KMS public key
 *   - Token expiration validation (exp claim)
 *   - Issuer validation (iss claim must match expected issuer)
 *   - DPoP proof validation for sender-constrained tokens
 *   - User status verification (must be ACTIVE)
 *   - Cache-Control: no-store prevents caching of user data
 *
 * Environment Variables (injected via Terraform):
 *   - TABLE_NAME: DynamoDB table name for user data
 *   - KMS_KEY_ID: AWS KMS key ID for JWT signature verification
 *   - ISSUER: OAuth 2.1 issuer URL for token validation
 *
 * @module oidc_userinfo
 * @see https://openid.net/specs/openid-connect-core-1_0.html#UserInfo
 * @see https://datatracker.ietf.org/doc/html/rfc6750
 * @see https://datatracker.ietf.org/doc/html/rfc9449
 */

import type { APIGatewayProxyEventV2, APIGatewayProxyResultV2, Context } from 'aws-lambda';
import { DynamoDBClient } from '@aws-sdk/client-dynamodb';
import { DynamoDBDocumentClient, GetCommand } from '@aws-sdk/lib-dynamodb';
import { KMSClient, GetPublicKeyCommand } from '@aws-sdk/client-kms';
import { createVerify } from 'node:crypto';
import {
    base64UrlDecode,
    success,
    invalidRequest,
    invalidToken,
    insufficientScope,
    serverError,
    createLogger,
    validateDPoPProof,
    calculateAccessTokenHash,
} from '@oauth-server/shared';

// =============================================================================
// Types
// =============================================================================

/** User profile stored in DynamoDB */
interface UserProfile {
    /** Given/first name */
    readonly givenName?: string;
    /** Family/last name */
    readonly familyName?: string;
    /** Profile picture URL */
    readonly picture?: string;
    /** BCP 47 locale code */
    readonly locale?: string;
}

/** User record structure from DynamoDB */
interface UserRecord {
    /** Subject identifier (UUID) */
    readonly sub: string;
    /** Email address */
    readonly email: string;
    /** Whether email has been verified */
    readonly emailVerified: boolean;
    /** IANA timezone identifier */
    readonly zoneinfo: string;
    /** User profile information */
    readonly profile: UserProfile;
    /** Account status */
    readonly status: 'ACTIVE' | 'SUSPENDED' | 'PENDING_VERIFICATION';
}

/** DPoP confirmation claim in access token */
interface DPoPConfirmation {
    /** JWK SHA-256 thumbprint */
    readonly jkt: string;
}

/** JWT payload structure for access tokens */
interface AccessTokenPayload {
    /** Issuer identifier */
    readonly iss: string;
    /** Subject identifier */
    readonly sub: string;
    /** Audience (client_id or array of client_ids) */
    readonly aud: string | string[];
    /** Expiration time (Unix timestamp) */
    readonly exp: number;
    /** Issued at time (Unix timestamp) */
    readonly iat: number;
    /** Space-delimited scope string */
    readonly scope: string;
    /** Client identifier */
    readonly client_id: string;
    /** DPoP confirmation claim (RFC 9449) */
    readonly cnf?: DPoPConfirmation;
}

/**
 * OIDC UserInfo response per Section 5.3.2.
 * Claims are returned based on granted scopes (Section 5.4).
 */
interface UserInfoResponse {
    /** Subject identifier (always included) */
    sub: string;
    /** Email address (email scope) */
    email?: string;
    /** Whether email is verified (email scope) */
    email_verified?: boolean;
    /** Full name (profile scope) */
    name?: string;
    /** Given/first name (profile scope) */
    given_name?: string;
    /** Family/last name (profile scope) */
    family_name?: string;
    /** Profile picture URL (profile scope) */
    picture?: string;
    /** BCP 47 locale code (profile scope) */
    locale?: string;
    /** IANA timezone identifier (profile scope) */
    zoneinfo?: string;
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
 *   4. Expiration check (exp claim)
 *   5. Issuer claim matches expected value
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

        const now = Math.floor(Date.now() / 1000);
        if (payload.exp <= now) return null;
        if (payload.iss !== expectedIssuer) return null;

        return payload;
    } catch {
        return null;
    }
}

// =============================================================================
// Token Extraction
// =============================================================================

/** Result of token extraction */
interface TokenExtractionResult {
    /** The access token string */
    token: string;
    /** Whether the token was presented as DPoP (vs Bearer) */
    isDPoP: boolean;
}

/**
 * Extract access token from request per RFC 6750 and RFC 9449.
 *
 * Supports:
 *   1. Authorization header: "Bearer <token>" (RFC 6750 Section 2.1)
 *   2. Authorization header: "DPoP <token>" (RFC 9449 Section 7.1)
 *   3. Form body: access_token parameter for POST (RFC 6750 Section 2.2)
 *
 * @param event - API Gateway HTTP API v2 event
 * @returns Token extraction result or null if not found
 */
function extractAccessToken(event: APIGatewayProxyEventV2): TokenExtractionResult | null {
    // RFC 6750 Section 2.1 & RFC 9449 Section 7.1: Authorization Request Header Field
    const authHeader = event.headers?.['authorization'];
    if (authHeader) {
        // Check for DPoP token type first (RFC 9449)
        const dpopMatch = authHeader.match(/^DPoP\s+(.+)$/i);
        if (dpopMatch) {
            return { token: dpopMatch[1], isDPoP: true };
        }

        // Check for Bearer token type (RFC 6750)
        const bearerMatch = authHeader.match(/^Bearer\s+(.+)$/i);
        if (bearerMatch) {
            return { token: bearerMatch[1], isDPoP: false };
        }
    }

    // RFC 6750 Section 2.2: Form-Encoded Body Parameter (POST only, Bearer only)
    if (event.requestContext.http.method === 'POST') {
        const contentType = event.headers?.['content-type'] || '';
        if (contentType.includes('application/x-www-form-urlencoded')) {
            let body = event.body || '';
            if (event.isBase64Encoded) {
                body = Buffer.from(body, 'base64').toString('utf8');
            }
            const params = new URLSearchParams(body);
            const token = params.get('access_token');
            if (token) {
                return { token, isDPoP: false };
            }
        }
    }

    return null;
}

// =============================================================================
// DPoP Validation for Resource Server
// =============================================================================

/**
 * Build the UserInfo endpoint URL from the issuer.
 *
 * @param issuer - OAuth issuer URL (e.g., https://auth.example.com)
 * @returns UserInfo endpoint URL (e.g., https://auth.example.com/userinfo)
 */
function buildUserInfoEndpointUrl(issuer: string): string {
    const base = issuer.endsWith('/') ? issuer.slice(0, -1) : issuer;
    return `${base}/userinfo`;
}

/**
 * Validate DPoP proof for sender-constrained access tokens.
 *
 * Per RFC 9449 Section 7.1, when an access token contains a cnf claim:
 * - The DPoP header MUST be present
 * - The DPoP proof MUST be valid
 * - The proof's key thumbprint MUST match the cnf.jkt in the token
 * - The proof's ath claim MUST match the hash of the access token
 *
 * @param dpopHeader - DPoP header value from request
 * @param accessToken - The access token string
 * @param expectedThumbprint - Expected JWK thumbprint from cnf.jkt
 * @param httpMethod - HTTP method of the request
 * @param httpUri - HTTP URI of the request
 * @returns Error message if validation fails, undefined if valid
 */
function validateDPoPForResourceServer(
    dpopHeader: string | undefined,
    accessToken: string,
    expectedThumbprint: string,
    httpMethod: string,
    httpUri: string
): string | undefined {
    // DPoP header is required for sender-constrained tokens
    if (!dpopHeader) {
        return 'DPoP proof required for sender-constrained token';
    }

    // Calculate access token hash for ath claim validation
    const accessTokenHash = calculateAccessTokenHash(accessToken);

    // Validate the DPoP proof
    const result = validateDPoPProof(dpopHeader, {
        httpMethod,
        httpUri,
        accessTokenHash,
    });

    if (!result.valid) {
        return result.error || 'Invalid DPoP proof';
    }

    // Verify the key thumbprint matches the token's cnf.jkt
    if (result.thumbprint !== expectedThumbprint) {
        return 'DPoP key binding mismatch';
    }

    return undefined;
}

// =============================================================================
// Response Builder
// =============================================================================

/**
 * Build UserInfo response based on granted scopes.
 *
 * Per OIDC Core Section 5.4, claims are returned based on scope:
 *   - openid: sub (always required)
 *   - profile: name, given_name, family_name, picture, locale, zoneinfo
 *   - email: email, email_verified
 *
 * @param user - User record from DynamoDB
 * @param scopes - Array of granted scopes
 * @returns UserInfo response object
 */
function buildUserInfoResponse(user: UserRecord, scopes: string[]): UserInfoResponse {
    const response: UserInfoResponse = { sub: user.sub };

    if (scopes.includes('email')) {
        response.email = user.email;
        response.email_verified = user.emailVerified;
    }

    if (scopes.includes('profile')) {
        const profile = user.profile || {};

        if (profile.givenName || profile.familyName) {
            response.name = [profile.givenName, profile.familyName].filter(Boolean).join(' ');
        }
        if (profile.givenName) response.given_name = profile.givenName;
        if (profile.familyName) response.family_name = profile.familyName;
        if (profile.picture) response.picture = profile.picture;
        if (profile.locale) response.locale = profile.locale;
        if (user.zoneinfo) response.zoneinfo = user.zoneinfo;
    }

    return response;
}

// =============================================================================
// Lambda Handler
// =============================================================================

export const handler = async (
    event: APIGatewayProxyEventV2,
    context: Context
): Promise<APIGatewayProxyResultV2> => {
    const logger = createLogger(event, context);

    try {
        const method = event.requestContext.http.method;
        logger.info('UserInfo request received', { method });

        // OIDC Core Section 5.3.1: Only GET and POST are allowed
        if (method !== 'GET' && method !== 'POST') {
            return invalidRequest('Method not allowed');
        }

        // Extract access token per RFC 6750 / RFC 9449
        const tokenResult = extractAccessToken(event);
        if (!tokenResult) {
            return invalidToken('Missing access token');
        }

        const config = getEnvConfig();

        // Verify access token signature and claims
        const publicKey = await getPublicKey(config.kmsKeyId);
        const tokenPayload = verifyAccessToken(tokenResult.token, publicKey, config.issuer);

        if (!tokenPayload) {
            logger.warn('Access token verification failed');
            return invalidToken('Access token is invalid or expired');
        }

        // =====================================================================
        // DPoP Validation (RFC 9449 Section 7.1)
        // If the access token contains a cnf claim, validate DPoP proof
        // =====================================================================
        if (tokenPayload.cnf?.jkt) {
            const dpopHeader = event.headers?.['dpop'];
            const userInfoUrl = buildUserInfoEndpointUrl(config.issuer);

            const dpopError = validateDPoPForResourceServer(
                dpopHeader,
                tokenResult.token,
                tokenPayload.cnf.jkt,
                method,
                userInfoUrl
            );

            if (dpopError) {
                logger.warn('DPoP validation failed', { error: dpopError, sub: tokenPayload.sub });
                return invalidToken(dpopError);
            }

            logger.info('DPoP proof validated', { sub: tokenPayload.sub });
        } else if (tokenResult.isDPoP) {
            // Token presented as DPoP but doesn't have cnf claim - reject
            logger.warn('DPoP token type used but token has no cnf claim', { sub: tokenPayload.sub });
            return invalidToken('Token is not DPoP-bound');
        }

        // OIDC Core Section 5.3.1: openid scope is required
        const scopes = tokenPayload.scope.split(' ');
        if (!scopes.includes('openid')) {
            logger.warn('Access token missing openid scope', { sub: tokenPayload.sub });
            return insufficientScope('openid');
        }

        // Fetch user from DynamoDB
        const client = getDocClient();
        const userResult = await client.send(
            new GetCommand({
                TableName: config.tableName,
                Key: { PK: `USER#${tokenPayload.sub}`, SK: 'PROFILE' },
            })
        );

        if (!userResult.Item) {
            logger.warn('User not found', { sub: tokenPayload.sub });
            return invalidToken('User not found');
        }

        const user = userResult.Item as UserRecord;

        // Verify user is active
        if (user.status !== 'ACTIVE') {
            logger.warn('User not active', { sub: tokenPayload.sub, status: user.status });
            return invalidToken('User account is not active');
        }

        // Build response based on granted scopes
        const response = buildUserInfoResponse(user, scopes);

        logger.info('UserInfo response sent', { sub: user.sub, scopes });
        return success(response);
    } catch (err) {
        const error = err as Error;
        logger.error('UserInfo endpoint error', { error: error.message, stack: error.stack });
        return serverError('An unexpected error occurred');
    }
};
