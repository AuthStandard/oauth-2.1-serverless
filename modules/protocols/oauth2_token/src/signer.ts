/**
 * OAuth 2.1 Token Endpoint - KMS JWT Signer
 *
 * Signs JWTs using AWS KMS with RS256 algorithm per RFC 7518.
 * Private key never leaves KMS HSM boundary (FIPS 140-2 Level 3).
 *
 * Security Architecture:
 * - Asymmetric signing: Private key remains in KMS, only public key is exposed
 * - RS256 (RSASSA-PKCS1-v1_5 with SHA-256): Industry standard, widely supported
 * - Key rotation: Managed via KEY_ID environment variable and JWKS endpoint
 *
 * Token Types:
 * - Access Token: RFC 9068 JWT Profile for OAuth 2.0 Access Tokens
 * - ID Token: OpenID Connect Core 1.0 Section 2
 * - Refresh Token: Opaque JWT for server-side validation only
 *
 * @module oauth2_token/signer
 * @see RFC 7519 - JSON Web Token (JWT)
 * @see RFC 9068 - JWT Profile for OAuth 2.0 Access Tokens
 * @see RFC 7518 - JSON Web Algorithms (JWA)
 */

import { KMSClient, SignCommand, SigningAlgorithmSpec } from '@aws-sdk/client-kms';
import { randomUUID } from 'node:crypto';

// =============================================================================
// Configuration
// =============================================================================

/**
 * KMS Signer configuration.
 * All values are injected from Lambda environment variables.
 */
interface SignerConfig {
    /** KMS Key ID or ARN for signing operations */
    readonly kmsKeyId: string;
    /** JWT Key ID (kid) for the JWT header - must match JWKS endpoint */
    readonly keyId: string;
    /** AWS region (optional, defaults to Lambda's region) */
    readonly region?: string;
}

// =============================================================================
// Base64URL Encoding (RFC 4648 Section 5)
// =============================================================================

/**
 * Encode data to base64url format.
 * Base64url is URL-safe: '+' → '-', '/' → '_', no padding.
 */
function base64UrlEncode(data: string | Buffer): string {
    const buffer = typeof data === 'string' ? Buffer.from(data) : data;
    return buffer
        .toString('base64')
        .replace(/\+/g, '-')
        .replace(/\//g, '_')
        .replace(/=+$/, '');
}

// =============================================================================
// JWT Payload Types (RFC 9068 & OpenID Connect)
// =============================================================================

/**
 * Access Token payload per RFC 9068 (JWT Profile for OAuth 2.0 Access Tokens).
 *
 * Required claims:
 * - iss, sub, aud, exp, iat, jti, client_id
 *
 * Recommended claims:
 * - nbf, scope
 *
 * Custom claims:
 * - groups: User's group memberships for RBAC
 *
 * DPoP binding (RFC 9449):
 * - cnf: Confirmation claim with JWK thumbprint
 */
export interface AccessTokenPayload {
    /** Issuer - Authorization server URL */
    readonly iss: string;
    /** Subject - User identifier or client_id for client_credentials */
    readonly sub: string;
    /** Audience - Resource server(s) this token is intended for */
    readonly aud: string | readonly string[];
    /** Expiration time (Unix timestamp) */
    readonly exp: number;
    /** Issued at time (Unix timestamp) */
    readonly iat: number;
    /** Not before time (Unix timestamp) */
    readonly nbf: number;
    /** JWT ID - Unique token identifier */
    readonly jti: string;
    /** Client ID that requested this token */
    readonly client_id: string;
    /** Space-delimited scope string */
    readonly scope: string;
    /** User's group memberships for RBAC */
    readonly groups?: readonly string[];
    /** Confirmation claim for sender-constrained tokens (RFC 9449) */
    readonly cnf?: { readonly jkt: string };
}

/**
 * ID Token payload per OpenID Connect Core 1.0 Section 2.
 *
 * Required claims:
 * - iss, sub, aud, exp, iat
 *
 * Conditionally required:
 * - auth_time (if max_age requested or auth_time_required)
 * - nonce (if provided in authorization request)
 * - at_hash (if issued with access token from authorization endpoint)
 * - sid (for session management and RP-Initiated Logout)
 */
export interface IdTokenPayload {
    /** Issuer - Authorization server URL */
    readonly iss: string;
    /** Subject - User identifier */
    readonly sub: string;
    /** Audience - Client ID */
    readonly aud: string;
    /** Expiration time (Unix timestamp) */
    readonly exp: number;
    /** Issued at time (Unix timestamp) */
    readonly iat: number;
    /** Not before time (Unix timestamp) */
    readonly nbf: number;
    /** Time of user authentication (Unix timestamp) */
    readonly auth_time: number;
    /** Session ID for session management and logout (OIDC Session Management) */
    readonly sid?: string;
    /** Nonce from authorization request (replay protection) */
    readonly nonce?: string;
    /** Access token hash (left half of SHA-256, base64url encoded) */
    readonly at_hash?: string;
    /** User's email address */
    readonly email?: string;
    /** Whether email has been verified */
    readonly email_verified?: boolean;
    /** User's full name */
    readonly name?: string;
}

/**
 * Refresh Token payload (internal format, not standardized).
 * Used for server-side validation and token family tracking.
 */
interface RefreshTokenPayload {
    /** Issuer - Authorization server URL */
    readonly iss: string;
    /** Subject - User identifier */
    readonly sub: string;
    /** Audience - Client ID */
    readonly aud: string;
    /** Expiration time (Unix timestamp) */
    readonly exp: number;
    /** Issued at time (Unix timestamp) */
    readonly iat: number;
    /** JWT ID - Unique token identifier */
    readonly jti: string;
    /** Space-delimited scope string */
    readonly scope: string;
    /** Token type discriminator */
    readonly token_type: 'refresh';
}

// =============================================================================
// KMS Signer Class
// =============================================================================

/**
 * JWT signer using AWS KMS for cryptographic operations.
 *
 * This class provides a secure signing mechanism where the private key
 * never leaves the KMS HSM boundary. All signing operations are performed
 * by KMS, ensuring FIPS 140-2 Level 3 compliance.
 */
export class KmsSigner {
    private readonly kmsClient: KMSClient;
    private readonly kmsKeyId: string;
    private readonly keyId: string;

    constructor(config: SignerConfig) {
        this.kmsKeyId = config.kmsKeyId;
        this.keyId = config.keyId;
        this.kmsClient = new KMSClient({ region: config.region });
    }

    /**
     * Sign a JWT payload using KMS.
     *
     * @param payload - JWT payload object
     * @returns Signed JWT string (header.payload.signature)
     * @throws Error if KMS signing fails
     */
    async signJwt<T extends object>(payload: T): Promise<string> {
        const header = { alg: 'RS256', typ: 'JWT', kid: this.keyId };
        const encodedHeader = base64UrlEncode(JSON.stringify(header));
        const encodedPayload = base64UrlEncode(JSON.stringify(payload));
        const signingInput = `${encodedHeader}.${encodedPayload}`;

        const signResult = await this.kmsClient.send(
            new SignCommand({
                KeyId: this.kmsKeyId,
                Message: Buffer.from(signingInput),
                MessageType: 'RAW',
                SigningAlgorithm: SigningAlgorithmSpec.RSASSA_PKCS1_V1_5_SHA_256,
            })
        );

        if (!signResult.Signature) {
            throw new Error('KMS signing operation returned no signature');
        }

        const encodedSignature = base64UrlEncode(Buffer.from(signResult.Signature));
        return `${signingInput}.${encodedSignature}`;
    }

    /**
     * Create an access token per RFC 9068.
     *
     * @param params - Token parameters
     * @param params.dpopThumbprint - DPoP JWK thumbprint for sender-constrained tokens (RFC 9449)
     * @param params.groups - User's group memberships for RBAC
     * @returns Signed JWT access token
     */
    async createAccessToken(params: {
        issuer: string;
        sub: string;
        clientId: string;
        scope: string;
        audience: string | string[];
        expiresIn: number;
        jti: string;
        dpopThumbprint?: string;
        groups?: string[];
    }): Promise<string> {
        const now = Math.floor(Date.now() / 1000);
        const payload: AccessTokenPayload = {
            iss: params.issuer,
            sub: params.sub,
            aud: params.audience,
            exp: now + params.expiresIn,
            iat: now,
            nbf: now,
            jti: params.jti,
            client_id: params.clientId,
            scope: params.scope,
            ...(params.groups && params.groups.length > 0 && { groups: params.groups }),
            ...(params.dpopThumbprint && { cnf: { jkt: params.dpopThumbprint } }),
        };
        return this.signJwt(payload);
    }

    /**
     * Create an ID token per OpenID Connect Core 1.0.
     *
     * @param params - Token parameters including user claims
     * @param params.sessionId - Session ID for OIDC Session Management and RP-Initiated Logout
     * @returns Signed JWT ID token
     */
    async createIdToken(params: {
        issuer: string;
        sub: string;
        clientId: string;
        expiresIn: number;
        authTime: number;
        sessionId?: string;
        nonce?: string;
        atHash?: string;
        email?: string;
        emailVerified?: boolean;
        name?: string;
    }): Promise<string> {
        const now = Math.floor(Date.now() / 1000);
        const payload: IdTokenPayload = {
            iss: params.issuer,
            sub: params.sub,
            aud: params.clientId,
            exp: now + params.expiresIn,
            iat: now,
            nbf: now,
            auth_time: params.authTime,
            ...(params.sessionId && { sid: params.sessionId }),
            ...(params.nonce && { nonce: params.nonce }),
            ...(params.atHash && { at_hash: params.atHash }),
            ...(params.email && { email: params.email }),
            ...(params.emailVerified !== undefined && { email_verified: params.emailVerified }),
            ...(params.name && { name: params.name }),
        };
        return this.signJwt(payload);
    }

    /**
     * Create a refresh token.
     *
     * Note: Refresh tokens are JWTs for convenience but are validated
     * server-side via database lookup, not JWT verification.
     *
     * @param params - Token parameters
     * @returns Signed JWT refresh token
     */
    async createRefreshToken(params: {
        issuer: string;
        sub: string;
        clientId: string;
        scope: string;
        expiresIn: number;
    }): Promise<string> {
        const now = Math.floor(Date.now() / 1000);
        const payload: RefreshTokenPayload = {
            iss: params.issuer,
            sub: params.sub,
            aud: params.clientId,
            exp: now + params.expiresIn,
            iat: now,
            jti: randomUUID(),
            scope: params.scope,
            token_type: 'refresh',
        };
        return this.signJwt(payload);
    }
}

// =============================================================================
// Singleton Factory
// =============================================================================

/** Cached signer instance for Lambda warm starts */
let signerInstance: KmsSigner | null = null;
let cachedKmsKeyId: string | null = null;
let cachedKeyId: string | null = null;

/**
 * Create or retrieve a cached KMS signer instance.
 *
 * Uses singleton pattern to reuse KMS client across Lambda invocations,
 * reducing cold start latency. Cache is invalidated if environment
 * variables change (supports key rotation).
 *
 * @returns KmsSigner instance
 * @throws Error if required environment variables are missing
 */
export function createSigner(): KmsSigner {
    const kmsKeyId = process.env.KMS_KEY_ID;
    const keyId = process.env.KEY_ID;

    if (!kmsKeyId) throw new Error('KMS_KEY_ID environment variable is required');
    if (!keyId) throw new Error('KEY_ID environment variable is required');

    // Invalidate cache if config changed (supports key rotation)
    if (!signerInstance || cachedKmsKeyId !== kmsKeyId || cachedKeyId !== keyId) {
        signerInstance = new KmsSigner({ kmsKeyId, keyId });
        cachedKmsKeyId = kmsKeyId;
        cachedKeyId = keyId;
    }

    return signerInstance;
}
