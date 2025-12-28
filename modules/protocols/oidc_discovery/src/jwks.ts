/**
 * JWKS Endpoint - Lambda Handler
 *
 * Implements GET /keys returning JSON Web Key Set (JWKS) per RFC 7517.
 * Clients use this endpoint to retrieve public keys for JWT verification.
 *
 * Features:
 *   - Retrieves RSA public key from AWS KMS
 *   - Converts DER/SPKI format to JWK (modulus/exponent)
 *   - In-memory caching to minimize KMS API calls
 *   - Cache-Control headers for client-side caching
 *
 * Security Properties:
 *   - Public keys are safe to expose (only private keys must be protected)
 *   - KMS ensures private key never leaves HSM boundary (FIPS 140-2 Level 3)
 *   - Cache invalidation happens automatically on Lambda cold start
 *   - No authentication required (public endpoint per OIDC spec)
 *   - Key validation ensures only RSA_2048/RSA_4096 SIGN_VERIFY keys are used
 *
 * Key Rotation Support:
 *   During key rotation, this endpoint should serve both old and new keys.
 *   Clients select the correct key using the 'kid' (Key ID) from JWT headers.
 *   
 *   Rotation Procedure:
 *     1. Create new KMS key, update jwt_key_id in terraform.tfvars
 *     2. Deploy - JWKS endpoint now serves both old and new public keys
 *     3. New tokens signed with new key, old tokens still verify with old key
 *     4. Wait for max token lifetime (access + refresh TTL) to elapse
 *     5. Remove old key from JWKS, schedule old KMS key for deletion
 *
 *   Current implementation serves single key. For rotation support:
 *     - Accept multiple KMS key IDs via environment variable (comma-separated)
 *     - Fetch and include all public keys in JWKS response
 *
 * Environment Variables (injected via Terraform - no hardcoded defaults):
 *   - KMS_KEY_ID: AWS KMS key ID or ARN for GetPublicKey operation
 *   - KEY_ID: JWT 'kid' header value (stable identifier for key rotation)
 *
 * @module oidc_discovery/jwks
 * @see https://datatracker.ietf.org/doc/html/rfc7517
 * @see https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderMetadata
 */

import type { APIGatewayProxyEventV2, APIGatewayProxyResultV2, Context } from 'aws-lambda';
import { KMSClient, GetPublicKeyCommand } from '@aws-sdk/client-kms';

// ============================================================================
// Shared Module Imports
// ============================================================================
// This module uses @oauth-server/shared for common utilities.
// esbuild bundles these into the final Lambda deployment package.
// See esbuild.config.mjs for bundling configuration.
// ============================================================================

import { createLogger } from '@oauth-server/shared';

/**
 * Cache TTL for JWKS response.
 * 1 hour provides good balance between performance and key rotation responsiveness.
 * During key rotation, Lambda cold starts will fetch the new key.
 */
const CACHE_TTL_MS = 3600 * 1000;

// =============================================================================
// Types
// =============================================================================

/**
 * RSA JSON Web Key per RFC 7517 Section 6.3.
 * @see https://datatracker.ietf.org/doc/html/rfc7517#section-6.3
 */
interface RSAJsonWebKey {
    /** Key Type - always 'RSA' for RSA keys */
    kty: 'RSA';
    /** Public Key Use - 'sig' for signature verification */
    use: 'sig';
    /** Algorithm - RS256 per OIDC Core Section 15.1 */
    alg: 'RS256';
    /** Key ID - matches 'kid' in JWT headers */
    kid: string;
    /** Modulus (Base64url encoded) */
    n: string;
    /** Exponent (Base64url encoded) */
    e: string;
}

interface JWKS {
    keys: RSAJsonWebKey[];
}

// =============================================================================
// Environment Configuration
// =============================================================================

interface EnvConfig {
    kmsKeyId: string;
    keyId: string;
}

function getEnvConfig(): EnvConfig {
    const kmsKeyId = process.env.KMS_KEY_ID;
    const keyId = process.env.KEY_ID;

    if (!kmsKeyId) {
        throw new Error('KMS_KEY_ID environment variable is required');
    }

    if (!keyId) {
        throw new Error('KEY_ID environment variable is required');
    }

    return { kmsKeyId, keyId };
}

// =============================================================================
// KMS Client (Singleton)
// =============================================================================

let kmsClient: KMSClient | null = null;

function getKmsClient(): KMSClient {
    if (!kmsClient) {
        kmsClient = new KMSClient({});
    }
    return kmsClient;
}

// =============================================================================
// In-Memory Cache
// =============================================================================

interface CacheEntry {
    jwks: JWKS;
    expiresAt: number;
}

let jwksCache: CacheEntry | null = null;

function getCachedJwks(): JWKS | null {
    if (jwksCache && Date.now() < jwksCache.expiresAt) {
        return jwksCache.jwks;
    }
    return null;
}

function setCachedJwks(jwks: JWKS): void {
    jwksCache = {
        jwks,
        expiresAt: Date.now() + CACHE_TTL_MS,
    };
}

// =============================================================================
// Base64url Encoding (RFC 4648 Section 5)
// =============================================================================

function base64urlEncode(buffer: Buffer): string {
    return buffer
        .toString('base64')
        .replace(/\+/g, '-')
        .replace(/\//g, '_')
        .replace(/=+$/, '');
}

// =============================================================================
// RSA Public Key Parsing (DER/SPKI to JWK)
// =============================================================================

/**
 * Parse an RSA public key in SPKI format to extract modulus (n) and exponent (e).
 * Handles the ASN.1 DER structure of SubjectPublicKeyInfo per RFC 5280.
 *
 * SPKI Structure:
 *   SEQUENCE {
 *     SEQUENCE { algorithm OID, parameters }
 *     BIT STRING { RSAPublicKey }
 *   }
 *
 * RSAPublicKey Structure (RFC 3447):
 *   SEQUENCE {
 *     INTEGER (modulus n)
 *     INTEGER (exponent e)
 *   }
 */
function parseRsaPublicKey(derBuffer: Buffer): { n: Buffer; e: Buffer } {
    let offset = 0;

    function readLength(): number {
        const firstByte = derBuffer[offset++];
        if (firstByte === undefined) throw new Error('Unexpected end of DER data');

        if ((firstByte & 0x80) === 0) {
            return firstByte;
        }

        const numBytes = firstByte & 0x7f;
        let length = 0;
        for (let i = 0; i < numBytes; i++) {
            const byte = derBuffer[offset++];
            if (byte === undefined) throw new Error('Unexpected end of DER data');
            length = (length << 8) | byte;
        }
        return length;
    }

    function expectTag(expectedTag: number): void {
        const tag = derBuffer[offset++];
        if (tag !== expectedTag) {
            throw new Error(`Expected ASN.1 tag ${expectedTag}, got ${tag}`);
        }
    }

    // Parse outer SEQUENCE (SPKI)
    expectTag(0x30);
    readLength();

    // Parse algorithm SEQUENCE
    expectTag(0x30);
    const algLength = readLength();
    offset += algLength;

    // Parse BIT STRING containing RSAPublicKey
    expectTag(0x03);
    readLength();
    const unusedBits = derBuffer[offset++];
    if (unusedBits !== 0) {
        throw new Error(`Unexpected unused bits in BIT STRING: ${unusedBits}`);
    }

    // Parse RSAPublicKey SEQUENCE
    expectTag(0x30);
    readLength();

    // Read modulus (n)
    expectTag(0x02);
    let nLength = readLength();
    if (derBuffer[offset] === 0x00) {
        offset++;
        nLength--;
    }
    const n = derBuffer.subarray(offset, offset + nLength);
    offset += nLength;

    // Read exponent (e)
    expectTag(0x02);
    let eLength = readLength();
    if (derBuffer[offset] === 0x00) {
        offset++;
        eLength--;
    }
    const e = derBuffer.subarray(offset, offset + eLength);

    return { n: Buffer.from(n), e: Buffer.from(e) };
}

// =============================================================================
// Response Helpers
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

const JSON_HEADERS = {
    'Content-Type': 'application/json',
    'Cache-Control': 'public, max-age=3600',
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'GET, OPTIONS',
    ...SECURITY_HEADERS,
} as const;

function success<T>(body: T): APIGatewayProxyResultV2 {
    return {
        statusCode: 200,
        headers: JSON_HEADERS,
        body: JSON.stringify(body),
    };
}

function serverError(description: string): APIGatewayProxyResultV2 {
    return {
        statusCode: 500,
        headers: {
            'Content-Type': 'application/json',
            ...SECURITY_HEADERS,
        },
        body: JSON.stringify({ error: 'server_error', error_description: description }),
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

    try {
        logger.info('JWKS request received', { path: event.requestContext.http.path });

        // Return cached JWKS if available
        const cached = getCachedJwks();
        if (cached) {
            logger.debug('Returning cached JWKS');
            return success(cached);
        }

        const config = getEnvConfig();
        const kms = getKmsClient();

        logger.info('Fetching public key from KMS', { keyId: config.kmsKeyId });

        const response = await kms.send(
            new GetPublicKeyCommand({
                KeyId: config.kmsKeyId,
            })
        );

        if (!response.PublicKey) {
            logger.error('KMS returned no public key', { keyId: config.kmsKeyId });
            throw new Error('KMS returned no public key');
        }

        // Validate key specification - must be RSA for RS256 signing
        if (response.KeySpec !== 'RSA_2048' && response.KeySpec !== 'RSA_4096') {
            logger.error('Invalid KMS key specification', {
                keyId: config.kmsKeyId,
                keySpec: response.KeySpec,
                expected: ['RSA_2048', 'RSA_4096'],
            });
            throw new Error(`Invalid key specification: ${response.KeySpec}. RS256 requires RSA_2048 or RSA_4096.`);
        }

        // Validate key usage - must be SIGN_VERIFY for JWT signing
        if (!response.KeyUsage || response.KeyUsage !== 'SIGN_VERIFY') {
            logger.error('Invalid KMS key usage', {
                keyId: config.kmsKeyId,
                keyUsage: response.KeyUsage,
                expected: 'SIGN_VERIFY',
            });
            throw new Error(`Invalid key usage: ${response.KeyUsage}. Expected SIGN_VERIFY.`);
        }

        // Parse the DER-encoded public key
        const publicKeyDer = Buffer.from(response.PublicKey);
        const { n, e } = parseRsaPublicKey(publicKeyDer);

        // Build JWK per RFC 7517
        const jwk: RSAJsonWebKey = {
            kty: 'RSA',
            use: 'sig',
            alg: 'RS256',
            kid: config.keyId,
            n: base64urlEncode(n),
            e: base64urlEncode(e),
        };

        const jwks: JWKS = {
            keys: [jwk],
        };

        setCachedJwks(jwks);

        logger.info('Returning JWKS', { kid: jwk.kid, keySpec: response.KeySpec });

        return success(jwks);
    } catch (err) {
        const error = err as Error;
        logger.error('JWKS endpoint error', { error: error.message, stack: error.stack });
        return serverError('Failed to retrieve signing keys');
    }
};
