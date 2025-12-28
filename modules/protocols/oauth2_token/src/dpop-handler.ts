/**
 * OAuth 2.1 Token Endpoint - DPoP Handler
 *
 * Handles DPoP (Demonstrating Proof of Possession) validation and JTI storage
 * for sender-constrained access tokens per RFC 9449.
 *
 * Architecture:
 * - JTI replay prevention via DynamoDB conditional writes
 * - TTL-based automatic cleanup (no manual garbage collection)
 * - Atomic operations prevent race conditions
 * - Backward compatible - non-DPoP requests continue to work
 *
 * @module oauth2_token/dpop-handler
 * @see RFC 9449 - OAuth 2.0 Demonstrating Proof of Possession (DPoP)
 */

import type { DynamoDBDocumentClient } from '@aws-sdk/lib-dynamodb';
import { PutCommand } from '@aws-sdk/lib-dynamodb';
import {
    validateDPoPProofExtended,
    DPOP_PROOF_MAX_AGE_SECONDS,
    Logger,
} from '@oauth-server/shared';
import type { DPoPValidationResultExtended, DPoPPayload } from '@oauth-server/shared';

// =============================================================================
// Types
// =============================================================================

/**
 * Result of DPoP validation with JTI storage.
 */
export interface DPoPHandlerResult {
    /** Whether DPoP validation succeeded (or was not required) */
    valid: boolean;
    /** Error code for OAuth error response */
    errorCode?: 'invalid_dpop_proof' | 'invalid_grant';
    /** Error description */
    errorDescription?: string;
    /** JWK thumbprint for token binding (if DPoP was used) */
    thumbprint?: string;
    /** Whether DPoP was used in this request */
    dpopUsed: boolean;
}

/**
 * Options for DPoP validation.
 */
export interface DPoPHandlerOptions {
    /** DPoP header value from request */
    dpopHeader?: string;
    /** HTTP method (e.g., 'POST') */
    httpMethod: string;
    /** Token endpoint URL (scheme + host + path, no query) */
    tokenEndpointUrl: string;
    /** DynamoDB table name for JTI storage */
    tableName: string;
    /** DynamoDB document client */
    dbClient: DynamoDBDocumentClient;
    /** Logger instance */
    logger: Logger;
    /** Expected DPoP thumbprint for refresh token binding validation */
    expectedThumbprint?: string;
}

// =============================================================================
// JTI Storage
// =============================================================================

/**
 * Store a DPoP JTI to prevent replay attacks.
 *
 * Uses conditional PutItem with attribute_not_exists to atomically
 * check and store the JTI. If the JTI already exists, the condition
 * fails and we know it's a replay attempt.
 *
 * @param dbClient - DynamoDB document client
 * @param tableName - DynamoDB table name
 * @param payload - Parsed DPoP payload containing jti
 * @param thumbprint - JWK thumbprint of the signing key
 * @returns True if stored successfully, false if JTI already exists (replay)
 */
async function storeJti(
    dbClient: DynamoDBDocumentClient,
    tableName: string,
    payload: DPoPPayload,
    thumbprint: string
): Promise<boolean> {
    const now = new Date().toISOString();
    // TTL = iat + max proof age + clock skew buffer
    const ttl = payload.iat + DPOP_PROOF_MAX_AGE_SECONDS + 60;

    try {
        await dbClient.send(
            new PutCommand({
                TableName: tableName,
                Item: {
                    PK: `DPOP_JTI#${payload.jti}`,
                    SK: 'METADATA',
                    entityType: 'DPOP_JTI',
                    jti: payload.jti,
                    thumbprint,
                    htm: payload.htm,
                    htu: payload.htu,
                    ttl,
                    createdAt: now,
                },
                // Atomic check: only succeed if JTI doesn't exist
                ConditionExpression: 'attribute_not_exists(PK)',
            })
        );
        return true;
    } catch (err) {
        if ((err as Error).name === 'ConditionalCheckFailedException') {
            // JTI already exists - replay detected
            return false;
        }
        // Re-throw other errors
        throw err;
    }
}

// =============================================================================
// DPoP Handler
// =============================================================================

/**
 * Validate DPoP proof and store JTI for replay prevention.
 *
 * This function handles the complete DPoP validation flow:
 * 1. Check if DPoP header is present
 * 2. Validate the DPoP proof (signature, claims, timing)
 * 3. Store JTI in DynamoDB for replay prevention
 * 4. Optionally validate thumbprint matches expected value (for refresh)
 *
 * @param options - DPoP handler options
 * @returns Handler result with thumbprint if valid
 */
export async function handleDPoP(options: DPoPHandlerOptions): Promise<DPoPHandlerResult> {
    const { dpopHeader, httpMethod, tokenEndpointUrl, tableName, dbClient, logger, expectedThumbprint } = options;

    // No DPoP header - standard flow (no binding)
    if (!dpopHeader) {
        // If we expected a thumbprint (refresh token with DPoP binding), fail
        if (expectedThumbprint) {
            logger.warn('DPoP proof required but not provided', { expectedThumbprint });
            return {
                valid: false,
                errorCode: 'invalid_grant',
                errorDescription: 'DPoP proof required for this refresh token',
                dpopUsed: false,
            };
        }
        return { valid: true, dpopUsed: false };
    }

    logger.info('DPoP proof received, validating');

    // Validate the DPoP proof
    const validation: DPoPValidationResultExtended = validateDPoPProofExtended(dpopHeader, {
        httpMethod,
        httpUri: tokenEndpointUrl,
    });

    if (!validation.valid) {
        logger.warn('DPoP proof validation failed', { error: validation.error });
        return {
            valid: false,
            errorCode: 'invalid_dpop_proof',
            errorDescription: validation.error || 'Invalid DPoP proof',
            dpopUsed: true,
        };
    }

    // Check thumbprint matches expected value (for refresh token binding)
    if (expectedThumbprint && validation.thumbprint !== expectedThumbprint) {
        logger.warn('DPoP key binding mismatch', {
            expected: expectedThumbprint,
            actual: validation.thumbprint,
        });
        return {
            valid: false,
            errorCode: 'invalid_grant',
            errorDescription: 'DPoP key binding mismatch',
            dpopUsed: true,
        };
    }

    // Store JTI for replay prevention
    if (!validation.payload) {
        logger.error('DPoP validation succeeded but payload missing');
        return {
            valid: false,
            errorCode: 'invalid_dpop_proof',
            errorDescription: 'Internal error processing DPoP proof',
            dpopUsed: true,
        };
    }

    const jtiStored = await storeJti(dbClient, tableName, validation.payload, validation.thumbprint!);
    if (!jtiStored) {
        logger.warn('DPoP proof replay detected', { jti: validation.payload.jti });
        return {
            valid: false,
            errorCode: 'invalid_dpop_proof',
            errorDescription: 'DPoP proof replay detected',
            dpopUsed: true,
        };
    }

    logger.info('DPoP proof validated and JTI stored', {
        thumbprint: validation.thumbprint,
        jti: validation.payload.jti,
    });

    return {
        valid: true,
        thumbprint: validation.thumbprint,
        dpopUsed: true,
    };
}

/**
 * Build the token endpoint URL from the issuer.
 *
 * @param issuer - OAuth issuer URL (e.g., https://auth.example.com)
 * @returns Token endpoint URL (e.g., https://auth.example.com/token)
 */
export function buildTokenEndpointUrl(issuer: string): string {
    // Remove trailing slash if present
    const base = issuer.endsWith('/') ? issuer.slice(0, -1) : issuer;
    return `${base}/token`;
}
