/**
 * OAuth Server - DPoP (Demonstrating Proof of Possession) Support
 *
 * Implements RFC 9449 - OAuth 2.0 Demonstrating Proof of Possession (DPoP).
 * DPoP provides sender-constrained access tokens that are bound to a specific
 * client's cryptographic key, preventing token theft and replay attacks.
 *
 * Security Benefits:
 * - Tokens are bound to the client's private key
 * - Prevents token theft (stolen tokens are unusable without the key)
 * - Replay protection via jti and iat claims
 * - Proof of possession at both token endpoint and resource servers
 *
 * Implementation Notes:
 * - DPoP proofs are JWTs signed with the client's private key
 * - The public key is embedded in the JWT header (jwk claim)
 * - Proofs are single-use and time-limited
 * - Access tokens include a cnf claim with the key thumbprint
 *
 * @module shared/dpop
 * @see RFC 9449 - OAuth 2.0 Demonstrating Proof of Possession (DPoP)
 * @see RFC 7638 - JSON Web Key (JWK) Thumbprint
 */

import * as crypto from 'node:crypto';
import { createHash, createVerify, createPublicKey, randomBytes, constants } from 'node:crypto';

// =============================================================================
// Constants
// =============================================================================

/** Maximum allowed clock skew for DPoP proof validation (seconds) */
const MAX_CLOCK_SKEW_SECONDS = 60;

/** Maximum age of a DPoP proof (seconds) */
const MAX_PROOF_AGE_SECONDS = 300;

/** Supported DPoP signing algorithms per RFC 9449 */
const SUPPORTED_ALGORITHMS = ['RS256', 'RS384', 'RS512', 'ES256', 'ES384', 'ES512', 'PS256', 'PS384', 'PS512'] as const;

type DPoPAlgorithm = typeof SUPPORTED_ALGORITHMS[number];

// =============================================================================
// Types - JWK
// =============================================================================

/**
 * JSON Web Key interface for DPoP.
 * Subset of the full JWK spec needed for DPoP.
 */
export interface DPoPJwk {
    /** Key type (RSA, EC, OKP) */
    kty: string;
    /** Algorithm */
    alg?: string;
    /** Key ID */
    kid?: string;
    /** RSA public exponent */
    e?: string;
    /** RSA modulus */
    n?: string;
    /** EC curve */
    crv?: string;
    /** EC x coordinate */
    x?: string;
    /** EC y coordinate */
    y?: string;
    /** Private key (should NOT be present in DPoP proofs) */
    d?: string;
    /** RSA prime p (should NOT be present) */
    p?: string;
    /** RSA prime q (should NOT be present) */
    q?: string;
}

// =============================================================================
// Types - DPoP Proof
// =============================================================================

/**
 * DPoP proof JWT header per RFC 9449 Section 4.2.
 */
export interface DPoPHeader {
    /** Type - MUST be "dpop+jwt" */
    typ: 'dpop+jwt';
    /** Algorithm - asymmetric algorithm from SUPPORTED_ALGORITHMS */
    alg: DPoPAlgorithm;
    /** JSON Web Key - the public key */
    jwk: DPoPJwk;
}

/**
 * DPoP proof JWT payload per RFC 9449 Section 4.2.
 */
export interface DPoPPayload {
    /** JWT ID - unique identifier for replay protection */
    jti: string;
    /** HTTP method of the request */
    htm: string;
    /** HTTP URI of the request (without query and fragment) */
    htu: string;
    /** Issued at timestamp */
    iat: number;
    /** Access token hash (for resource server requests) */
    ath?: string;
    /** Nonce from server (if required) */
    nonce?: string;
}

/**
 * Result of DPoP proof validation.
 */
export interface DPoPValidationResult {
    /** Whether the proof is valid */
    valid: boolean;
    /** Error message if invalid */
    error?: string;
    /** JWK thumbprint of the public key (for cnf claim) */
    thumbprint?: string;
    /** The public key from the proof */
    publicKey?: DPoPJwk;
}

/**
 * Options for DPoP proof validation.
 */
export interface DPoPValidationOptions {
    /** Expected HTTP method */
    httpMethod: string;
    /** Expected HTTP URI (scheme + host + path, no query/fragment) */
    httpUri: string;
    /** Expected access token hash (for resource server validation) */
    accessTokenHash?: string;
    /** Server-provided nonce (if nonce was required) */
    expectedNonce?: string;
    /** Set of recently seen jti values for replay detection */
    seenJtis?: Set<string>;
}

// =============================================================================
// JWK Thumbprint Calculation (RFC 7638)
// =============================================================================

/**
 * Calculate the JWK thumbprint per RFC 7638.
 *
 * The thumbprint is a base64url-encoded SHA-256 hash of the canonical
 * JSON representation of the JWK's required members.
 *
 * @param jwk - The JSON Web Key
 * @returns Base64url-encoded SHA-256 thumbprint
 */
export function calculateJwkThumbprint(jwk: DPoPJwk): string {
    // Build canonical JSON representation per RFC 7638 Section 3
    // Members must be in lexicographic order
    let canonical: Record<string, unknown>;

    switch (jwk.kty) {
        case 'RSA':
            canonical = {
                e: jwk.e,
                kty: jwk.kty,
                n: jwk.n,
            };
            break;
        case 'EC':
            canonical = {
                crv: jwk.crv,
                kty: jwk.kty,
                x: jwk.x,
                y: jwk.y,
            };
            break;
        case 'OKP':
            canonical = {
                crv: jwk.crv,
                kty: jwk.kty,
                x: jwk.x,
            };
            break;
        default:
            throw new Error(`Unsupported key type: ${jwk.kty}`);
    }

    // Sort keys lexicographically and stringify without whitespace
    const sortedKeys = Object.keys(canonical).sort();
    const sortedObj: Record<string, unknown> = {};
    for (const key of sortedKeys) {
        sortedObj[key] = canonical[key];
    }
    const json = JSON.stringify(sortedObj);

    // SHA-256 hash and base64url encode
    const hash = createHash('sha256').update(json, 'utf8').digest();
    return hash.toString('base64')
        .replace(/\+/g, '-')
        .replace(/\//g, '_')
        .replace(/=+$/, '');
}

// =============================================================================
// Signature Verification Helpers
// =============================================================================

/**
 * Convert a JWK to PEM format for Node.js crypto verification.
 *
 * Uses Node.js native crypto.createPublicKey which supports JWK input
 * directly (Node.js 16+).
 *
 * @param jwk - The JSON Web Key (public key only)
 * @returns PEM-encoded public key in SPKI format
 */
function jwkToPem(jwk: DPoPJwk): string {
    const keyObject = createPublicKey({ key: jwk as crypto.JsonWebKey, format: 'jwk' });
    return keyObject.export({ type: 'spki', format: 'pem' }) as string;
}

/**
 * Map JWA algorithm identifier to Node.js crypto algorithm name.
 *
 * @param alg - JWA algorithm (RS256, ES256, PS256, etc.)
 * @returns Node.js crypto algorithm name
 */
function getVerifyAlgorithm(alg: DPoPAlgorithm): string {
    switch (alg) {
        case 'RS256':
        case 'PS256':
            return 'RSA-SHA256';
        case 'RS384':
        case 'PS384':
            return 'RSA-SHA384';
        case 'RS512':
        case 'PS512':
            return 'RSA-SHA512';
        case 'ES256':
            return 'SHA256';
        case 'ES384':
            return 'SHA384';
        case 'ES512':
            return 'SHA512';
        default:
            throw new Error(`Unsupported algorithm: ${alg}`);
    }
}

/**
 * Decode base64url string to Buffer.
 *
 * @param str - Base64url-encoded string
 * @returns Decoded buffer
 */
function base64UrlDecode(str: string): Buffer {
    const padded = str + '='.repeat((4 - (str.length % 4)) % 4);
    return Buffer.from(padded.replace(/-/g, '+').replace(/_/g, '/'), 'base64');
}

/**
 * Verify JWT signature using the embedded JWK public key.
 *
 * Supports RS256/384/512, ES256/384/512, and PS256/384/512 algorithms.
 * PS* algorithms use RSA-PSS padding per RFC 7518.
 * ES* algorithms use IEEE P1363 signature format (raw R||S) per RFC 7515.
 *
 * @param header - Parsed JWT header containing algorithm and JWK
 * @param signingInput - The "header.payload" string that was signed
 * @param signature - Base64url-encoded signature
 * @returns True if signature is valid, false otherwise
 */
function verifySignature(header: DPoPHeader, signingInput: string, signature: string): boolean {
    try {
        const pem = jwkToPem(header.jwk);
        const algorithm = getVerifyAlgorithm(header.alg);
        const signatureBuffer = base64UrlDecode(signature);

        const verifier = createVerify(algorithm);
        verifier.update(signingInput);

        // Handle PSS padding for PS* algorithms
        if (header.alg.startsWith('PS')) {
            return verifier.verify(
                {
                    key: pem,
                    padding: constants.RSA_PKCS1_PSS_PADDING,
                    saltLength: constants.RSA_PSS_SALTLEN_DIGEST,
                },
                signatureBuffer
            );
        }

        // Handle ES* algorithms - JWS uses IEEE P1363 format (raw R||S concatenation)
        // Node.js crypto expects DER by default, so we specify ieee-p1363
        if (header.alg.startsWith('ES')) {
            return verifier.verify(
                {
                    key: pem,
                    dsaEncoding: 'ieee-p1363',
                },
                signatureBuffer
            );
        }

        // Standard verification for RS* algorithms
        return verifier.verify(pem, signatureBuffer);
    } catch {
        return false;
    }
}

// =============================================================================
// DPoP Proof Parsing
// =============================================================================

/**
 * Parse a DPoP proof JWT without verification.
 *
 * @param proof - The DPoP proof JWT string
 * @returns Parsed header and payload, or null if malformed
 */
function parseDPoPProof(proof: string): { header: DPoPHeader; payload: DPoPPayload; signature: string } | null {
    const parts = proof.split('.');
    if (parts.length !== 3) {
        return null;
    }

    try {
        const headerJson = Buffer.from(parts[0], 'base64url').toString('utf8');
        const payloadJson = Buffer.from(parts[1], 'base64url').toString('utf8');

        const header = JSON.parse(headerJson) as DPoPHeader;
        const payload = JSON.parse(payloadJson) as DPoPPayload;

        return { header, payload, signature: parts[2] };
    } catch {
        return null;
    }
}

// =============================================================================
// DPoP Proof Validation
// =============================================================================

/**
 * Validate a DPoP proof per RFC 9449 Section 4.3.
 *
 * Validation steps:
 * 1. Parse the JWT and verify structure
 * 2. Verify typ is "dpop+jwt"
 * 3. Verify alg is a supported asymmetric algorithm
 * 4. Verify jwk is present and valid
 * 5. Verify signature using the embedded public key
 * 6. Verify htm matches the HTTP method
 * 7. Verify htu matches the HTTP URI
 * 8. Verify iat is recent (within clock skew)
 * 9. Verify jti is unique (replay protection)
 * 10. Verify ath if access token hash is expected
 * 11. Verify nonce if server nonce was provided
 *
 * @param proof - The DPoP proof JWT from the DPoP header
 * @param options - Validation options
 * @returns Validation result with thumbprint if valid
 */
export function validateDPoPProof(
    proof: string,
    options: DPoPValidationOptions
): DPoPValidationResult {
    // Step 1: Parse the JWT
    const parsed = parseDPoPProof(proof);
    if (!parsed) {
        return { valid: false, error: 'Malformed DPoP proof' };
    }

    const { header, payload } = parsed;

    // Step 2: Verify typ
    if (header.typ !== 'dpop+jwt') {
        return { valid: false, error: 'Invalid DPoP proof type' };
    }

    // Step 3: Verify alg
    if (!SUPPORTED_ALGORITHMS.includes(header.alg)) {
        return { valid: false, error: `Unsupported DPoP algorithm: ${header.alg}` };
    }

    // Step 4: Verify jwk is present
    if (!header.jwk || typeof header.jwk !== 'object') {
        return { valid: false, error: 'Missing or invalid jwk in DPoP proof' };
    }

    // Verify jwk doesn't contain private key material
    if ('d' in header.jwk || 'p' in header.jwk || 'q' in header.jwk) {
        return { valid: false, error: 'DPoP proof jwk must not contain private key' };
    }

    // Step 5: Verify signature using the embedded public key
    const signingInput = `${proof.split('.')[0]}.${proof.split('.')[1]}`;
    if (!verifySignature(header, signingInput, parsed.signature)) {
        return { valid: false, error: 'Invalid DPoP proof signature' };
    }

    try {
        const thumbprint = calculateJwkThumbprint(header.jwk);

        // Step 6: Verify htm
        if (payload.htm !== options.httpMethod) {
            return { valid: false, error: 'DPoP htm mismatch' };
        }

        // Step 7: Verify htu
        if (payload.htu !== options.httpUri) {
            return { valid: false, error: 'DPoP htu mismatch' };
        }

        // Step 8: Verify iat
        const now = Math.floor(Date.now() / 1000);
        if (payload.iat > now + MAX_CLOCK_SKEW_SECONDS) {
            return { valid: false, error: 'DPoP proof issued in the future' };
        }
        if (payload.iat < now - MAX_PROOF_AGE_SECONDS) {
            return { valid: false, error: 'DPoP proof too old' };
        }

        // Step 9: Verify jti uniqueness
        if (!payload.jti || typeof payload.jti !== 'string') {
            return { valid: false, error: 'Missing jti in DPoP proof' };
        }
        if (options.seenJtis?.has(payload.jti)) {
            return { valid: false, error: 'DPoP proof replay detected' };
        }

        // Step 10: Verify ath if expected
        if (options.accessTokenHash) {
            if (payload.ath !== options.accessTokenHash) {
                return { valid: false, error: 'DPoP ath mismatch' };
            }
        }

        // Step 11: Verify nonce if expected
        if (options.expectedNonce) {
            if (payload.nonce !== options.expectedNonce) {
                return { valid: false, error: 'DPoP nonce mismatch' };
            }
        }

        return {
            valid: true,
            thumbprint,
            publicKey: header.jwk,
        };
    } catch (err) {
        return { valid: false, error: `DPoP validation error: ${(err as Error).message}` };
    }
}

// =============================================================================
// Access Token Hash Calculation
// =============================================================================

/**
 * Calculate the access token hash for the ath claim.
 *
 * Per RFC 9449 Section 4.2, the ath claim is the base64url-encoded
 * SHA-256 hash of the access token.
 *
 * @param accessToken - The access token string
 * @returns Base64url-encoded SHA-256 hash
 */
export function calculateAccessTokenHash(accessToken: string): string {
    const hash = createHash('sha256').update(accessToken, 'ascii').digest();
    return hash.toString('base64')
        .replace(/\+/g, '-')
        .replace(/\//g, '_')
        .replace(/=+$/, '');
}

// =============================================================================
// DPoP Nonce Generation
// =============================================================================

/**
 * Generate a DPoP nonce for replay protection.
 *
 * Per RFC 9449 Section 8, servers can require nonces to provide
 * additional replay protection beyond jti uniqueness.
 *
 * @returns A cryptographically random nonce string
 */
export function generateDPoPNonce(): string {
    return randomBytes(32).toString('base64url');
}

// =============================================================================
// Confirmation Claim (cnf) Builder
// =============================================================================

/**
 * Build the confirmation claim for DPoP-bound tokens.
 *
 * Per RFC 9449 Section 6, access tokens bound to a DPoP key
 * include a cnf claim with the JWK thumbprint.
 *
 * @param thumbprint - The JWK thumbprint from DPoP proof validation
 * @returns The cnf claim object for inclusion in the access token
 */
export function buildDPoPConfirmationClaim(thumbprint: string): { jkt: string } {
    return { jkt: thumbprint };
}

// =============================================================================
// Extended Validation Result (with parsed payload for JTI storage)
// =============================================================================

/**
 * Extended DPoP validation result including parsed payload.
 * Used when JTI needs to be stored for replay prevention.
 */
export interface DPoPValidationResultExtended extends DPoPValidationResult {
    /** Parsed DPoP payload (for JTI storage) */
    payload?: DPoPPayload;
}

/**
 * Validate a DPoP proof and return extended result with payload.
 *
 * This is the same as validateDPoPProof but also returns the parsed
 * payload for JTI storage in DynamoDB.
 *
 * @param proof - The DPoP proof JWT from the DPoP header
 * @param options - Validation options
 * @returns Extended validation result with payload if valid
 */
export function validateDPoPProofExtended(
    proof: string,
    options: DPoPValidationOptions
): DPoPValidationResultExtended {
    // Step 1: Parse the JWT
    const parsed = parseDPoPProof(proof);
    if (!parsed) {
        return { valid: false, error: 'Malformed DPoP proof' };
    }

    const { header, payload } = parsed;

    // Step 2: Verify typ
    if (header.typ !== 'dpop+jwt') {
        return { valid: false, error: 'Invalid DPoP proof type' };
    }

    // Step 3: Verify alg
    if (!SUPPORTED_ALGORITHMS.includes(header.alg)) {
        return { valid: false, error: `Unsupported DPoP algorithm: ${header.alg}` };
    }

    // Step 4: Verify jwk is present
    if (!header.jwk || typeof header.jwk !== 'object') {
        return { valid: false, error: 'Missing or invalid jwk in DPoP proof' };
    }

    // Verify jwk doesn't contain private key material
    if ('d' in header.jwk || 'p' in header.jwk || 'q' in header.jwk) {
        return { valid: false, error: 'DPoP proof jwk must not contain private key' };
    }

    // Step 5: Verify signature using the embedded public key
    const signingInput = `${proof.split('.')[0]}.${proof.split('.')[1]}`;
    if (!verifySignature(header, signingInput, parsed.signature)) {
        return { valid: false, error: 'Invalid DPoP proof signature' };
    }

    try {
        const thumbprint = calculateJwkThumbprint(header.jwk);

        // Step 6: Verify htm
        if (payload.htm !== options.httpMethod) {
            return { valid: false, error: 'DPoP htm mismatch' };
        }

        // Step 7: Verify htu
        if (payload.htu !== options.httpUri) {
            return { valid: false, error: 'DPoP htu mismatch' };
        }

        // Step 8: Verify iat
        const now = Math.floor(Date.now() / 1000);
        if (payload.iat > now + MAX_CLOCK_SKEW_SECONDS) {
            return { valid: false, error: 'DPoP proof issued in the future' };
        }
        if (payload.iat < now - MAX_PROOF_AGE_SECONDS) {
            return { valid: false, error: 'DPoP proof too old' };
        }

        // Step 9: Verify jti exists (uniqueness checked via DynamoDB)
        if (!payload.jti || typeof payload.jti !== 'string') {
            return { valid: false, error: 'Missing jti in DPoP proof' };
        }
        // Note: In-memory seenJtis check skipped - use DynamoDB for serverless
        if (options.seenJtis?.has(payload.jti)) {
            return { valid: false, error: 'DPoP proof replay detected' };
        }

        // Step 10: Verify ath if expected
        if (options.accessTokenHash) {
            if (payload.ath !== options.accessTokenHash) {
                return { valid: false, error: 'DPoP ath mismatch' };
            }
        }

        // Step 11: Verify nonce if expected
        if (options.expectedNonce) {
            if (payload.nonce !== options.expectedNonce) {
                return { valid: false, error: 'DPoP nonce mismatch' };
            }
        }

        return {
            valid: true,
            thumbprint,
            publicKey: header.jwk,
            payload,
        };
    } catch (err) {
        return { valid: false, error: `DPoP validation error: ${(err as Error).message}` };
    }
}

// =============================================================================
// Constants Export (for JTI TTL calculation)
// =============================================================================

/**
 * Maximum age of a DPoP proof in seconds.
 * Used for JTI TTL calculation in DynamoDB.
 */
export const DPOP_PROOF_MAX_AGE_SECONDS = MAX_PROOF_AGE_SECONDS;

/**
 * Maximum clock skew allowed for DPoP proofs in seconds.
 */
export const DPOP_MAX_CLOCK_SKEW_SECONDS = MAX_CLOCK_SKEW_SECONDS;
