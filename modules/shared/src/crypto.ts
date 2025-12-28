/**
 * OAuth Server - Cryptographic Utilities
 *
 * Secure cryptographic operations for OAuth 2.1 compliance.
 * Implements PKCE verification, token hashing, and secure random generation.
 *
 * Security Architecture:
 * - All comparisons use constant-time algorithms to prevent timing attacks
 * - Token hashing uses SHA-256 for secure storage (tokens never stored in plaintext)
 * - Random generation uses Node.js crypto module (CSPRNG backed by OS entropy)
 * - PKCE verification enforces S256 only per OAuth 2.1 mandate
 *
 * Implementation Notes:
 * - SHA-256 is used consistently for all hashing operations
 * - Base64url encoding follows RFC 4648 Section 5 (URL-safe, no padding)
 * - HMAC-SHA256 is used for CSRF tokens to bind them to sessions
 * - All functions are pure and stateless for predictable behavior
 *
 * Thread Safety:
 * - All functions are thread-safe and can be called concurrently
 * - No shared mutable state exists in this module
 *
 * @see RFC 7636 - Proof Key for Code Exchange (PKCE)
 * @see RFC 4648 Section 5 - Base64url Encoding
 * @see OAuth 2.1 Draft Section 4.1.1 - PKCE Requirements
 * @see RFC 9700 Section 4.8 - PKCE Security Considerations
 */

import { createHash, createHmac, randomBytes, timingSafeEqual } from 'node:crypto';

// =============================================================================
// Constants
// =============================================================================

/** Hash algorithm used for PKCE and token hashing */
const HASH_ALGORITHM = 'sha256';

/** Default entropy bytes for secure random generation */
const DEFAULT_ENTROPY_BYTES = 32;

// =============================================================================
// PKCE (Proof Key for Code Exchange)
// =============================================================================

/**
 * Generate a cryptographically secure code verifier for PKCE.
 * Per RFC 7636 Section 4.1, must be 43-128 characters from unreserved URI characters.
 *
 * @returns A 43-character base64url-encoded random string (32 bytes of entropy)
 *
 * @see RFC 7636 Section 4.1 - code_verifier = 43*128unreserved
 * @see RFC 3986 Section 2.3 - unreserved = ALPHA / DIGIT / "-" / "." / "_" / "~"
 */
export function generateCodeVerifier(): string {
    return base64UrlEncode(randomBytes(DEFAULT_ENTROPY_BYTES));
}

/**
 * Generate a code challenge from a code verifier using S256 method.
 * S256: BASE64URL(SHA256(code_verifier))
 *
 * OAuth 2.1 mandates S256 only - the "plain" method is explicitly forbidden.
 *
 * @param codeVerifier - The PKCE code verifier
 * @returns The S256 code challenge (43 characters)
 *
 * @see RFC 7636 Section 4.2 - code_challenge = BASE64URL(SHA256(code_verifier))
 * @see OAuth 2.1 Draft Section 4.1.1 - S256 is mandatory
 */
export function generateCodeChallenge(codeVerifier: string): string {
    const hash = createHash(HASH_ALGORITHM).update(codeVerifier, 'ascii').digest();
    return base64UrlEncode(hash);
}

/**
 * Verify a PKCE code verifier against a stored code challenge.
 * Uses constant-time comparison to prevent timing attacks.
 *
 * This function computes S256(code_verifier) and compares it to the stored challenge.
 * Per OAuth 2.1, only S256 method is supported.
 *
 * @param codeVerifier - The code verifier from the token request
 * @param codeChallenge - The stored code challenge from the authorization request
 * @returns True if the verifier matches the challenge
 *
 * @see RFC 7636 Section 4.6 - Server Verifies code_verifier
 * @see OAuth 2.1 Draft Section 4.1.3 - Token Endpoint Extension
 */
export function verifyPkce(codeVerifier: string, codeChallenge: string): boolean {
    const computed = generateCodeChallenge(codeVerifier);

    // Use constant-time comparison to prevent timing attacks
    if (computed.length !== codeChallenge.length) {
        return false;
    }

    try {
        return timingSafeEqual(
            Buffer.from(computed, 'utf-8'),
            Buffer.from(codeChallenge, 'utf-8')
        );
    } catch {
        return false;
    }
}

// =============================================================================
// Token Hashing
// =============================================================================

/**
 * Hash a token for secure storage.
 * Tokens should never be stored in plaintext.
 *
 * Uses SHA-256 which provides:
 * - 256-bit output (64 hex characters)
 * - Collision resistance suitable for token identification
 * - Fast computation for high-throughput token validation
 *
 * @param token - The raw token value
 * @returns SHA-256 hash of the token (hex encoded, 64 characters)
 *
 * @example
 * ```typescript
 * const rawToken = generateSecureRandom();
 * const tokenHash = hashToken(rawToken);
 * // Store tokenHash in database, return rawToken to client
 * ```
 */
export function hashToken(token: string): string {
    return createHash(HASH_ALGORITHM).update(token).digest('hex');
}

// =============================================================================
// Base64URL Encoding
// =============================================================================

/**
 * Encode a buffer to base64url format (RFC 4648 Section 5).
 * Base64url is URL-safe: '+' → '-', '/' → '_', no padding.
 *
 * @param data - Buffer or string to encode
 * @returns Base64url-encoded string
 */
export function base64UrlEncode(data: Buffer | string): string {
    const buffer = typeof data === 'string' ? Buffer.from(data) : data;
    return buffer
        .toString('base64')
        .replace(/\+/g, '-')
        .replace(/\//g, '_')
        .replace(/=+$/, '');
}

/**
 * Decode a base64url-encoded string.
 *
 * @param encoded - Base64url-encoded string
 * @returns Decoded buffer
 */
export function base64UrlDecode(encoded: string): Buffer {
    // Restore standard base64 characters
    let base64 = encoded.replace(/-/g, '+').replace(/_/g, '/');

    // Add padding if needed
    const padding = 4 - (base64.length % 4);
    if (padding !== 4) {
        base64 += '='.repeat(padding);
    }

    return Buffer.from(base64, 'base64');
}

// =============================================================================
// Secure Random Generation
// =============================================================================

/**
 * Generate a cryptographically secure random string.
 * Suitable for authorization codes, state parameters, etc.
 *
 * Uses the Node.js crypto module which is backed by the operating system's
 * cryptographically secure pseudorandom number generator (CSPRNG).
 *
 * @param byteLength - Number of random bytes (default: 32, providing 256 bits of entropy)
 * @returns Base64url-encoded random string
 *
 * @example
 * ```typescript
 * const authCode = generateSecureRandom(32);  // 43 characters
 * const state = generateSecureRandom(16);     // 22 characters
 * ```
 */
export function generateSecureRandom(byteLength = DEFAULT_ENTROPY_BYTES): string {
    return base64UrlEncode(randomBytes(byteLength));
}

/**
 * Generate a secure CSRF token bound to a session.
 * Uses HMAC-SHA256 to create a token that can only be verified with the secret.
 *
 * The token is deterministic for a given session/secret pair, allowing
 * verification without storing the token server-side.
 *
 * @param sessionId - Session identifier to bind the token to
 * @param secret - Server-side secret for HMAC (must be kept secure, min 32 bytes recommended)
 * @returns HMAC-based CSRF token (hex encoded, 64 characters)
 *
 * @example
 * ```typescript
 * const csrfToken = generateCsrfToken(sessionId, process.env.CSRF_SECRET);
 * // Include in form as hidden field, verify on submission
 * ```
 */
export function generateCsrfToken(sessionId: string, secret: string): string {
    return createHmac(HASH_ALGORITHM, secret).update(sessionId).digest('hex');
}

/**
 * Verify a CSRF token using constant-time comparison.
 *
 * @param sessionId - Session identifier
 * @param token - Token to verify
 * @param secret - Server-side secret
 * @returns True if the token is valid
 */
export function verifyCsrfToken(sessionId: string, token: string, secret: string): boolean {
    const expected = generateCsrfToken(sessionId, secret);

    if (expected.length !== token.length) {
        return false;
    }

    try {
        return timingSafeEqual(
            Buffer.from(expected, 'utf-8'),
            Buffer.from(token, 'utf-8')
        );
    } catch {
        return false;
    }
}

/**
 * Generate a token family ID for refresh token rotation tracking.
 *
 * Token families allow detection of refresh token reuse attacks.
 * When a refresh token is rotated, the new token inherits the same familyId.
 * If a rotated token is reused, the entire family can be revoked.
 *
 * @returns A cryptographically secure family identifier (UUID v4 format)
 *
 * @example
 * ```typescript
 * const familyId = generateTokenFamilyId();
 * // Store with refresh token, inherit on rotation
 * ```
 *
 * @see OAuth 2.1 Draft Section 4.3.3 - Refresh Token Rotation
 */
export function generateTokenFamilyId(): string {
    // Generate 16 random bytes and format as UUID v4
    const bytes = randomBytes(16);
    // Set version (4) and variant (RFC 4122)
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;

    const hex = bytes.toString('hex');
    return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}
