/**
 * OAuth Server - DPoP (Demonstrating Proof of Possession) Entity Types
 *
 * DPoP provides sender-constrained access tokens per RFC 9449.
 * JTI records prevent replay attacks via atomic conditional writes.
 *
 * Key Pattern:
 *   PK: DPOP_JTI#<jti>
 *   SK: METADATA
 *   TTL: iat + 300 (auto-cleanup after proof expiry window)
 *
 * @see RFC 9449 - OAuth 2.0 Demonstrating Proof of Possession (DPoP)
 * @see RFC 7638 - JSON Web Key (JWK) Thumbprint
 */

// =============================================================================
// DPoP JTI Entity (Replay Prevention)
// =============================================================================

/**
 * DPoP JTI record for replay attack prevention.
 *
 * Each DPoP proof contains a unique jti claim. We store seen JTIs
 * with a short TTL to detect replay attempts within the proof validity window.
 *
 * Storage Strategy:
 * - Conditional PutItem with attribute_not_exists(PK) = atomic dedup
 * - TTL auto-deletes records after proof would be rejected anyway
 * - No GSI needed - only point lookups by JTI
 *
 * @see RFC 9449 Section 11.1 - Replay of DPoP Proofs
 */
export interface DPoPJtiItem {
    /** PK pattern: DPOP_JTI#<jti_value> */
    PK: `DPOP_JTI#${string}`;
    SK: 'METADATA';

    /** Entity type discriminator */
    entityType: 'DPOP_JTI';

    /** The JTI value from the DPoP proof */
    jti: string;

    /** JWK thumbprint of the key that signed this proof */
    thumbprint: string;

    /** HTTP method the proof was bound to */
    htm: string;

    /** HTTP URI the proof was bound to */
    htu: string;

    /** TTL for automatic cleanup (iat + MAX_PROOF_AGE_SECONDS) */
    ttl: number;

    /** ISO 8601 timestamp when this JTI was first seen */
    createdAt: string;
}

// =============================================================================
// DPoP Binding Types
// =============================================================================

/**
 * DPoP confirmation claim for access tokens per RFC 9449 Section 6.
 *
 * When a token is bound to a DPoP key, the access token includes
 * a cnf (confirmation) claim with the JWK thumbprint.
 */
export interface DPoPConfirmation {
    /** JWK SHA-256 Thumbprint per RFC 7638 */
    jkt: string;
}

/**
 * DPoP binding information stored with refresh tokens.
 *
 * When a refresh token is issued with DPoP binding, subsequent
 * refresh requests MUST use the same DPoP key.
 */
export interface DPoPBinding {
    /** JWK SHA-256 Thumbprint - must match on refresh */
    jkt: string;

    /** ISO 8601 timestamp when binding was established */
    boundAt: string;
}

// =============================================================================
// DPoP Token Response Types
// =============================================================================

/**
 * Token type for DPoP-bound tokens.
 * Per RFC 9449 Section 5, DPoP tokens use "DPoP" instead of "Bearer".
 */
export type DPoPTokenType = 'DPoP';

/**
 * Standard Bearer token type for non-DPoP tokens.
 */
export type BearerTokenType = 'Bearer';

/**
 * Union of supported token types.
 */
export type TokenType = DPoPTokenType | BearerTokenType;
