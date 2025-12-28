/**
 * OAuth Server - Token Entity Types
 *
 * Authorization codes and refresh tokens stored in DynamoDB.
 *
 * Security:
 * - Authorization codes are single-use (used flag prevents replay)
 * - Refresh tokens are stored as SHA-256 hashes (never plaintext)
 * - Token rotation creates audit trail via replacedByHash
 *
 * @see OAuth 2.1 Draft Section 4.1 - Authorization Code Grant
 * @see OAuth 2.1 Draft Section 4.3 - Refresh Token Grant
 * @see RFC 7636 - Proof Key for Code Exchange (PKCE)
 */

import type { BaseItem } from './base';

// =============================================================================
// Authorization Code Entity
// PK: CODE#<code>  SK: METADATA
// GSI1PK: CLIENT#<client_id>  GSI1SK: CODE#<timestamp>
// =============================================================================

/**
 * Authorization code stored in DynamoDB.
 * Single-use credential exchanged for tokens at the token endpoint.
 *
 * OAuth 2.1 Requirements:
 * - MUST be single-use (Section 4.1.2)
 * - MUST be bound to client_id (Section 4.1.3)
 * - MUST be bound to redirect_uri (Section 4.1.3)
 * - MUST be bound to code_challenge for PKCE (Section 4.1.3)
 * - SHOULD expire shortly after issuance (recommended: 10 minutes)
 *
 * @see OAuth 2.1 Section 1.3.1 - Authorization Code
 * @see OAuth 2.1 Section 4.1.2 - Authorization Response
 * @see OAuth 2.1 Section 4.1.3 - Token Endpoint Extension
 */
export interface AuthCodeItem extends BaseItem {
    /** PK pattern: CODE#<authorization_code> */
    PK: `CODE#${string}`;
    SK: 'METADATA';
    entityType: 'AUTH_CODE';

    /** The authorization code value (cryptographically random) */
    code: string;

    /** PKCE code_challenge from original authorization request */
    codeChallenge: string;

    /** PKCE method - must match original request */
    codeChallengeMethod: 'S256';

    /** Client that this code was issued to */
    clientId: string;

    /** Authenticated user's subject identifier */
    sub: string;

    /** Granted scopes (space-delimited) */
    scope: string;

    /** redirect_uri from original request - must match at token exchange */
    redirectUri: string;

    /** OIDC nonce for ID token binding */
    nonce?: string;

    /** Whether this code has been exchanged - prevents replay attacks */
    used: boolean;

    /** ISO 8601 timestamp when code was issued */
    issuedAt: string;
}

// =============================================================================
// Refresh Token Entity
// PK: REFRESH#<token_hash>  SK: METADATA
// GSI1PK: USER#<sub>  GSI1SK: REFRESH#<timestamp>
// =============================================================================

/**
 * Refresh token stored in DynamoDB.
 * Used to obtain new access tokens without re-authentication.
 *
 * Security: Token value is never stored - only SHA-256 hash.
 *
 * OAuth 2.1 Requirements:
 * - MUST be bound to client_id (Section 4.3.1)
 * - Token rotation is RECOMMENDED (Section 4.3.3)
 * - SHOULD be sender-constrained when possible
 *
 * DPoP Binding (RFC 9449):
 * - When issued with DPoP, dpopJkt stores the key thumbprint
 * - Refresh requests MUST use the same DPoP key
 * - Prevents stolen refresh tokens from being used
 *
 * Key Patterns:
 * - PK: REFRESH#<token_hash>, SK: METADATA
 * - GSI1PK: USER#<sub>, GSI1SK: REFRESH#<timestamp> (user's tokens)
 * - GSI2PK: FAMILY#<family_id>, GSI2SK: REFRESH#<timestamp> (token family)
 *
 * @see OAuth 2.1 Section 1.3.2 - Refresh Token
 * @see OAuth 2.1 Section 4.3 - Refresh Token Grant
 * @see RFC 9449 Section 6 - DPoP-Bound Refresh Tokens
 */
export interface RefreshTokenItem extends BaseItem {
    /** PK pattern: REFRESH#<sha256_hash_of_token> */
    PK: `REFRESH#${string}`;
    SK: 'METADATA';
    entityType: 'REFRESH_TOKEN';

    /** SHA256 hash of the actual token (we never store raw tokens) */
    tokenHash: string;

    /** Token family ID for rotation chain tracking */
    familyId: string;

    /** Whether this token has been rotated (replaced by a new one) */
    rotated: boolean;

    /** Client ID this token was issued to */
    clientId: string;

    /** User's subject identifier */
    sub: string;

    /** Space-delimited scope string */
    scope: string;

    /** ISO 8601 timestamp when the token was issued */
    issuedAt: string;

    /** ISO 8601 timestamp when the token was rotated (if rotated) */
    rotatedAt?: string;

    /** Hash of the token that replaced this one (if rotated) */
    replacedByHash?: string;

    /** Reason for revocation (if revoked via family revocation) */
    revokedReason?: string;

    /** ISO 8601 timestamp when the token was revoked (if revoked) */
    revokedAt?: string;

    /** GSI2 Partition Key - For token family queries */
    GSI2PK?: `FAMILY#${string}`;

    /** GSI2 Sort Key - For ordering within family */
    GSI2SK?: string;

    // =========================================================================
    // DPoP Binding (RFC 9449)
    // =========================================================================

    /**
     * DPoP JWK thumbprint for sender-constrained tokens.
     *
     * When set, refresh requests MUST include a valid DPoP proof
     * signed by the same key (thumbprint must match).
     *
     * @see RFC 9449 Section 6 - DPoP-Bound Refresh Tokens
     * @see RFC 7638 - JSON Web Key (JWK) Thumbprint
     */
    dpopJkt?: string;
}

// =============================================================================
// Type Guard Declarations
// =============================================================================

// Note: Type guard implementations are provided in the shared module (type-guards.ts).
// These declarations exist for documentation purposes only.
