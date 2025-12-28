/**
 * OIDC RP-Initiated Logout - Validation Utilities
 *
 * Validates logout request parameters and ID tokens per OpenID Connect RP-Initiated Logout 1.0.
 *
 * @see https://openid.net/specs/openid-connect-rpinitiated-1_0.html
 */

import { createVerify } from 'node:crypto';
import { base64UrlDecode } from '@oauth-server/shared';
import type { LogoutRequestParams, IdTokenPayload, ClientRecord } from './types';

// =============================================================================
// Request Parameter Validation
// =============================================================================

/**
 * Parse and validate logout request query parameters.
 *
 * Per OIDC RP-Initiated Logout 1.0 Section 2:
 * - id_token_hint is RECOMMENDED (we require it for security)
 * - post_logout_redirect_uri requires id_token_hint or client_id
 * - state is OPTIONAL
 *
 * @param queryParams - Raw query string parameters
 * @returns Parsed logout request parameters
 */
export function parseLogoutParams(
    queryParams: Record<string, string | undefined>
): LogoutRequestParams {
    return {
        id_token_hint: queryParams['id_token_hint'],
        post_logout_redirect_uri: queryParams['post_logout_redirect_uri'],
        state: queryParams['state'],
        client_id: queryParams['client_id'],
        ui_locales: queryParams['ui_locales'],
    };
}

/**
 * Validate that required parameters are present.
 *
 * Security: We require id_token_hint to prevent unauthorized logout attacks.
 * This is stricter than the spec (which only RECOMMENDS it) but provides
 * better security by ensuring only the legitimate token holder can logout.
 *
 * @param params - Parsed logout parameters
 * @returns Validation error message or null if valid
 */
export function validateRequiredParams(params: LogoutRequestParams): string | null {
    if (!params.id_token_hint) {
        return 'id_token_hint is required for logout';
    }
    return null;
}

// =============================================================================
// ID Token Verification
// =============================================================================

/**
 * Verify an ID token JWT and extract its payload.
 *
 * Per OIDC RP-Initiated Logout 1.0 Section 2.1:
 * - The ID token MAY be expired (we still accept it for logout)
 * - The signature MUST be valid
 * - The issuer MUST match the expected issuer
 *
 * Validation sequence:
 * 1. JWT structure (header.payload.signature)
 * 2. Algorithm is RS256 (asymmetric, KMS-compatible)
 * 3. Cryptographic signature via KMS public key
 * 4. Issuer claim matches expected value
 * 5. Expiration is NOT checked (expired tokens are valid for logout)
 *
 * @param token - The JWT ID token string
 * @param publicKey - PEM-encoded public key from KMS
 * @param expectedIssuer - Expected issuer URL for validation
 * @returns Decoded payload if valid, null for any validation failure
 */
export function verifyIdToken(
    token: string,
    publicKey: string,
    expectedIssuer: string
): IdTokenPayload | null {
    const parts = token.split('.');
    if (parts.length !== 3) {
        return null;
    }

    const [headerB64, payloadB64, signatureB64] = parts;

    try {
        // Validate header - must be RS256
        const header = JSON.parse(base64UrlDecode(headerB64).toString('utf8')) as { alg?: string };
        if (header.alg !== 'RS256') {
            return null;
        }

        // Decode payload
        const payload = JSON.parse(base64UrlDecode(payloadB64).toString('utf8')) as IdTokenPayload;

        // Verify cryptographic signature
        const verifier = createVerify('RSA-SHA256');
        verifier.update(`${headerB64}.${payloadB64}`);
        if (!verifier.verify(publicKey, base64UrlDecode(signatureB64))) {
            return null;
        }

        // Validate issuer (MUST match)
        if (payload.iss !== expectedIssuer) {
            return null;
        }

        // Note: We intentionally do NOT check expiration for logout
        // Per OIDC RP-Initiated Logout 1.0, expired tokens are valid for logout

        return payload;
    } catch {
        return null;
    }
}

// =============================================================================
// Redirect URI Validation
// =============================================================================

/**
 * Validate post_logout_redirect_uri against client configuration.
 *
 * Per OIDC RP-Initiated Logout 1.0 Section 2.1:
 * - The URI MUST have been registered with the OP
 * - Exact string matching is REQUIRED (no wildcards)
 *
 * @param redirectUri - The requested post_logout_redirect_uri
 * @param client - Client configuration from DynamoDB
 * @returns true if the URI is registered, false otherwise
 */
export function validatePostLogoutRedirectUri(
    redirectUri: string,
    client: ClientRecord
): boolean {
    // Check if client has registered post-logout redirect URIs
    const registeredUris = client.postLogoutRedirectUris;
    if (!registeredUris || registeredUris.length === 0) {
        return false;
    }

    // Exact string match required per spec
    return registeredUris.includes(redirectUri);
}

/**
 * Extract client_id from ID token audience claim.
 *
 * The audience can be a single string or an array of strings.
 * For logout, we use the first audience value as the client_id.
 *
 * @param payload - Decoded ID token payload
 * @returns Client ID extracted from audience
 */
export function extractClientIdFromToken(payload: IdTokenPayload): string {
    if (Array.isArray(payload.aud)) {
        return payload.aud[0];
    }
    return payload.aud;
}
