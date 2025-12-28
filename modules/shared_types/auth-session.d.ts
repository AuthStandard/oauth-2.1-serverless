/**
 * OAuth Server - Authenticated User Session Entity Types
 *
 * Persistent authenticated sessions for users who have completed login.
 * Used to support silent authentication (prompt=none) per OIDC Core 1.0.
 *
 * Key Pattern:
 *   PK: AUTH_SESSION#<session_id>
 *   SK: METADATA
 *   GSI1PK: USER#<sub>
 *   GSI1SK: AUTH_SESSION#<timestamp>
 *
 * @see https://openid.net/specs/openid-connect-core-1_0.html#AuthRequest
 */

import type { BaseItem } from './base';

// =============================================================================
// Authenticated User Session Entity
// =============================================================================

/**
 * Persistent authenticated session for a user.
 *
 * Created after successful authentication (password, SAML, etc.).
 * Used by the authorize endpoint to support:
 * - prompt=none (silent authentication)
 * - max_age validation
 * - Session-based logout
 *
 * Lifecycle:
 * 1. Created by /authorize/callback after successful authentication
 * 2. Referenced by session cookie in browser
 * 3. Checked by /authorize for prompt=none requests
 * 4. Deleted by /logout endpoint or TTL expiration
 *
 * @see OIDC Core 1.0 Section 3.1.2.1 - Authentication Request
 */
export interface AuthenticatedSessionItem extends BaseItem {
    /** PK pattern: AUTH_SESSION#<session_id> */
    PK: `AUTH_SESSION#${string}`;
    SK: 'METADATA';
    entityType: 'AUTH_SESSION';

    /** Unique session identifier (UUID) */
    sessionId: string;

    /** User's subject identifier */
    sub: string;

    /** ISO 8601 timestamp when authentication occurred */
    authenticatedAt: string;

    /** Authentication method used (e.g., 'password', 'saml') */
    authMethod: string;

    /** Authentication Context Class Reference (if applicable) */
    acr?: string;

    /** Authentication Methods References (if applicable) */
    amr?: string[];

    /** Client ID that initiated the original authentication */
    clientId: string;

    /** User agent string from the authentication request */
    userAgent?: string;

    /** IP address from the authentication request */
    ipAddress?: string;

    /** Last activity timestamp (updated on each use) */
    lastActivityAt: string;
}

// =============================================================================
// Session Cookie Configuration
// =============================================================================

/**
 * Configuration for the session cookie.
 * Set via environment variables in Terraform.
 */
export interface SessionCookieConfig {
    /** Cookie name (default: __Host-sid) */
    name: string;

    /** Cookie domain (optional, for cross-subdomain sessions) */
    domain?: string;

    /** Session TTL in seconds (default: 24 hours) */
    ttlSeconds: number;

    /** Whether to use __Host- prefix (requires Secure, no Domain) */
    useHostPrefix: boolean;
}
