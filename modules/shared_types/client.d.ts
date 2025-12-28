/**
 * OAuth Server - Client Entity Types
 *
 * OAuth 2.1 Client configuration stored in DynamoDB.
 *
 * Key Pattern:
 *   PK: CLIENT#<client_id>
 *   SK: CONFIG
 *   GSI1PK: CLIENTS
 *   GSI1SK: <client_id> (for listing all clients)
 *
 * OAuth 2.1 Requirements:
 * - Client types: PUBLIC or CONFIDENTIAL (Section 2.1)
 * - Redirect URI registration is REQUIRED (Section 2.3.1)
 * - Exact redirect URI matching is REQUIRED (Section 2.3.1)
 * - PKCE is REQUIRED for all clients (Section 4.1.1)
 *
 * @see OAuth 2.1 Draft Section 2 - Client Registration
 * @see OAuth 2.1 Draft Section 2.1 - Client Types
 * @see OAuth 2.1 Draft Section 2.3 - Client Redirection Endpoint
 */

import type { BaseItem, GrantType, AuthStrategyId } from './base';

// =============================================================================
// Token Lifetimes Configuration
// =============================================================================

export interface TokenLifetimes {
    /** Access token lifetime in seconds (e.g., 3600 = 1 hour) */
    accessToken: number;
    /** Refresh token lifetime in seconds (e.g., 2592000 = 30 days) */
    refreshToken: number;
    /** Authorization code lifetime in seconds (e.g., 600 = 10 minutes) */
    authorizationCode: number;
}

// =============================================================================
// Client Entity
// =============================================================================

export interface ClientItem extends BaseItem {
    /** PK pattern: CLIENT#<client_id> */
    PK: `CLIENT#${string}`;
    SK: 'CONFIG';
    entityType: 'CLIENT';

    /** OAuth2 Client ID */
    clientId: string;

    /** Registered redirect URIs (must be exact match per OAuth 2.1) */
    redirectUris: readonly string[];

    /** Allowed OAuth 2.1 grant types */
    grantTypes: readonly GrantType[];

    /** Authentication strategy this client uses */
    authStrategyId: AuthStrategyId;

    /** Client display name */
    clientName: string;

    /** Client type for secret requirements */
    clientType: 'PUBLIC' | 'CONFIDENTIAL';

    /** SHA-256 hash of client secret (confidential clients only) */
    clientSecretHash?: string;

    /** Allowed scopes for this client */
    allowedScopes: readonly string[];

    /** Token lifetime configuration in seconds */
    tokenLifetimes: TokenLifetimes;

    /**
     * Registered post-logout redirect URIs for OIDC RP-Initiated Logout.
     * Must be exact match per OIDC RP-Initiated Logout 1.0 Section 2.1.
     * @see https://openid.net/specs/openid-connect-rpinitiated-1_0.html
     */
    postLogoutRedirectUris?: readonly string[];
}

// =============================================================================
// Type Guard Declarations
// =============================================================================

// Note: Type guard implementations are provided in the shared module (type-guards.ts).
// These declarations exist for documentation purposes only.
