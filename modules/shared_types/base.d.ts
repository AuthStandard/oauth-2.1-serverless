/**
 * OAuth Server - Base DynamoDB Schema Types
 *
 * Foundation interfaces for Single Table Design.
 * All entity types extend BaseItem for consistent key structure.
 *
 * Key Design:
 * - PK (Partition Key): Entity-specific prefix pattern (e.g., CLIENT#<id>)
 * - SK (Sort Key): Entity type identifier (CONFIG, PROFILE, METADATA)
 * - GSI1: Secondary access patterns (e.g., user lookup by email)
 *
 * TTL Strategy:
 * - Short-lived entities (auth codes, sessions): TTL set to expiration time
 * - Long-lived entities (users, clients): No TTL (managed via admin operations)
 * - Refresh tokens: TTL set to token expiration for automatic cleanup
 *
 * @see https://www.alexdebrie.com/posts/dynamodb-single-table/
 * @see https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/TTL.html
 */

// =============================================================================
// Key Pattern Prefixes (Strict Typing)
// =============================================================================

/** Partition Key prefixes for each entity type */
export type PKPrefix =
    | `CLIENT#${string}`
    | `USER#${string}`
    | `CODE#${string}`
    | `REFRESH#${string}`
    | `SAML#${string}`
    | `SESSION#${string}`
    | `DPOP_JTI#${string}`
    | `GROUP#${string}`;

/** Sort Key values */
export type SKValue = 'CONFIG' | 'PROFILE' | 'METADATA' | `MEMBER#${string}` | `GROUP#${string}`;

// =============================================================================
// Entity Type Discriminators
// =============================================================================

export type EntityType =
    | 'CLIENT'
    | 'USER'
    | 'AUTH_CODE'
    | 'REFRESH_TOKEN'
    | 'SAML_PROVIDER'
    | 'LOGIN_SESSION'
    | 'DPOP_JTI'
    | 'GROUP'
    | 'GROUP_MEMBERSHIP'
    | 'USER_GROUP';

// =============================================================================
// Grant Types (OAuth 2.1 Compliant)
// =============================================================================

export type GrantType =
    | 'authorization_code'
    | 'refresh_token'
    | 'client_credentials';

// =============================================================================
// Auth Strategy Identifiers
// =============================================================================

export type AuthStrategyId =
    | 'password'
    | 'saml'
    | 'oidc';

// =============================================================================
// Base Item Interface
// =============================================================================

/**
 * Base interface for all DynamoDB items in the Single Table Design.
 * All entities extend this to ensure consistent key structure.
 */
export interface BaseItem {
    /** Partition Key - Entity-specific prefix pattern */
    PK: string;
    /** Sort Key - Entity type identifier */
    SK: SKValue;
    /** GSI1 Partition Key - For reverse lookups and queries */
    GSI1PK: string;
    /** GSI1 Sort Key - For range queries on GSI1 */
    GSI1SK: string;
    /** TTL for automatic expiration (Unix epoch seconds). Optional for long-lived entities. */
    ttl?: number;
    /** Entity type discriminator for type guards */
    entityType: EntityType;
    /** ISO 8601 creation timestamp */
    createdAt: string;
    /** ISO 8601 last update timestamp */
    updatedAt: string;
}
