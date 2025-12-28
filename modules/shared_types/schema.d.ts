/**
 * OAuth Server - DynamoDB Schema Types
 *
 * Single Table Design interfaces for all entities.
 * All items share the same table with PK/SK key patterns.
 *
 * Key Patterns:
 *   - Client:       PK=CLIENT#<id>       SK=CONFIG
 *   - User:         PK=USER#<sub_id>     SK=PROFILE
 *   - AuthCode:     PK=CODE#<code>       SK=METADATA
 *   - RefreshToken: PK=REFRESH#<hash>    SK=METADATA
 *   - SAMLProvider: PK=SAML#<issuer>     SK=CONFIG
 *   - LoginSession: PK=SESSION#<id>      SK=METADATA
 *
 * This file re-exports all entity types from their individual modules
 * for backward compatibility and convenience.
 *
 * @see https://www.alexdebrie.com/posts/dynamodb-single-table/
 */

// =============================================================================
// Base Types
// =============================================================================

export type {
    PKPrefix,
    SKValue,
    EntityType,
    GrantType,
    AuthStrategyId,
    BaseItem,
} from './base';

// =============================================================================
// Entity Types
// =============================================================================

export type { ClientItem, TokenLifetimes } from './client';

export type { UserItem, UserProfile, UserStatus } from './user';

export type { AuthCodeItem, RefreshTokenItem } from './token';

export type { SAMLProviderItem, SAMLNameIdFormat, SAMLAttributeMapping } from './saml';

export type { LoginSessionItem } from './session';

export type { AuthenticatedSessionItem, SessionCookieConfig } from './auth-session';

export type { DPoPJtiItem, DPoPConfirmation, DPoPBinding, TokenType } from './dpop';

export type { GroupItem, GroupMembershipItem, UserGroupItem } from './group';

// =============================================================================
// Union Type for All Items
// =============================================================================

import type { ClientItem } from './client';
import type { UserItem } from './user';
import type { AuthCodeItem, RefreshTokenItem } from './token';
import type { SAMLProviderItem } from './saml';
import type { LoginSessionItem } from './session';
import type { AuthenticatedSessionItem } from './auth-session';
import type { DPoPJtiItem } from './dpop';
import type { GroupItem, GroupMembershipItem, UserGroupItem } from './group';

export type OAuthServerItem =
    | ClientItem
    | UserItem
    | AuthCodeItem
    | RefreshTokenItem
    | SAMLProviderItem
    | LoginSessionItem
    | AuthenticatedSessionItem
    | DPoPJtiItem
    | GroupItem
    | GroupMembershipItem
    | UserGroupItem;
