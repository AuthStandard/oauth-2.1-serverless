/**
 * OAuth Server - Type Guards
 *
 * Runtime type guards for DynamoDB entity discrimination.
 * These provide safe type narrowing for Single Table Design entities.
 *
 * Each guard validates:
 * - entityType discriminator matches expected value
 * - PK prefix matches expected pattern
 * - SK value matches expected value for the entity type
 *
 * Usage:
 * ```typescript
 * const item = await storage.getItem(pk, sk);
 * if (isClientItem(item)) {
 *   // TypeScript knows item is ClientItem here
 *   console.log(item.clientId);
 * }
 * ```
 *
 * @see https://www.typescriptlang.org/docs/handbook/2/narrowing.html#using-type-predicates
 */

import type { BaseItem } from '../../shared_types/base';
import type { ClientItem } from '../../shared_types/client';
import type { UserItem } from '../../shared_types/user';
import type { AuthCodeItem, RefreshTokenItem } from '../../shared_types/token';
import type { SAMLProviderItem } from '../../shared_types/saml';
import type { LoginSessionItem } from '../../shared_types/session';
import { KeyPrefixes } from './constants';

// =============================================================================
// Type Guards
// =============================================================================

/**
 * Check if an item is a ClientItem.
 * Key Pattern: PK=CLIENT#<client_id>, SK=CONFIG
 */
export function isClientItem(item: BaseItem): item is ClientItem {
    return (
        item.entityType === 'CLIENT' &&
        item.PK.startsWith(KeyPrefixes.CLIENT) &&
        item.SK === 'CONFIG'
    );
}

/**
 * Check if an item is a UserItem.
 * Key Pattern: PK=USER#<sub>, SK=PROFILE
 */
export function isUserItem(item: BaseItem): item is UserItem {
    return (
        item.entityType === 'USER' &&
        item.PK.startsWith(KeyPrefixes.USER) &&
        item.SK === 'PROFILE'
    );
}

/**
 * Check if an item is an AuthCodeItem.
 * Key Pattern: PK=CODE#<code>, SK=METADATA
 */
export function isAuthCodeItem(item: BaseItem): item is AuthCodeItem {
    return (
        item.entityType === 'AUTH_CODE' &&
        item.PK.startsWith(KeyPrefixes.CODE) &&
        item.SK === 'METADATA'
    );
}

/**
 * Check if an item is a RefreshTokenItem.
 * Key Pattern: PK=REFRESH#<token_hash>, SK=METADATA
 */
export function isRefreshTokenItem(item: BaseItem): item is RefreshTokenItem {
    return (
        item.entityType === 'REFRESH_TOKEN' &&
        item.PK.startsWith(KeyPrefixes.REFRESH) &&
        item.SK === 'METADATA'
    );
}

/**
 * Check if an item is a SAMLProviderItem.
 * Key Pattern: PK=SAML#<issuer>, SK=CONFIG
 */
export function isSAMLProviderItem(item: BaseItem): item is SAMLProviderItem {
    return (
        item.entityType === 'SAML_PROVIDER' &&
        item.PK.startsWith(KeyPrefixes.SAML) &&
        item.SK === 'CONFIG'
    );
}

/**
 * Check if an item is a LoginSessionItem.
 * Key Pattern: PK=SESSION#<session_id>, SK=METADATA
 */
export function isLoginSessionItem(item: BaseItem): item is LoginSessionItem {
    return (
        item.entityType === 'LOGIN_SESSION' &&
        item.PK.startsWith(KeyPrefixes.SESSION) &&
        item.SK === 'METADATA'
    );
}
