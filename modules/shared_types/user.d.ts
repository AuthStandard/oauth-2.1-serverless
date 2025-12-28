/**
 * OAuth Server - User Entity Types
 *
 * User profile and authentication data stored in DynamoDB.
 *
 * Key Pattern:
 *   PK: USER#<sub_id>
 *   SK: PROFILE
 *   GSI1PK: EMAIL#<email>
 *   GSI1SK: USER (for email lookup)
 *
 * @see OpenID Connect Core 1.0 Section 5.1 - Standard Claims
 */

import type { BaseItem } from './base';

// =============================================================================
// User Profile
// =============================================================================

export interface UserProfile {
    /** Given/first name */
    givenName?: string;
    /** Family/last name */
    familyName?: string;
    /** Profile picture URL */
    picture?: string;
    /** BCP 47 locale code (e.g., "en-US") */
    locale?: string;
}

export type UserStatus = 'ACTIVE' | 'SUSPENDED' | 'PENDING_VERIFICATION';

// =============================================================================
// User Entity
// =============================================================================

export interface UserItem extends BaseItem {
    /** PK pattern: USER#<sub_id> */
    PK: `USER#${string}`;
    SK: 'PROFILE';
    entityType: 'USER';

    /** User's unique subject identifier (UUID) */
    sub: string;

    /** User's email address */
    email: string;

    /** Whether the email has been verified */
    emailVerified: boolean;

    /** IANA timezone identifier (e.g., "America/New_York") */
    zoneinfo: string;

    /** Argon2id password hash (if using password strategy) */
    passwordHash?: string;

    /** User profile information */
    profile: UserProfile;

    /** Account status */
    status: UserStatus;
}

// =============================================================================
// Type Guard Declarations
// =============================================================================

// Note: Type guard implementations are provided in the shared module (type-guards.ts).
// These declarations exist for documentation purposes only.
