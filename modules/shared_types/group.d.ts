/**
 * OAuth Server - Group Entity Types
 *
 * SCIM Group resources and membership stored in DynamoDB.
 *
 * Key Patterns (Adjacency List for Group Membership):
 *   - Group:          PK=GROUP#<id>       SK=METADATA
 *   - Membership:     PK=GROUP#<id>       SK=MEMBER#<user_id>
 *   - Reverse Lookup: PK=USER#<user_id>   SK=GROUP#<group_id>
 *
 * This design enables:
 *   - Efficient group member listing (Query PK=GROUP#<id>, SK begins_with MEMBER#)
 *   - Efficient user's groups lookup (Query PK=USER#<id>, SK begins_with GROUP#)
 *   - JWT claims injection (user's groups for RBAC)
 *
 * @see RFC 7643 - SCIM Core Schema (Section 4.2 - Group Resource)
 * @see RFC 7644 - SCIM Protocol
 */

import type { BaseItem } from './base';

// =============================================================================
// Group Entity
// PK: GROUP#<group_id>  SK: METADATA
// GSI1PK: GROUPS  GSI1SK: GROUP#<timestamp>#<group_id>
// =============================================================================

/**
 * Group metadata stored in DynamoDB.
 */
export interface GroupItem extends BaseItem {
    /** PK pattern: GROUP#<group_id> */
    PK: `GROUP#${string}`;
    SK: 'METADATA';
    /** GSI1 for listing all groups */
    GSI1PK: 'GROUPS';
    GSI1SK: string;
    entityType: 'GROUP';

    /** Group's unique identifier (UUID) */
    groupId: string;
    /** Human-readable display name */
    displayName: string;
    /** External identifier from provisioning client */
    externalId?: string;
    /** Number of members (denormalized for efficiency) */
    memberCount: number;
    /** ISO 8601 timestamp when group was created */
    createdAt: string;
    /** ISO 8601 timestamp when group was last modified */
    updatedAt: string;
}

// =============================================================================
// Group Membership Entity (Group → User direction)
// PK: GROUP#<group_id>  SK: MEMBER#<user_id>
// =============================================================================

/**
 * Group membership item in DynamoDB.
 * Represents the Group → User relationship.
 */
export interface GroupMembershipItem extends BaseItem {
    /** PK pattern: GROUP#<group_id> */
    PK: `GROUP#${string}`;
    /** SK pattern: MEMBER#<user_id> */
    SK: `MEMBER#${string}`;
    entityType: 'GROUP_MEMBERSHIP';

    /** Group's unique identifier */
    groupId: string;
    /** Member's unique identifier (user sub) */
    memberId: string;
    /** Member type: "User" or "Group" */
    memberType: 'User' | 'Group';
    /** Member's display name (denormalized for efficiency) */
    memberDisplay?: string;
    /** Member's email (denormalized for efficiency) */
    memberEmail?: string;
    /** ISO 8601 timestamp when member was added */
    addedAt: string;
}

// =============================================================================
// User Group Entity (User → Group direction - Reverse Lookup)
// PK: USER#<user_id>  SK: GROUP#<group_id>
// =============================================================================

/**
 * User's group membership item in DynamoDB.
 * Represents the User → Group relationship (reverse lookup).
 *
 * This enables efficient JWT claims injection for RBAC.
 */
export interface UserGroupItem extends BaseItem {
    /** PK pattern: USER#<user_id> */
    PK: `USER#${string}`;
    /** SK pattern: GROUP#<group_id> */
    SK: `GROUP#${string}`;
    entityType: 'USER_GROUP';

    /** User's unique identifier (sub) */
    userId: string;
    /** Group's unique identifier */
    groupId: string;
    /** Group's display name (denormalized for JWT claims) */
    groupName: string;
    /** ISO 8601 timestamp when membership was created */
    addedAt: string;
}
