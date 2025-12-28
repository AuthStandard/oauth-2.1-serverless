/**
 * SCIM v2 Group Provisioning - Type Definitions
 *
 * Implements SCIM 2.0 (RFC 7643, RFC 7644) Group Resource types.
 *
 * DynamoDB Key Patterns (Adjacency List for Group Membership):
 *   - Group:          PK=GROUP#<id>       SK=METADATA
 *   - Membership:     PK=GROUP#<id>       SK=MEMBER#<user_id>
 *   - Reverse Lookup: PK=USER#<user_id>   SK=GROUP#<group_id>
 *
 * This design enables:
 *   - Efficient group member listing (Query PK=GROUP#<id>, SK begins_with MEMBER#)
 *   - Efficient user's groups lookup (Query PK=USER#<id>, SK begins_with GROUP#)
 *   - JWT claims injection (user's groups for RBAC)
 *
 * @module governance/scim_groups/types
 * @see RFC 7643 - SCIM Core Schema (Section 4.2 - Group Resource)
 * @see RFC 7644 - SCIM Protocol
 */

import type { BaseItem } from '../../../shared_types/base';

// =============================================================================
// Environment Configuration
// =============================================================================

/**
 * Runtime configuration from Lambda environment variables.
 * All values originate from Terraform - no hardcoded defaults.
 */
export interface EnvConfig {
    /** DynamoDB table name */
    readonly tableName: string;
    /** OAuth issuer URL (used for SCIM location URIs) */
    readonly issuer: string;
    /** SCIM base URL (derived from issuer) */
    readonly scimBaseUrl: string;
}

// =============================================================================
// SCIM 2.0 Group Resource Types (RFC 7643 Section 4.2)
// =============================================================================

/**
 * SCIM Group Member reference (RFC 7643 Section 4.2).
 */
export interface ScimGroupMember {
    /** Member's resource ID (user sub or group id) */
    readonly value: string;
    /** URI reference to the member resource */
    readonly $ref?: string;
    /** Display name of the member */
    readonly display?: string;
    /** Member type: "User" or "Group" (for nested groups) */
    readonly type?: 'User' | 'Group';
}

/**
 * SCIM Group Meta attribute (RFC 7643 Section 3.1).
 */
export interface ScimGroupMeta {
    /** Resource type (always "Group" for group resources) */
    readonly resourceType: 'Group';
    /** Date and time the resource was created (ISO 8601) */
    readonly created: string;
    /** Date and time the resource was last modified (ISO 8601) */
    readonly lastModified: string;
    /** URI of the resource */
    readonly location: string;
    /** Version of the resource (ETag) */
    readonly version?: string;
}

/**
 * SCIM Group Resource (RFC 7643 Section 4.2).
 *
 * Core attributes for group provisioning.
 */
export interface ScimGroup {
    /** SCIM schema URIs */
    readonly schemas: readonly string[];
    /** Unique identifier (UUID) */
    readonly id: string;
    /** External identifier from provisioning client */
    readonly externalId?: string;
    /** Human-readable name for the group */
    readonly displayName: string;
    /** Group members */
    readonly members?: readonly ScimGroupMember[];
    /** Resource metadata */
    readonly meta: ScimGroupMeta;
}

/**
 * SCIM Group creation request.
 */
export interface ScimGroupCreateRequest {
    /** SCIM schema URIs */
    readonly schemas?: readonly string[];
    /** External identifier from provisioning client */
    readonly externalId?: string;
    /** Human-readable name for the group (REQUIRED) */
    readonly displayName: string;
    /** Initial group members */
    readonly members?: readonly ScimGroupMember[];
}

// =============================================================================
// SCIM 2.0 PATCH Operation (RFC 7644 Section 3.5.2)
// =============================================================================

/**
 * SCIM PATCH operation types.
 */
export type ScimPatchOp = 'add' | 'remove' | 'replace';

/**
 * SCIM PATCH operation (RFC 7644 Section 3.5.2).
 */
export interface ScimPatchOperation {
    /** Operation type */
    readonly op: ScimPatchOp;
    /** Attribute path (e.g., "displayName", "members") */
    readonly path?: string;
    /** Value to set (for add/replace operations) */
    readonly value?: unknown;
}

/**
 * SCIM PATCH request body.
 */
export interface ScimPatchRequest {
    /** SCIM schema URIs (must include PatchOp schema) */
    readonly schemas: readonly string[];
    /** Array of patch operations */
    readonly Operations: readonly ScimPatchOperation[];
}

// =============================================================================
// DynamoDB Entity Types
// =============================================================================

/**
 * Group metadata item in DynamoDB.
 * PK: GROUP#<group_id>, SK: METADATA
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

/**
 * Group membership item in DynamoDB (Group → User direction).
 * PK: GROUP#<group_id>, SK: MEMBER#<user_id>
 */
export interface GroupMembershipItem extends BaseItem {
    /** PK pattern: GROUP#<group_id> */
    PK: `GROUP#${string}`;
    /** SK pattern: MEMBER#<user_id> */
    SK: `MEMBER#${string}`;
    /** GSI1 PK for reverse lookup by member */
    GSI1PK: `MEMBER#${string}`;
    /** GSI1 SK for group ordering */
    GSI1SK: `GROUP#${string}`;
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

/**
 * User's group membership item in DynamoDB (User → Group direction).
 * PK: USER#<user_id>, SK: GROUP#<group_id>
 *
 * This reverse lookup enables efficient JWT claims injection.
 */
export interface UserGroupItem extends BaseItem {
    /** PK pattern: USER#<user_id> */
    PK: `USER#${string}`;
    /** SK pattern: GROUP#<group_id> */
    SK: `GROUP#${string}`;
    /** GSI1 PK for reverse lookup by group */
    GSI1PK: `GROUP#${string}`;
    /** GSI1 SK for user ordering */
    GSI1SK: `USER#${string}`;
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

// =============================================================================
// SCIM 2.0 Error Response (RFC 7644 Section 3.12)
// =============================================================================

/**
 * SCIM error types (RFC 7644 Section 3.12).
 */
export type ScimErrorType =
    | 'invalidFilter'
    | 'tooMany'
    | 'uniqueness'
    | 'mutability'
    | 'invalidSyntax'
    | 'invalidPath'
    | 'noTarget'
    | 'invalidValue'
    | 'invalidVers'
    | 'sensitive';

/**
 * SCIM error response (RFC 7644 Section 3.12).
 */
export interface ScimErrorResponse {
    /** SCIM schema URIs */
    readonly schemas: readonly ['urn:ietf:params:scim:api:messages:2.0:Error'];
    /** HTTP status code */
    readonly status: string;
    /** SCIM error type */
    readonly scimType?: ScimErrorType;
    /** Human-readable error detail */
    readonly detail?: string;
}

/**
 * SCIM List Response (RFC 7644 Section 3.4.2).
 */
export interface ScimListResponse<T> {
    /** SCIM schema URIs */
    readonly schemas: readonly ['urn:ietf:params:scim:api:messages:2.0:ListResponse'];
    /** Total number of results */
    readonly totalResults: number;
    /** Starting index (1-based) */
    readonly startIndex: number;
    /** Number of results per page */
    readonly itemsPerPage: number;
    /** Array of resources */
    readonly Resources: readonly T[];
}

// =============================================================================
// Constants
// =============================================================================

/** SCIM 2.0 Group schema URI */
export const SCIM_GROUP_SCHEMA = 'urn:ietf:params:scim:schemas:core:2.0:Group';

/** SCIM 2.0 Error schema URI */
export const SCIM_ERROR_SCHEMA = 'urn:ietf:params:scim:api:messages:2.0:Error';

/** SCIM 2.0 PatchOp schema URI */
export const SCIM_PATCH_SCHEMA = 'urn:ietf:params:scim:api:messages:2.0:PatchOp';

/** SCIM 2.0 ListResponse schema URI */
export const SCIM_LIST_SCHEMA = 'urn:ietf:params:scim:api:messages:2.0:ListResponse';
